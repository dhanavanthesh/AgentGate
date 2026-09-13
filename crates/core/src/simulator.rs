use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Barrier, Mutex, MutexGuard};

use serde::{Deserialize, Serialize};

use crate::authorize::TransactionalAuthorizer;
use crate::clock::{Clock, SystemClock};
use crate::digest::{canonical_json, sha256_hex};
use crate::error::{ErrorCode, GateError, GateResult};
use crate::execute::AuthorizedExecutionRequest;
use crate::idempotency::{BeginOutcome, BoundedIdempotencyStore, IdempotencyStore};
use crate::ids::{
    IdempotencyKey, OpaqueHandle, OperationId, PrincipalId, ReceiptDigest, ReconciliationReference,
    SourceRevision, TenantId,
};

#[derive(Clone, Debug)]
struct Issue {
    title: String,
    writable: bool,
    comments: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdapterFault {
    None,
    TimeoutBeforeCommit,
    TimeoutAfterCommit,
}

pub struct TransactionHook {
    entered: Barrier,
    release: Barrier,
}

impl TransactionHook {
    #[must_use]
    pub fn new() -> Self {
        Self {
            entered: Barrier::new(2),
            release: Barrier::new(2),
        }
    }

    pub fn wait_until_entered(&self) {
        self.entered.wait();
    }

    pub fn release(&self) {
        self.release.wait();
    }

    fn pause(&self) {
        self.entered.wait();
        self.release.wait();
    }
}

impl Default for TransactionHook {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
struct State {
    revision: SourceRevision,
    issues: BTreeMap<OpaqueHandle, Issue>,
    allowed: BTreeSet<(PrincipalId, TenantId)>,
    idempotency: BoundedIdempotencyStore<ExecutionReceipt>,
    execute_calls: u64,
    side_effects: u64,
    fault: AdapterFault,
}

#[derive(Clone, Debug)]
pub struct ListedIssue {
    pub handle: OpaqueHandle,
    pub title: String,
    pub writable: bool,
}

#[derive(Clone, Debug)]
pub struct AuthoritativeList {
    pub source_revision: SourceRevision,
    pub issues: Vec<ListedIssue>,
    adapter_id: u64,
}

#[derive(Clone, Debug)]
pub struct InspectionResult {
    pub handle: OpaqueHandle,
    pub title: String,
    pub source_revision: SourceRevision,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ExecutionReceipt {
    pub operation_id: OperationId,
    pub idempotency_key: IdempotencyKey,
    pub receipt_digest: ReceiptDigest,
    pub comment_count: usize,
    pub replayed: bool,
}

pub enum ExecutionAttempt {
    Completed(ExecutionReceipt),
    TimeoutBeforeCommit,
    TimeoutAfterCommit(ReconciliationReference),
}

pub struct FakeGithub {
    adapter_id: u64,
    tenant: TenantId,
    repository: OpaqueHandle,
    state: Mutex<State>,
    transaction_hook: Mutex<Option<Arc<TransactionHook>>>,
    clock: Arc<dyn Clock>,
}

impl FakeGithub {
    #[must_use]
    pub fn seeded() -> Self {
        Self::seeded_with_clock(Arc::new(SystemClock::new()))
    }

    #[must_use]
    pub fn seeded_with_clock(clock: Arc<dyn Clock>) -> Self {
        let tenant = TenantId::new("tenant_acme");
        let repository = OpaqueHandle::new("github:tenant_acme:repo_R1");
        let mut issues = BTreeMap::new();
        issues.insert(
            OpaqueHandle::new("github:tenant_acme:repo_R1:issue_I12"),
            Issue {
                title: "Example".to_owned(),
                writable: true,
                comments: Vec::new(),
            },
        );
        issues.insert(
            OpaqueHandle::new("github:tenant_acme:repo_R1:issue_I13"),
            Issue {
                title: "Read only".to_owned(),
                writable: false,
                comments: Vec::new(),
            },
        );
        issues.insert(
            OpaqueHandle::new("github:tenant_acme:repo_R1:issue_I14"),
            Issue {
                title: "Second writable issue".to_owned(),
                writable: true,
                comments: Vec::new(),
            },
        );
        let mut allowed = BTreeSet::new();
        allowed.insert((PrincipalId::new("user:42"), tenant.clone()));
        Self {
            adapter_id: 0x4147_5354_4550_3201,
            tenant,
            repository,
            state: Mutex::new(State {
                revision: SourceRevision::new("repo_R1:rev_7"),
                issues,
                allowed,
                idempotency: BoundedIdempotencyStore::new(4096, 8 * 1024 * 1024),
                execute_calls: 0,
                side_effects: 0,
                fault: AdapterFault::None,
            }),
            transaction_hook: Mutex::new(None),
            clock,
        }
    }

    pub fn list_issues(
        &self,
        principal: &PrincipalId,
        tenant: &TenantId,
    ) -> GateResult<AuthoritativeList> {
        let state = self.lock()?;
        require_scope(&state, &self.tenant, principal, tenant)?;
        let issues = state
            .issues
            .iter()
            .map(|(handle, issue)| ListedIssue {
                handle: handle.clone(),
                title: issue.title.clone(),
                writable: issue.writable,
            })
            .collect();
        Ok(AuthoritativeList {
            source_revision: state.revision.clone(),
            issues,
            adapter_id: self.adapter_id,
        })
    }

    pub fn inspect_issue(
        &self,
        principal: &PrincipalId,
        tenant: &TenantId,
        handle: &OpaqueHandle,
        expected_revision: &SourceRevision,
    ) -> GateResult<InspectionResult> {
        let state = self.lock()?;
        require_scope(&state, &self.tenant, principal, tenant)?;
        if &state.revision != expected_revision {
            return Err(GateError::new(
                ErrorCode::CatalogStale,
                "repository revision changed",
            ));
        }
        let issue = state
            .issues
            .get(handle)
            .ok_or_else(|| GateError::new(ErrorCode::AuthDenied, "issue is unavailable"))?;
        Ok(InspectionResult {
            handle: handle.clone(),
            title: issue.title.clone(),
            source_revision: state.revision.clone(),
        })
    }

    pub fn verify_provenance(&self, result: &AuthoritativeList) -> GateResult<()> {
        if result.adapter_id != self.adapter_id {
            return Err(GateError::new(
                ErrorCode::CatalogInvalid,
                "adapter provenance differs",
            ));
        }
        Ok(())
    }

    pub fn reconcile(&self, key: &IdempotencyKey) -> GateResult<Option<ExecutionReceipt>> {
        self.lock()?.idempotency.reconcile(key)
    }

    pub fn revoke(&self, handle: &OpaqueHandle) -> GateResult<()> {
        let mut state = self.lock()?;
        let issue = state
            .issues
            .get_mut(handle)
            .ok_or_else(|| GateError::new(ErrorCode::CatalogInvalid, "unknown issue handle"))?;
        issue.writable = false;
        Ok(())
    }

    pub fn change_revision(&self, revision: SourceRevision) -> GateResult<()> {
        self.lock()?.revision = revision;
        Ok(())
    }

    pub fn set_fault(&self, fault: AdapterFault) -> GateResult<()> {
        self.lock()?.fault = fault;
        Ok(())
    }

    pub fn set_transaction_hook(&self, hook: Option<Arc<TransactionHook>>) -> GateResult<()> {
        *self.transaction_hook.lock().map_err(|_| {
            GateError::new(
                ErrorCode::InternalInvariant,
                "transaction hook lock poisoned",
            )
        })? = hook;
        Ok(())
    }

    pub fn counts(&self) -> GateResult<(u64, u64)> {
        let state = self.lock()?;
        Ok((state.execute_calls, state.side_effects))
    }

    pub fn retained_idempotency(&self) -> GateResult<(usize, usize)> {
        let state = self.lock()?;
        Ok(state.idempotency.retained())
    }

    #[must_use]
    pub fn repository(&self) -> &OpaqueHandle {
        &self.repository
    }

    #[must_use]
    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    fn execute_in_transaction(
        &self,
        request: &AuthorizedExecutionRequest<'_>,
    ) -> GateResult<ExecutionAttempt> {
        request.deadline.check(self.clock.as_ref())?;
        let hook = self
            .transaction_hook
            .lock()
            .map_err(|_| {
                GateError::new(
                    ErrorCode::InternalInvariant,
                    "transaction hook lock poisoned",
                )
            })?
            .clone();
        let mut state = self.lock()?;
        if let Some(hook) = hook {
            hook.pause();
        }
        state.execute_calls = state.execute_calls.checked_add(1).ok_or_else(|| {
            GateError::new(ErrorCode::InternalInvariant, "execution counter overflow")
        })?;
        require_scope(&state, &self.tenant, request.principal, request.tenant)?;
        if request.tool_id != &crate::ids::ToolId::new("github.comment_issue", "1") {
            return Err(GateError::new(
                ErrorCode::AuthDenied,
                "tool is not authorized by this adapter transaction",
            ));
        }
        if &state.revision != request.expected_revision {
            return Err(GateError::new(
                ErrorCode::CatalogStale,
                "repository revision changed",
            ));
        }
        let issue = state.issues.get(request.issue_handle).ok_or_else(|| {
            GateError::new(ErrorCode::AuthDenied, "issue is not currently available")
        })?;
        if !issue.writable {
            return Err(GateError::new(
                ErrorCode::AuthDenied,
                "issue is not currently writable",
            ));
        }
        let next_count = issue.comments.len().checked_add(1).ok_or_else(|| {
            GateError::new(ErrorCode::InternalInvariant, "comment count overflow")
        })?;
        let accounted_bytes = request
            .idempotency_key
            .as_str()
            .len()
            .checked_add(request.action_digest.as_str().len())
            .and_then(|bytes| bytes.checked_add(request.body.len()))
            .and_then(|bytes| bytes.checked_add(256))
            .ok_or_else(|| {
                GateError::new(ErrorCode::CatalogTooLarge, "idempotency size overflow")
            })?;
        let committed_at_ms = self.clock.wall_time_ms()?;
        let lease_expiry_ms = committed_at_ms.checked_add(10_000).ok_or_else(|| {
            GateError::new(ErrorCode::InternalInvariant, "idempotency lease overflow")
        })?;
        match state.idempotency.begin(
            request.idempotency_key.clone(),
            request.operation_id.clone(),
            request.action_digest.clone(),
            committed_at_ms,
            lease_expiry_ms,
            accounted_bytes,
        )? {
            BeginOutcome::Replay(mut receipt) => {
                receipt.replayed = true;
                return Ok(ExecutionAttempt::Completed(receipt));
            }
            BeginOutcome::Pending => {
                return Err(GateError::new(
                    ErrorCode::ToolTimeout,
                    "matching idempotent operation is still pending",
                ));
            }
            BeginOutcome::Indeterminate(reference) => {
                return Err(GateError::new(
                    ErrorCode::ToolTimeout,
                    "idempotent operation requires reconciliation",
                )
                .safe_context(reference.as_str()));
            }
            BeginOutcome::TerminalFailure => {
                return Err(GateError::new(
                    ErrorCode::ToolFailed,
                    "idempotent operation previously failed terminally",
                ));
            }
            BeginOutcome::Started => {}
        }
        if state.fault == AdapterFault::TimeoutBeforeCommit {
            state.fault = AdapterFault::None;
            state
                .idempotency
                .fail_retryable(request.idempotency_key, request.action_digest)?;
            return Ok(ExecutionAttempt::TimeoutBeforeCommit);
        }
        if let Err(error) = request.deadline.check(self.clock.as_ref()) {
            state
                .idempotency
                .fail_retryable(request.idempotency_key, request.action_digest)?;
            return Err(error);
        }
        let receipt_value = serde_json::json!({
            "operation_id": request.operation_id,
            "idempotency_key": request.idempotency_key,
            "comment_count": next_count,
            "committed_at_ms": committed_at_ms,
        });
        let receipt_digest =
            ReceiptDigest::new(sha256_hex(canonical_json(&receipt_value)?.as_bytes()));
        let receipt = ExecutionReceipt {
            operation_id: request.operation_id.clone(),
            idempotency_key: request.idempotency_key.clone(),
            receipt_digest: receipt_digest.clone(),
            comment_count: next_count,
            replayed: false,
        };
        state
            .issues
            .get_mut(request.issue_handle)
            .ok_or_else(|| {
                GateError::new(ErrorCode::InternalInvariant, "authorized issue disappeared")
            })?
            .comments
            .push(request.body.to_owned());
        state.side_effects = state.side_effects.checked_add(1).ok_or_else(|| {
            GateError::new(ErrorCode::InternalInvariant, "side-effect counter overflow")
        })?;
        let normalized_receipt =
            canonical_json(&serde_json::to_value(&receipt).map_err(|_| {
                GateError::new(ErrorCode::InternalInvariant, "receipt normalization failed")
            })?)?;
        state.idempotency.commit(
            request.idempotency_key,
            request.action_digest,
            receipt_digest,
            receipt.clone(),
            normalized_receipt,
            committed_at_ms,
        )?;
        if state.fault == AdapterFault::TimeoutAfterCommit {
            state.fault = AdapterFault::None;
            return Ok(ExecutionAttempt::TimeoutAfterCommit(
                ReconciliationReference::new(request.idempotency_key.as_str()),
            ));
        }
        Ok(ExecutionAttempt::Completed(receipt))
    }

    fn lock(&self) -> GateResult<MutexGuard<'_, State>> {
        self.state.lock().map_err(|_| {
            GateError::new(ErrorCode::InternalInvariant, "adapter state lock poisoned")
        })
    }
}

impl TransactionalAuthorizer for FakeGithub {
    fn execute_authorized(
        &self,
        request: &AuthorizedExecutionRequest<'_>,
    ) -> GateResult<ExecutionAttempt> {
        self.execute_in_transaction(request)
    }
}

fn require_scope(
    state: &State,
    adapter_tenant: &TenantId,
    principal: &PrincipalId,
    tenant: &TenantId,
) -> GateResult<()> {
    if tenant != adapter_tenant {
        return Err(GateError::new(
            ErrorCode::SnapshotScopeMismatch,
            "tenant differs from adapter scope",
        ));
    }
    if !state.allowed.contains(&(principal.clone(), tenant.clone())) {
        return Err(GateError::new(
            ErrorCode::AuthDenied,
            "principal is not currently authorized",
        ));
    }
    Ok(())
}
