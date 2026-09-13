use std::collections::BTreeSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::approval::{
    ApprovalProvider, ApprovalRequest, ApprovalReservation, ApprovalSemantics, ApprovalToken,
    InMemoryApprovalProvider,
};
use crate::audit::{AuditDraft, AuditLog, LatencyBreakdown};
use crate::authorize::TransactionalAuthorizer;
use crate::catalog::{build_snapshot, require_handle, Limits, Snapshot, SnapshotRequest};
use crate::clock::{Clock, SystemClock};
use crate::deadline::Deadline;
use crate::digest::{canonical_json, sha256_hex};
use crate::error::{ErrorCode, GateError, GateResult};
use crate::execute::AuthorizedExecutionRequest;
use crate::ids::{
    ActionDigest, ConversationId, GenerationNonce, IdempotencyKey, OperationId, PrincipalId,
    TenantId, ToolId,
};
use crate::normalize::parse_and_bound;
use crate::policy::{require_allowed, PolicyContext, PolicyEngine, WorkflowPolicy};
use crate::registry::{Registry, Risk, COMMENT_TOOL, INSPECT_TOOL, LIST_TOOL};
use crate::session::{GenerationConfig, GuideSession};
use crate::simulator::{ExecutionAttempt, ExecutionReceipt, FakeGithub, InspectionResult};
use crate::workflow::{WorkflowKey, WorkflowStore};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InspectionReceipt {
    pub issue_handle: String,
    pub title: String,
    pub source_revision: String,
    pub inspection_digest: String,
}

pub struct WriteRequest<'a> {
    pub principal: PrincipalId,
    pub tenant: TenantId,
    pub action_json: &'a [u8],
    pub snapshot: &'a Snapshot,
    pub generation_nonce: &'a GenerationNonce,
    pub operation_id: OperationId,
    pub conversation_id: ConversationId,
    pub approval: &'a ApprovalToken,
}

pub struct CommentApprovalRequest<'a> {
    pub principal: &'a PrincipalId,
    pub tenant: &'a TenantId,
    pub snapshot: &'a Snapshot,
    pub issue_handle: &'a str,
    pub body: &'a str,
    pub operation_id: &'a OperationId,
    pub conversation_id: &'a ConversationId,
    pub ttl_ms: u64,
    pub semantics: ApprovalSemantics,
}

pub struct Runtime {
    registry: Registry,
    adapter: Arc<FakeGithub>,
    approval: Arc<dyn ApprovalProvider>,
    policy: Arc<dyn PolicyEngine>,
    workflows: Arc<WorkflowStore>,
    clock: Arc<dyn Clock>,
    audit: AuditLog,
    limits: Limits,
    active_sessions: AtomicUsize,
}

impl Runtime {
    pub fn github() -> GateResult<Self> {
        Self::github_with_clock(Arc::new(SystemClock::new()))
    }

    pub fn github_with_clock(clock: Arc<dyn Clock>) -> GateResult<Self> {
        let limits = Limits::default();
        let workflows = Arc::new(WorkflowStore::new(
            limits.max_workflow_records,
            limits.max_workflow_bytes,
        ));
        let policy: Arc<dyn PolicyEngine> = Arc::new(WorkflowPolicy::new(Arc::clone(&workflows)));
        let approval: Arc<dyn ApprovalProvider> =
            Arc::new(InMemoryApprovalProvider::new(limits.max_approval_records));
        Ok(Self {
            registry: Registry::github()?,
            adapter: Arc::new(FakeGithub::seeded_with_clock(Arc::clone(&clock))),
            approval,
            policy,
            workflows,
            clock,
            audit: AuditLog::with_limits(
                limits.max_audit_entry_bytes,
                limits.max_audit_entries,
                limits.max_audit_bytes,
            ),
            limits,
            active_sessions: AtomicUsize::new(0),
        })
    }

    pub fn list_issues(
        &self,
        principal: PrincipalId,
        tenant: TenantId,
        ttl_ms: u64,
        nonce: GenerationNonce,
        conversation_id: ConversationId,
    ) -> GateResult<Snapshot> {
        let _permit = self.acquire_session()?;
        let now_ms = self.clock.wall_time_ms()?;
        let workflow = workflow_key(&principal, &tenant, &conversation_id);
        let tool_id = ToolId::new(LIST_TOOL, "1");
        let exposed = self.policy.exposed_tools(&workflow, now_ms)?;
        if !exposed.contains(&tool_id) {
            return Err(GateError::new(
                ErrorCode::PolicyDenied,
                "list tool is not exposed",
            ));
        }
        let spec = self.registry.require_exact(&tool_id)?;
        if spec.risk != Risk::Read {
            return Err(GateError::new(
                ErrorCode::InternalInvariant,
                "list risk differs",
            ));
        }
        let deadline = Deadline::after_ms(self.clock.as_ref(), spec.timeout_policy.generation_ms)?;
        let action = format!(
            "{{\"tool\":\"github.list_issues\",\"repository_handle\":{}}}",
            serde_json::to_string(self.adapter.repository().as_str()).map_err(|_| {
                GateError::new(
                    ErrorCode::InternalInvariant,
                    "repository serialization failed",
                )
            })?
        );
        let config = GenerationConfig::exact(&spec);
        let mut session = GuideSession::new(Arc::clone(&spec), None, config)?;
        session.generate_target_until(action.as_bytes(), self.clock.as_ref(), deadline)?;
        validate_list_action(action.as_bytes(), self.adapter.repository().as_str())?;
        let result = self.adapter.list_issues(&principal, &tenant)?;
        let expires_at_ms = now_ms.checked_add(ttl_ms).ok_or_else(|| {
            GateError::new(ErrorCode::CatalogTooLarge, "snapshot expiry overflow")
        })?;
        let comment_spec = self
            .registry
            .require_exact(&ToolId::new(COMMENT_TOOL, "1"))?;
        let snapshot = build_snapshot(
            &self.adapter,
            &comment_spec,
            &result,
            SnapshotRequest {
                principal,
                tenant,
                created_at_ms: now_ms,
                expires_at_ms,
                generation_nonce: nonce,
            },
            &self.limits,
        )?;
        self.workflows.record_listed(
            workflow,
            snapshot.digest().clone(),
            snapshot.source_revision().clone(),
            snapshot.expires_at_ms(),
        )?;
        self.audit.append(audit_draft(
            &snapshot,
            &spec,
            "snapshot_built",
            "list",
            Some(ActionDigest::new(sha256_hex(action.as_bytes()))),
            "allow",
            "not_required",
            "listed",
            None,
            None,
            self.policy.as_ref(),
            now_ms,
            LatencyBreakdown::zero(),
        ))?;
        Ok(snapshot)
    }

    pub fn inspect_issue(
        &self,
        principal: PrincipalId,
        tenant: TenantId,
        snapshot: &Snapshot,
        issue_handle: &str,
        conversation_id: ConversationId,
    ) -> GateResult<InspectionReceipt> {
        let _permit = self.acquire_session()?;
        let now_ms = self.clock.wall_time_ms()?;
        require_snapshot_scope(
            snapshot,
            &principal,
            &tenant,
            snapshot.generation_nonce(),
            now_ms,
        )?;
        let handle = require_handle(issue_handle)?;
        if !snapshot
            .values("writable_issue_handles")
            .is_some_and(|values| values.iter().any(|value| value == issue_handle))
        {
            return Err(GateError::new(
                ErrorCode::AuthDenied,
                "issue was not listed in snapshot",
            ));
        }
        let tool_id = ToolId::new(INSPECT_TOOL, "1");
        let workflow = workflow_key(&principal, &tenant, &conversation_id);
        let decision = self.policy.evaluate(&PolicyContext {
            workflow: &workflow,
            tool_id: &tool_id,
            issue_handle: Some(&handle),
            expected_revision: Some(snapshot.source_revision()),
            now_ms,
        })?;
        require_allowed(&decision)?;
        let spec = self.registry.require_exact(&tool_id)?;
        let action = format!(
            "{{\"tool\":\"github.inspect_issue\",\"issue_handle\":{}}}",
            serde_json::to_string(issue_handle).map_err(|_| {
                GateError::new(ErrorCode::InternalInvariant, "handle serialization failed")
            })?
        );
        let deadline = Deadline::after_ms(self.clock.as_ref(), spec.timeout_policy.generation_ms)?;
        let mut session =
            GuideSession::new(Arc::clone(&spec), None, GenerationConfig::exact(&spec))?;
        session.generate_target_until(action.as_bytes(), self.clock.as_ref(), deadline)?;
        let result =
            self.adapter
                .inspect_issue(&principal, &tenant, &handle, snapshot.source_revision())?;
        let receipt = normalize_inspection(&result, &spec.output_limits)?;
        self.workflows.record_inspected(
            workflow,
            snapshot.digest().clone(),
            handle,
            result.source_revision,
            receipt.inspection_digest.clone(),
            snapshot.expires_at_ms(),
        )?;
        self.audit.append(audit_draft(
            snapshot,
            &spec,
            "inspected",
            "inspect",
            Some(ActionDigest::new(sha256_hex(action.as_bytes()))),
            "allow",
            "not_required",
            "inspected",
            None,
            None,
            self.policy.as_ref(),
            self.clock.wall_time_ms()?,
            LatencyBreakdown::zero(),
        ))?;
        Ok(receipt)
    }

    pub fn approval_for_comment(
        &self,
        request: CommentApprovalRequest<'_>,
    ) -> GateResult<ApprovalToken> {
        let CommentApprovalRequest {
            principal,
            tenant,
            snapshot,
            issue_handle,
            body,
            operation_id,
            conversation_id,
            ttl_ms,
            semantics,
        } = request;
        let now_ms = self.clock.wall_time_ms()?;
        require_snapshot_scope(
            snapshot,
            principal,
            tenant,
            snapshot.generation_nonce(),
            now_ms,
        )?;
        let action = build_comment_action(issue_handle, body, self.limits.max_comment_bytes)?;
        require_snapshot_member(snapshot, action.handle.as_str())?;
        let spec = self
            .registry
            .require_exact(&ToolId::new(COMMENT_TOOL, "1"))?;
        let workflow = workflow_key(principal, tenant, conversation_id);
        let decision = self.policy.evaluate(&PolicyContext {
            workflow: &workflow,
            tool_id: &spec.id,
            issue_handle: Some(&action.handle),
            expected_revision: Some(snapshot.source_revision()),
            now_ms,
        })?;
        require_allowed(&decision)?;
        self.approval.issue(
            &approval_request(
                principal,
                tenant,
                operation_id,
                &spec.id,
                &action.digest,
                snapshot,
                &decision.policy_digest,
            ),
            self.clock.as_ref(),
            ttl_ms,
            semantics,
        )
    }

    pub fn run_write(&self, request: WriteRequest<'_>) -> GateResult<ExecutionReceipt> {
        let result = self.run_write_inner(&request);
        if let Err(error) = &result {
            if error.code != ErrorCode::AuditFailed {
                if let Ok(spec) = self.registry.require_exact(request.snapshot.tool_id()) {
                    let digest = action_digest_for_audit(request.action_json);
                    self.audit.append(audit_draft(
                        request.snapshot,
                        &spec,
                        "denied",
                        request.operation_id.as_str(),
                        digest,
                        if matches!(error.code, ErrorCode::AuthDenied | ErrorCode::CatalogStale) {
                            "deny"
                        } else {
                            "not_evaluated"
                        },
                        if error.code == ErrorCode::ApprovalDenied {
                            "deny"
                        } else {
                            "not_evaluated"
                        },
                        "not_executed",
                        Some(error.code),
                        None,
                        self.policy.as_ref(),
                        self.clock.wall_time_ms()?,
                        LatencyBreakdown::zero(),
                    ))?;
                }
            }
        }
        result
    }

    fn run_write_inner(&self, request: &WriteRequest<'_>) -> GateResult<ExecutionReceipt> {
        let _permit = self.acquire_session()?;
        let started_at_ms = self.clock.wall_time_ms()?;
        require_snapshot_scope(
            request.snapshot,
            &request.principal,
            &request.tenant,
            request.generation_nonce,
            started_at_ms,
        )?;
        let spec = self.registry.require_exact(request.snapshot.tool_id())?;
        if spec.id != ToolId::new(COMMENT_TOOL, "1") || spec.risk != Risk::Write {
            return Err(GateError::new(
                ErrorCode::InvalidToolSpec,
                "write coordinator requires the exact comment tool",
            ));
        }
        let total_timeout = spec
            .timeout_policy
            .generation_ms
            .checked_add(spec.timeout_policy.execution_ms)
            .ok_or_else(|| GateError::new(ErrorCode::InternalInvariant, "timeout overflow"))?;
        let deadline = Deadline::after_ms(self.clock.as_ref(), total_timeout)?;
        let generation_started = Instant::now();
        let imports = request.snapshot.to_imports()?;
        let mut session = GuideSession::new(
            Arc::clone(&spec),
            Some(imports),
            GenerationConfig::exact(&spec),
        )?;
        session.generate_target_until(request.action_json, self.clock.as_ref(), deadline)?;
        let generation_ns = elapsed_ns(generation_started);

        let validation_started = Instant::now();
        let raw: Value = serde_json::from_slice(request.action_json)
            .map_err(|_| GateError::new(ErrorCode::ParseFailed, "action is not valid JSON"))?;
        if !session.is_accepting()? {
            return Err(GateError::new(
                ErrorCode::NotAccepting,
                "guide is not accepting",
            ));
        }
        let action = validate_comment_action(raw, self.limits.max_comment_bytes)?;
        require_snapshot_member(request.snapshot, action.handle.as_str())?;
        let parse_validate_ns = elapsed_ns(validation_started);
        let now_ms = self.clock.wall_time_ms()?;
        if !request.snapshot.is_fresh(now_ms) {
            return Err(GateError::new(
                ErrorCode::CatalogStale,
                "snapshot expired after generation",
            ));
        }
        deadline.check(self.clock.as_ref())?;

        let policy_started = Instant::now();
        let workflow = workflow_key(
            &request.principal,
            &request.tenant,
            &request.conversation_id,
        );
        let decision = self.policy.evaluate(&PolicyContext {
            workflow: &workflow,
            tool_id: &spec.id,
            issue_handle: Some(&action.handle),
            expected_revision: Some(request.snapshot.source_revision()),
            now_ms,
        })?;
        require_allowed(&decision)?;
        let policy_ns = elapsed_ns(policy_started);

        let approval_started = Instant::now();
        let approval_request = approval_request(
            &request.principal,
            &request.tenant,
            &request.operation_id,
            &spec.id,
            &action.digest,
            request.snapshot,
            &decision.policy_digest,
        );
        self.approval
            .verify(request.approval, &approval_request, self.clock.as_ref())?;
        let approve_ns = elapsed_ns(approval_started);
        let key = derive_idempotency_key(
            &request.operation_id,
            &request.principal,
            &request.tenant,
            &spec.id,
            &action.digest,
        );
        let latency = LatencyBreakdown {
            generation_ns,
            parse_validate_ns,
            authorize_ns: 0,
            approve_ns,
            execute_ns: 0,
            policy_ns,
            normalize_ns: 0,
        };
        self.audit.append(audit_draft(
            request.snapshot,
            &spec,
            "pre_execution",
            request.operation_id.as_str(),
            Some(action.digest.clone()),
            "pending_transaction",
            "allow",
            "ready",
            None,
            Some(sha256_hex(key.as_str().as_bytes())),
            self.policy.as_ref(),
            self.clock.wall_time_ms()?,
            latency.clone(),
        ))?;
        deadline.check(self.clock.as_ref())?;

        let reservation = self.approval.reserve(
            request.approval,
            &approval_request,
            &key,
            self.clock.as_ref(),
        )?;

        let execute_started = Instant::now();
        let execution_request = AuthorizedExecutionRequest {
            principal: &request.principal,
            tenant: &request.tenant,
            operation_id: &request.operation_id,
            tool_id: &spec.id,
            issue_handle: &action.handle,
            body: &action.body,
            expected_revision: request.snapshot.source_revision(),
            action_digest: &action.digest,
            idempotency_key: &key,
            deadline,
            output_limits: &spec.output_limits,
        };
        let receipt = match reservation {
            ApprovalReservation::Completed(expected_digest) => {
                let mut receipt = self.adapter.reconcile(&key)?.ok_or_else(|| {
                    GateError::new(
                        ErrorCode::InternalInvariant,
                        "completed approval has no reconcilable receipt",
                    )
                    .safe_context(key.as_str())
                })?;
                if receipt.receipt_digest != expected_digest {
                    return Err(GateError::new(
                        ErrorCode::InternalInvariant,
                        "approval and adapter receipt digests differ",
                    )
                    .safe_context(key.as_str()));
                }
                receipt.replayed = true;
                receipt
            }
            ApprovalReservation::Reserved | ApprovalReservation::ExactRetry => {
                match self.adapter.execute_authorized(&execution_request)? {
                    ExecutionAttempt::Completed(receipt) => receipt,
                    ExecutionAttempt::TimeoutBeforeCommit => {
                        return Err(GateError::new(
                            ErrorCode::ToolTimeout,
                            "adapter timed out before commit",
                        ));
                    }
                    ExecutionAttempt::TimeoutAfterCommit(reference) => {
                        let mut receipt = self.adapter.reconcile(&key)?.ok_or_else(|| {
                            GateError::new(
                                ErrorCode::ToolTimeout,
                                "committed timeout could not be reconciled",
                            )
                            .safe_context(reference.as_str())
                        })?;
                        receipt.replayed = true;
                        receipt
                    }
                }
            }
        };
        let execute_ns = elapsed_ns(execute_started);
        let normalize_started = Instant::now();
        let receipt_bytes = serde_json::to_vec(&receipt).map_err(|_| {
            GateError::new(ErrorCode::InternalInvariant, "receipt serialization failed")
        })?;
        parse_and_bound(&receipt_bytes, &spec.output_limits)
            .map_err(|error| error.safe_context(key.as_str()))?;
        let normalize_ns = elapsed_ns(normalize_started);
        self.approval
            .complete(request.approval, &key, &receipt.receipt_digest)
            .map_err(|error| error.safe_context(key.as_str()))?;
        self.workflows
            .record_commented(
                workflow,
                request.snapshot.digest().clone(),
                action.handle.clone(),
                request.snapshot.source_revision().clone(),
                request.snapshot.expires_at_ms(),
            )
            .map_err(|error| error.safe_context(key.as_str()))?;
        let final_latency = LatencyBreakdown {
            execute_ns,
            normalize_ns,
            ..latency
        };
        if self
            .audit
            .append(audit_draft(
                request.snapshot,
                &spec,
                "executed",
                request.operation_id.as_str(),
                Some(action.digest),
                "allow_atomic",
                "allow",
                if receipt.replayed {
                    "replayed"
                } else {
                    "committed"
                },
                None,
                Some(sha256_hex(key.as_str().as_bytes())),
                self.policy.as_ref(),
                self.clock.wall_time_ms()?,
                final_latency,
            ))
            .is_err()
        {
            return Err(GateError::indeterminate(
                "execution committed but final audit persistence failed",
                key.to_string(),
            ));
        }
        Ok(receipt)
    }

    pub fn exposed_tools(
        &self,
        principal: PrincipalId,
        tenant: TenantId,
        conversation_id: ConversationId,
    ) -> GateResult<BTreeSet<ToolId>> {
        self.policy.exposed_tools(
            &workflow_key(&principal, &tenant, &conversation_id),
            self.clock.wall_time_ms()?,
        )
    }

    #[must_use]
    pub fn adapter(&self) -> &Arc<FakeGithub> {
        &self.adapter
    }

    #[must_use]
    pub fn audit(&self) -> &AuditLog {
        &self.audit
    }

    #[must_use]
    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    #[must_use]
    pub fn workflows(&self) -> &Arc<WorkflowStore> {
        &self.workflows
    }

    fn acquire_session(&self) -> GateResult<SessionPermit<'_>> {
        self.active_sessions
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < self.limits.max_concurrent_sessions).then(|| active + 1)
            })
            .map_err(|_| {
                GateError::new(
                    ErrorCode::CatalogTooLarge,
                    "concurrent session limit reached",
                )
            })?;
        Ok(SessionPermit {
            active: &self.active_sessions,
        })
    }
}

struct SessionPermit<'a> {
    active: &'a AtomicUsize,
}

impl Drop for SessionPermit<'_> {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

struct CommentAction {
    handle: crate::ids::OpaqueHandle,
    body: String,
    digest: ActionDigest,
}

fn build_comment_action(
    issue_handle: &str,
    body: &str,
    max_body_bytes: usize,
) -> GateResult<CommentAction> {
    let raw = serde_json::json!({
        "tool": COMMENT_TOOL,
        "issue_handle": issue_handle,
        "body": body,
    });
    validate_comment_action(raw, max_body_bytes)
}

pub fn normalized_comment_digest(issue_handle: &str, body: &str) -> GateResult<ActionDigest> {
    build_comment_action(issue_handle, body, Limits::default().max_comment_bytes)
        .map(|action| action.digest)
}

fn validate_comment_action(raw: Value, max_body_bytes: usize) -> GateResult<CommentAction> {
    let object = raw.as_object().ok_or_else(|| {
        GateError::new(
            ErrorCode::FinalValidationFailed,
            "comment action must be an object",
        )
    })?;
    if object.len() != 3 || object.get("tool").and_then(Value::as_str) != Some(COMMENT_TOOL) {
        return Err(GateError::new(
            ErrorCode::FinalValidationFailed,
            "comment action fields differ from schema",
        ));
    }
    let handle = object
        .get("issue_handle")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            GateError::new(
                ErrorCode::FinalValidationFailed,
                "issue_handle must be a string",
            )
        })?;
    let body = object
        .get("body")
        .and_then(Value::as_str)
        .ok_or_else(|| GateError::new(ErrorCode::FinalValidationFailed, "body must be a string"))?;
    if body.is_empty() || body.len() > max_body_bytes {
        return Err(GateError::new(
            ErrorCode::PolicyDenied,
            "comment body violates byte policy",
        ));
    }
    let normalized = canonical_json(&raw)?;
    Ok(CommentAction {
        handle: require_handle(handle)?,
        body: body.to_owned(),
        digest: ActionDigest::new(sha256_hex(normalized.as_bytes())),
    })
}

fn validate_list_action(bytes: &[u8], repository: &str) -> GateResult<()> {
    let raw: Value = serde_json::from_slice(bytes)
        .map_err(|_| GateError::new(ErrorCode::ParseFailed, "list action is not valid JSON"))?;
    let object = raw.as_object().ok_or_else(|| {
        GateError::new(
            ErrorCode::FinalValidationFailed,
            "list action must be an object",
        )
    })?;
    if object.len() != 2
        || object.get("tool").and_then(Value::as_str) != Some(LIST_TOOL)
        || object.get("repository_handle").and_then(Value::as_str) != Some(repository)
    {
        return Err(GateError::new(
            ErrorCode::FinalValidationFailed,
            "list action fields differ from contract",
        ));
    }
    Ok(())
}

fn normalize_inspection(
    result: &InspectionResult,
    limits: &crate::normalize::OutputLimits,
) -> GateResult<InspectionReceipt> {
    let value = serde_json::json!({
        "issue_handle": result.handle,
        "title": result.title,
        "source_revision": result.source_revision,
    });
    let raw = serde_json::to_vec(&value)
        .map_err(|_| GateError::new(ErrorCode::ToolFailed, "inspection serialization failed"))?;
    let bounded = parse_and_bound(&raw, limits)?;
    let normalized = canonical_json(&bounded)?;
    Ok(InspectionReceipt {
        issue_handle: result.handle.to_string(),
        title: result.title.clone(),
        source_revision: result.source_revision.to_string(),
        inspection_digest: sha256_hex(normalized.as_bytes()),
    })
}

fn require_snapshot_scope(
    snapshot: &Snapshot,
    principal: &PrincipalId,
    tenant: &TenantId,
    nonce: &GenerationNonce,
    now_ms: u64,
) -> GateResult<()> {
    if snapshot.principal() != principal
        || snapshot.tenant() != tenant
        || snapshot.generation_nonce() != nonce
    {
        return Err(GateError::new(
            ErrorCode::SnapshotScopeMismatch,
            "snapshot principal, tenant, or generation nonce differs",
        ));
    }
    if !snapshot.is_fresh(now_ms) {
        return Err(GateError::new(
            ErrorCode::CatalogStale,
            "snapshot is not fresh",
        ));
    }
    Ok(())
}

fn require_snapshot_member(snapshot: &Snapshot, handle: &str) -> GateResult<()> {
    if snapshot
        .values("writable_issue_handles")
        .is_some_and(|values| values.iter().any(|candidate| candidate == handle))
    {
        Ok(())
    } else {
        Err(GateError::new(
            ErrorCode::AuthDenied,
            "issue handle is absent from the generation snapshot",
        ))
    }
}

fn approval_request<'a>(
    principal: &'a PrincipalId,
    tenant: &'a TenantId,
    operation_id: &'a OperationId,
    tool_id: &'a ToolId,
    action_digest: &'a ActionDigest,
    snapshot: &'a Snapshot,
    policy_digest: &'a crate::ids::PolicyDigest,
) -> ApprovalRequest<'a> {
    ApprovalRequest {
        principal,
        tenant,
        operation_id,
        tool_id,
        action_digest,
        snapshot_digest: snapshot.digest(),
        source_revision: snapshot.source_revision(),
        policy_digest,
    }
}

fn workflow_key(
    principal: &PrincipalId,
    tenant: &TenantId,
    conversation: &ConversationId,
) -> WorkflowKey {
    WorkflowKey {
        principal: principal.clone(),
        tenant: tenant.clone(),
        conversation: conversation.clone(),
    }
}

pub fn derive_idempotency_key(
    operation: &OperationId,
    principal: &PrincipalId,
    tenant: &TenantId,
    tool: &ToolId,
    digest: &ActionDigest,
) -> IdempotencyKey {
    let material = format!(
        "{}:{}|{}:{}|{}:{}|{}:{}|{}:{}",
        operation.as_str().len(),
        operation,
        principal.as_str().len(),
        principal,
        tenant.as_str().len(),
        tenant,
        tool.to_string().len(),
        tool,
        digest.as_str().len(),
        digest,
    );
    IdempotencyKey::new(sha256_hex(material.as_bytes()))
}

fn action_digest_for_audit(bytes: &[u8]) -> Option<ActionDigest> {
    let raw = serde_json::from_slice(bytes).ok()?;
    let normalized = canonical_json(&raw).ok()?;
    Some(ActionDigest::new(sha256_hex(normalized.as_bytes())))
}

#[allow(clippy::too_many_arguments)]
fn audit_draft(
    snapshot: &Snapshot,
    spec: &crate::registry::ToolSpec,
    stage: &str,
    operation_id: &str,
    action_digest: Option<ActionDigest>,
    authorization: &str,
    approval: &str,
    execution_outcome: &str,
    error_code: Option<ErrorCode>,
    idempotency_digest: Option<String>,
    policy: &dyn PolicyEngine,
    timestamp_ms: u64,
    latency: LatencyBreakdown,
) -> AuditDraft {
    AuditDraft {
        timestamp_ms,
        stage: stage.to_owned(),
        principal: snapshot.principal().to_string(),
        tenant: snapshot.tenant().to_string(),
        tool_id: spec.id.to_string(),
        tool_schema_version: spec.id.version().as_str().to_owned(),
        vocabulary_fingerprint: spec.vocabulary_digest.clone(),
        schema_digest: spec.schema_digest.clone(),
        extension_digest: spec.extension_digest.clone(),
        engine_kind: spec.engine_kind.as_str().to_owned(),
        engine_version: spec.engine_kind.provenance().to_owned(),
        artifact_key: spec.artifact_key.to_string(),
        snapshot_id: snapshot.snapshot_id().to_string(),
        snapshot_digest: snapshot.digest().to_string(),
        source_revision: snapshot.source_revision().to_string(),
        snapshot_expiry_ms: snapshot.expires_at_ms(),
        generation_nonce: snapshot.generation_nonce().to_string(),
        operation_id: operation_id.to_owned(),
        action_digest: action_digest.map(|digest| digest.to_string()),
        authorization: authorization.to_owned(),
        approval: approval.to_owned(),
        policy_version: policy.version().to_owned(),
        policy_digest: policy.digest().to_string(),
        idempotency_digest,
        execution_outcome: execution_outcome.to_owned(),
        error_code: error_code.map(|code| code.as_str().to_owned()),
        latency,
    }
}

impl LatencyBreakdown {
    pub fn zero() -> Self {
        Self {
            generation_ns: 0,
            parse_validate_ns: 0,
            authorize_ns: 0,
            approve_ns: 0,
            execute_ns: 0,
            policy_ns: 0,
            normalize_ns: 0,
        }
    }
}

fn elapsed_ns(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX)
}
