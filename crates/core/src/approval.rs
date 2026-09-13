use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard};

use crate::clock::Clock;
use crate::digest::{canonical_json, sha256_hex};
use crate::error::{ErrorCode, GateError, GateResult};
use crate::ids::{
    ActionDigest, ApprovalId, IdempotencyKey, OperationId, PolicyDigest, PrincipalId,
    ReceiptDigest, SnapshotDigest, SourceRevision, TenantId, ToolId,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalSemantics {
    OneTime,
}

#[derive(Clone, Debug)]
pub struct ApprovalToken {
    approval_id: ApprovalId,
    expires_at_ms: u64,
}

impl ApprovalToken {
    #[must_use]
    pub fn approval_id(&self) -> &ApprovalId {
        &self.approval_id
    }

    #[must_use]
    pub fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }
}

pub struct ApprovalRequest<'a> {
    pub principal: &'a PrincipalId,
    pub tenant: &'a TenantId,
    pub operation_id: &'a OperationId,
    pub tool_id: &'a ToolId,
    pub action_digest: &'a ActionDigest,
    pub snapshot_digest: &'a SnapshotDigest,
    pub source_revision: &'a SourceRevision,
    pub policy_digest: &'a PolicyDigest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ApprovalReservation {
    Reserved,
    ExactRetry,
    Completed(ReceiptDigest),
}

pub trait ApprovalProvider: Send + Sync {
    fn issue(
        &self,
        request: &ApprovalRequest<'_>,
        clock: &dyn Clock,
        ttl_ms: u64,
        semantics: ApprovalSemantics,
    ) -> GateResult<ApprovalToken>;

    fn verify(
        &self,
        token: &ApprovalToken,
        request: &ApprovalRequest<'_>,
        clock: &dyn Clock,
    ) -> GateResult<()>;

    fn reserve(
        &self,
        token: &ApprovalToken,
        request: &ApprovalRequest<'_>,
        idempotency_key: &IdempotencyKey,
        clock: &dyn Clock,
    ) -> GateResult<ApprovalReservation>;

    fn complete(
        &self,
        token: &ApprovalToken,
        idempotency_key: &IdempotencyKey,
        receipt_digest: &ReceiptDigest,
    ) -> GateResult<()>;
}

#[derive(Clone, Debug)]
enum ApprovalState {
    Issued,
    Reserved {
        idempotency_key: IdempotencyKey,
    },
    Consumed {
        idempotency_key: IdempotencyKey,
        receipt_digest: ReceiptDigest,
    },
    Revoked,
}

#[derive(Clone, Debug)]
struct ApprovalRecord {
    request_digest: String,
    created_at_ms: u64,
    expires_at_ms: u64,
    semantics: ApprovalSemantics,
    state: ApprovalState,
}

pub struct InMemoryApprovalProvider {
    records: Mutex<BTreeMap<ApprovalId, ApprovalRecord>>,
    max_records: usize,
}

impl InMemoryApprovalProvider {
    #[must_use]
    pub fn new(max_records: usize) -> Self {
        Self {
            records: Mutex::new(BTreeMap::new()),
            max_records,
        }
    }

    pub fn revoke(&self, token: &ApprovalToken) -> GateResult<()> {
        let mut records = self.lock()?;
        let record = records.get_mut(token.approval_id()).ok_or_else(denied)?;
        record.state = ApprovalState::Revoked;
        Ok(())
    }

    pub fn retained_records(&self) -> GateResult<usize> {
        Ok(self.lock()?.len())
    }

    fn lock(&self) -> GateResult<MutexGuard<'_, BTreeMap<ApprovalId, ApprovalRecord>>> {
        self.records
            .lock()
            .map_err(|_| GateError::new(ErrorCode::ApprovalDenied, "approval lock poisoned"))
    }
}

impl ApprovalProvider for InMemoryApprovalProvider {
    fn issue(
        &self,
        request: &ApprovalRequest<'_>,
        clock: &dyn Clock,
        ttl_ms: u64,
        semantics: ApprovalSemantics,
    ) -> GateResult<ApprovalToken> {
        if ttl_ms == 0 {
            return Err(GateError::new(
                ErrorCode::ApprovalDenied,
                "approval TTL must be positive",
            ));
        }
        let created_at_ms = clock.wall_time_ms()?;
        let expires_at_ms = created_at_ms
            .checked_add(ttl_ms)
            .ok_or_else(|| GateError::new(ErrorCode::ApprovalDenied, "approval expiry overflow"))?;
        let request_digest = exact_request_digest(request, semantics)?;
        let mut records = self.lock()?;
        records.retain(|_, record| record.expires_at_ms > created_at_ms);
        if records.len() >= self.max_records {
            return Err(GateError::new(
                ErrorCode::ApprovalDenied,
                "approval retention limit reached",
            ));
        }
        let approval_id = unique_approval_id(&records)?;
        records.insert(
            approval_id.clone(),
            ApprovalRecord {
                request_digest,
                created_at_ms,
                expires_at_ms,
                semantics,
                state: ApprovalState::Issued,
            },
        );
        Ok(ApprovalToken {
            approval_id,
            expires_at_ms,
        })
    }

    fn verify(
        &self,
        token: &ApprovalToken,
        request: &ApprovalRequest<'_>,
        clock: &dyn Clock,
    ) -> GateResult<()> {
        let now_ms = clock.wall_time_ms()?;
        let records = self.lock()?;
        let record = records.get(token.approval_id()).ok_or_else(denied)?;
        verify_record(record, request, now_ms)
    }

    fn reserve(
        &self,
        token: &ApprovalToken,
        request: &ApprovalRequest<'_>,
        idempotency_key: &IdempotencyKey,
        clock: &dyn Clock,
    ) -> GateResult<ApprovalReservation> {
        let now_ms = clock.wall_time_ms()?;
        let mut records = self.lock()?;
        let record = records.get_mut(token.approval_id()).ok_or_else(denied)?;
        verify_record(record, request, now_ms)?;
        match &record.state {
            ApprovalState::Issued => {
                record.state = ApprovalState::Reserved {
                    idempotency_key: idempotency_key.clone(),
                };
                Ok(ApprovalReservation::Reserved)
            }
            ApprovalState::Reserved {
                idempotency_key: existing,
            } if existing == idempotency_key => Ok(ApprovalReservation::ExactRetry),
            ApprovalState::Consumed {
                idempotency_key: existing,
                receipt_digest,
            } if existing == idempotency_key => {
                Ok(ApprovalReservation::Completed(receipt_digest.clone()))
            }
            ApprovalState::Reserved { .. }
            | ApprovalState::Consumed { .. }
            | ApprovalState::Revoked => Err(denied()),
        }
    }

    fn complete(
        &self,
        token: &ApprovalToken,
        idempotency_key: &IdempotencyKey,
        receipt_digest: &ReceiptDigest,
    ) -> GateResult<()> {
        let mut records = self.lock()?;
        let record = records.get_mut(token.approval_id()).ok_or_else(denied)?;
        match &record.state {
            ApprovalState::Reserved {
                idempotency_key: existing,
            } if existing == idempotency_key => {
                record.state = ApprovalState::Consumed {
                    idempotency_key: idempotency_key.clone(),
                    receipt_digest: receipt_digest.clone(),
                };
                Ok(())
            }
            ApprovalState::Consumed {
                idempotency_key: existing,
                receipt_digest: existing_receipt,
            } if existing == idempotency_key && existing_receipt == receipt_digest => Ok(()),
            _ => Err(denied()),
        }
    }
}

fn verify_record(
    record: &ApprovalRecord,
    request: &ApprovalRequest<'_>,
    now_ms: u64,
) -> GateResult<()> {
    if now_ms < record.created_at_ms
        || now_ms >= record.expires_at_ms
        || matches!(record.state, ApprovalState::Revoked)
    {
        return Err(denied());
    }
    let candidate = exact_request_digest(request, record.semantics)?;
    if !constant_time_equal(record.request_digest.as_bytes(), candidate.as_bytes()) {
        return Err(denied());
    }
    Ok(())
}

fn exact_request_digest(
    request: &ApprovalRequest<'_>,
    semantics: ApprovalSemantics,
) -> GateResult<String> {
    let value = serde_json::json!({
        "principal": request.principal,
        "tenant": request.tenant,
        "operation": request.operation_id,
        "tool": request.tool_id.to_string(),
        "action": request.action_digest,
        "snapshot": request.snapshot_digest,
        "revision": request.source_revision,
        "policy": request.policy_digest,
        "semantics": match semantics {
            ApprovalSemantics::OneTime => "one_time",
        },
    });
    Ok(sha256_hex(canonical_json(&value)?.as_bytes()))
}

fn unique_approval_id(records: &BTreeMap<ApprovalId, ApprovalRecord>) -> GateResult<ApprovalId> {
    for _ in 0..4 {
        let mut random = [0_u8; 32];
        getrandom::fill(&mut random).map_err(|_| {
            GateError::new(
                ErrorCode::ApprovalDenied,
                "secure approval identifier generation failed",
            )
        })?;
        let id = ApprovalId::new(sha256_hex(&random));
        if !records.contains_key(&id) {
            return Ok(id);
        }
    }
    Err(GateError::new(
        ErrorCode::ApprovalDenied,
        "unique approval identifier generation failed",
    ))
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

fn denied() -> GateError {
    GateError::new(
        ErrorCode::ApprovalDenied,
        "approval is unavailable or does not match the request",
    )
}
