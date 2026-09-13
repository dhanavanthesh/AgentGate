use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard};

use crate::error::{ErrorCode, GateError, GateResult};
use crate::ids::{
    ConversationId, OpaqueHandle, PrincipalId, SnapshotDigest, SourceRevision, TenantId,
};

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct WorkflowKey {
    pub principal: PrincipalId,
    pub tenant: TenantId,
    pub conversation: ConversationId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkflowTransition {
    List,
    Inspect,
    Comment,
    None,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WorkflowState {
    Initial,
    Listed {
        snapshot_digest: SnapshotDigest,
        revision: SourceRevision,
        expires_at_ms: u64,
    },
    Inspected {
        snapshot_digest: SnapshotDigest,
        issue_handle: OpaqueHandle,
        revision: SourceRevision,
        inspection_digest: String,
        expires_at_ms: u64,
    },
    Commented {
        snapshot_digest: SnapshotDigest,
        issue_handle: OpaqueHandle,
        revision: SourceRevision,
        expires_at_ms: u64,
    },
}

struct WorkflowRecord {
    state: WorkflowState,
    accounted_bytes: usize,
    last_used: u64,
}

#[derive(Default)]
struct StoreState {
    records: BTreeMap<WorkflowKey, WorkflowRecord>,
    accounted_bytes: usize,
    clock: u64,
}

pub struct WorkflowStore {
    state: Mutex<StoreState>,
    max_records: usize,
    max_bytes: usize,
}

impl WorkflowStore {
    #[must_use]
    pub fn new(max_records: usize, max_bytes: usize) -> Self {
        Self {
            state: Mutex::new(StoreState::default()),
            max_records,
            max_bytes,
        }
    }

    pub fn get(&self, key: &WorkflowKey, now_ms: u64) -> GateResult<WorkflowState> {
        let mut state = self.lock()?;
        state.clock = checked_increment(state.clock)?;
        let clock = state.clock;
        let Some(record) = state.records.get_mut(key) else {
            return Ok(WorkflowState::Initial);
        };
        record.last_used = clock;
        if is_expired(&record.state, now_ms) {
            return Ok(WorkflowState::Initial);
        }
        Ok(record.state.clone())
    }

    pub fn record_listed(
        &self,
        key: WorkflowKey,
        snapshot_digest: SnapshotDigest,
        revision: SourceRevision,
        expires_at_ms: u64,
    ) -> GateResult<()> {
        self.insert(
            key,
            WorkflowState::Listed {
                snapshot_digest,
                revision,
                expires_at_ms,
            },
        )
    }

    pub fn record_inspected(
        &self,
        key: WorkflowKey,
        snapshot_digest: SnapshotDigest,
        issue_handle: OpaqueHandle,
        revision: SourceRevision,
        inspection_digest: String,
        expires_at_ms: u64,
    ) -> GateResult<()> {
        self.insert(
            key,
            WorkflowState::Inspected {
                snapshot_digest,
                issue_handle,
                revision,
                inspection_digest,
                expires_at_ms,
            },
        )
    }

    pub fn record_commented(
        &self,
        key: WorkflowKey,
        snapshot_digest: SnapshotDigest,
        issue_handle: OpaqueHandle,
        revision: SourceRevision,
        expires_at_ms: u64,
    ) -> GateResult<()> {
        self.insert(
            key,
            WorkflowState::Commented {
                snapshot_digest,
                issue_handle,
                revision,
                expires_at_ms,
            },
        )
    }

    pub fn len(&self) -> GateResult<usize> {
        Ok(self.lock()?.records.len())
    }

    pub fn is_empty(&self) -> GateResult<bool> {
        Ok(self.lock()?.records.is_empty())
    }

    fn insert(&self, key: WorkflowKey, next: WorkflowState) -> GateResult<()> {
        let bytes = estimate_bytes(&key, &next)?;
        if self.max_records == 0 || bytes > self.max_bytes {
            return Err(GateError::new(
                ErrorCode::CatalogTooLarge,
                "workflow record exceeds retention limit",
            ));
        }
        let mut state = self.lock()?;
        if let Some(previous) = state.records.remove(&key) {
            state.accounted_bytes = state
                .accounted_bytes
                .checked_sub(previous.accounted_bytes)
                .ok_or_else(accounting_error)?;
        }
        while state.records.len() >= self.max_records
            || state
                .accounted_bytes
                .checked_add(bytes)
                .is_none_or(|total| total > self.max_bytes)
        {
            let victim = state
                .records
                .iter()
                .min_by_key(|(candidate, record)| (record.last_used, (*candidate).clone()))
                .map(|(candidate, _)| candidate.clone())
                .ok_or_else(accounting_error)?;
            let removed = state.records.remove(&victim).ok_or_else(accounting_error)?;
            state.accounted_bytes = state
                .accounted_bytes
                .checked_sub(removed.accounted_bytes)
                .ok_or_else(accounting_error)?;
        }
        state.clock = checked_increment(state.clock)?;
        let last_used = state.clock;
        state.accounted_bytes = state
            .accounted_bytes
            .checked_add(bytes)
            .ok_or_else(accounting_error)?;
        state.records.insert(
            key,
            WorkflowRecord {
                state: next,
                accounted_bytes: bytes,
                last_used,
            },
        );
        Ok(())
    }

    fn lock(&self) -> GateResult<MutexGuard<'_, StoreState>> {
        self.state
            .lock()
            .map_err(|_| GateError::new(ErrorCode::InternalInvariant, "workflow lock poisoned"))
    }
}

fn is_expired(state: &WorkflowState, now_ms: u64) -> bool {
    match state {
        WorkflowState::Initial => false,
        WorkflowState::Listed { expires_at_ms, .. }
        | WorkflowState::Inspected { expires_at_ms, .. }
        | WorkflowState::Commented { expires_at_ms, .. } => now_ms >= *expires_at_ms,
    }
}

fn estimate_bytes(key: &WorkflowKey, state: &WorkflowState) -> GateResult<usize> {
    let fixed = key
        .principal
        .as_str()
        .len()
        .checked_add(key.tenant.as_str().len())
        .and_then(|bytes| bytes.checked_add(key.conversation.as_str().len()))
        .and_then(|bytes| bytes.checked_add(128))
        .ok_or_else(accounting_error)?;
    let dynamic = match state {
        WorkflowState::Initial => 0,
        WorkflowState::Listed {
            snapshot_digest,
            revision,
            ..
        } => snapshot_digest
            .as_str()
            .len()
            .checked_add(revision.as_str().len())
            .ok_or_else(accounting_error)?,
        WorkflowState::Inspected {
            snapshot_digest,
            issue_handle,
            revision,
            inspection_digest,
            ..
        } => snapshot_digest
            .as_str()
            .len()
            .checked_add(issue_handle.as_str().len())
            .and_then(|bytes| bytes.checked_add(revision.as_str().len()))
            .and_then(|bytes| bytes.checked_add(inspection_digest.len()))
            .ok_or_else(accounting_error)?,
        WorkflowState::Commented {
            snapshot_digest,
            issue_handle,
            revision,
            ..
        } => snapshot_digest
            .as_str()
            .len()
            .checked_add(issue_handle.as_str().len())
            .and_then(|bytes| bytes.checked_add(revision.as_str().len()))
            .ok_or_else(accounting_error)?,
    };
    fixed.checked_add(dynamic).ok_or_else(accounting_error)
}

fn checked_increment(value: u64) -> GateResult<u64> {
    value
        .checked_add(1)
        .ok_or_else(|| GateError::new(ErrorCode::InternalInvariant, "workflow counter overflow"))
}

fn accounting_error() -> GateError {
    GateError::new(
        ErrorCode::InternalInvariant,
        "workflow accounting invariant failed",
    )
}
