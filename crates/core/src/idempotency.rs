use std::collections::BTreeMap;

use crate::error::{ErrorCode, GateError, GateResult};
use crate::ids::{
    ActionDigest, IdempotencyKey, OperationId, ReceiptDigest, ReconciliationReference,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdempotencyState {
    Absent,
    Pending {
        operation: OperationId,
        action_digest: ActionDigest,
        created_at_ms: u64,
        lease_expiry_ms: u64,
    },
    Committed {
        receipt_digest: ReceiptDigest,
        normalized_receipt: String,
        committed_at_ms: u64,
    },
    Indeterminate {
        reconciliation_reference: ReconciliationReference,
    },
    FailedRetryable,
    FailedTerminal,
}

#[derive(Clone, Debug)]
enum Stored<T> {
    Pending {
        operation: OperationId,
        action_digest: ActionDigest,
        created_at_ms: u64,
        lease_expiry_ms: u64,
        bytes: usize,
    },
    Committed {
        action_digest: ActionDigest,
        receipt_digest: ReceiptDigest,
        receipt: T,
        normalized_receipt: String,
        committed_at_ms: u64,
        bytes: usize,
    },
    FailedRetryable {
        action_digest: ActionDigest,
        bytes: usize,
    },
    Indeterminate {
        action_digest: ActionDigest,
        reference: ReconciliationReference,
        bytes: usize,
    },
    FailedTerminal {
        action_digest: ActionDigest,
        bytes: usize,
    },
}

impl<T> Stored<T> {
    fn digest(&self) -> &ActionDigest {
        match self {
            Self::Pending { action_digest, .. }
            | Self::Committed { action_digest, .. }
            | Self::FailedRetryable { action_digest, .. }
            | Self::Indeterminate { action_digest, .. }
            | Self::FailedTerminal { action_digest, .. } => action_digest,
        }
    }

    fn bytes(&self) -> usize {
        match self {
            Self::Pending { bytes, .. }
            | Self::Committed { bytes, .. }
            | Self::FailedRetryable { bytes, .. }
            | Self::Indeterminate { bytes, .. }
            | Self::FailedTerminal { bytes, .. } => *bytes,
        }
    }
}

pub enum BeginOutcome<T> {
    Started,
    Replay(T),
    Pending,
    Indeterminate(ReconciliationReference),
    TerminalFailure,
}

pub trait IdempotencyStore<T: Clone> {
    fn begin(
        &mut self,
        key: IdempotencyKey,
        operation: OperationId,
        action_digest: ActionDigest,
        created_at_ms: u64,
        lease_expiry_ms: u64,
        accounted_bytes: usize,
    ) -> GateResult<BeginOutcome<T>>;
    fn commit(
        &mut self,
        key: &IdempotencyKey,
        action_digest: &ActionDigest,
        receipt_digest: ReceiptDigest,
        receipt: T,
        normalized_receipt: String,
        committed_at_ms: u64,
    ) -> GateResult<()>;
    fn fail_retryable(
        &mut self,
        key: &IdempotencyKey,
        action_digest: &ActionDigest,
    ) -> GateResult<()>;
    fn reconcile(&self, key: &IdempotencyKey) -> GateResult<Option<T>>;
    fn mark_indeterminate(
        &mut self,
        key: &IdempotencyKey,
        action_digest: &ActionDigest,
        reference: ReconciliationReference,
    ) -> GateResult<()>;
    fn fail_terminal(
        &mut self,
        key: &IdempotencyKey,
        action_digest: &ActionDigest,
    ) -> GateResult<()>;
}

#[derive(Debug)]
pub struct BoundedIdempotencyStore<T> {
    records: BTreeMap<IdempotencyKey, Stored<T>>,
    retained_bytes: usize,
    max_records: usize,
    max_bytes: usize,
}

impl<T> BoundedIdempotencyStore<T> {
    #[must_use]
    pub fn new(max_records: usize, max_bytes: usize) -> Self {
        Self {
            records: BTreeMap::new(),
            retained_bytes: 0,
            max_records,
            max_bytes,
        }
    }

    #[must_use]
    pub fn retained(&self) -> (usize, usize) {
        (self.records.len(), self.retained_bytes)
    }

    pub fn state(&self, key: &IdempotencyKey) -> IdempotencyState {
        match self.records.get(key) {
            None => IdempotencyState::Absent,
            Some(Stored::Pending {
                operation,
                action_digest,
                created_at_ms,
                lease_expiry_ms,
                ..
            }) => IdempotencyState::Pending {
                operation: operation.clone(),
                action_digest: action_digest.clone(),
                created_at_ms: *created_at_ms,
                lease_expiry_ms: *lease_expiry_ms,
            },
            Some(Stored::Committed {
                receipt_digest,
                normalized_receipt,
                committed_at_ms,
                ..
            }) => IdempotencyState::Committed {
                receipt_digest: receipt_digest.clone(),
                normalized_receipt: normalized_receipt.clone(),
                committed_at_ms: *committed_at_ms,
            },
            Some(Stored::FailedRetryable { .. }) => IdempotencyState::FailedRetryable,
            Some(Stored::Indeterminate { reference, .. }) => IdempotencyState::Indeterminate {
                reconciliation_reference: reference.clone(),
            },
            Some(Stored::FailedTerminal { .. }) => IdempotencyState::FailedTerminal,
        }
    }

    fn matching_bytes(
        &self,
        key: &IdempotencyKey,
        action_digest: &ActionDigest,
    ) -> GateResult<usize> {
        let record = self.records.get(key).ok_or_else(|| {
            GateError::new(ErrorCode::InternalInvariant, "idempotency record is absent")
        })?;
        if record.digest() != action_digest {
            return Err(conflict());
        }
        Ok(record.bytes())
    }
}

impl<T: Clone> IdempotencyStore<T> for BoundedIdempotencyStore<T> {
    fn begin(
        &mut self,
        key: IdempotencyKey,
        operation: OperationId,
        action_digest: ActionDigest,
        created_at_ms: u64,
        lease_expiry_ms: u64,
        accounted_bytes: usize,
    ) -> GateResult<BeginOutcome<T>> {
        if let Some(Stored::Pending {
            action_digest: existing_digest,
            lease_expiry_ms: existing_expiry,
            bytes,
            ..
        }) = self.records.get(&key)
        {
            if existing_digest != &action_digest {
                return Err(conflict());
            }
            if created_at_ms < *existing_expiry {
                return Ok(BeginOutcome::Pending);
            }
            let retained_bytes = *bytes;
            self.records.remove(&key);
            self.retained_bytes = self
                .retained_bytes
                .checked_sub(retained_bytes)
                .ok_or_else(accounting_error)?;
        }
        if let Some(record) = self.records.get(&key) {
            if record.digest() != &action_digest {
                return Err(conflict());
            }
            match record {
                Stored::Committed { receipt, .. } => {
                    return Ok(BeginOutcome::Replay(receipt.clone()));
                }
                Stored::Pending { .. } => {
                    return Err(GateError::new(
                        ErrorCode::InternalInvariant,
                        "expired idempotency lease was not cleared",
                    ));
                }
                Stored::Indeterminate { reference, .. } => {
                    return Ok(BeginOutcome::Indeterminate(reference.clone()));
                }
                Stored::FailedTerminal { .. } => return Ok(BeginOutcome::TerminalFailure),
                Stored::FailedRetryable { .. } => {
                    let old_bytes = record.bytes();
                    self.retained_bytes = self
                        .retained_bytes
                        .checked_sub(old_bytes)
                        .ok_or_else(accounting_error)?;
                    self.records.remove(&key);
                }
            }
        }
        let next_bytes = self
            .retained_bytes
            .checked_add(accounted_bytes)
            .ok_or_else(accounting_error)?;
        if self.records.len() >= self.max_records || next_bytes > self.max_bytes {
            return Err(GateError::new(
                ErrorCode::ToolFailed,
                "idempotency retention limit reached",
            ));
        }
        self.records.insert(
            key,
            Stored::Pending {
                operation,
                action_digest,
                created_at_ms,
                lease_expiry_ms,
                bytes: accounted_bytes,
            },
        );
        self.retained_bytes = next_bytes;
        Ok(BeginOutcome::Started)
    }

    fn commit(
        &mut self,
        key: &IdempotencyKey,
        action_digest: &ActionDigest,
        receipt_digest: ReceiptDigest,
        receipt: T,
        normalized_receipt: String,
        committed_at_ms: u64,
    ) -> GateResult<()> {
        let bytes = self.matching_bytes(key, action_digest)?;
        self.records.insert(
            key.clone(),
            Stored::Committed {
                action_digest: action_digest.clone(),
                receipt_digest,
                receipt,
                normalized_receipt,
                committed_at_ms,
                bytes,
            },
        );
        Ok(())
    }

    fn fail_retryable(
        &mut self,
        key: &IdempotencyKey,
        action_digest: &ActionDigest,
    ) -> GateResult<()> {
        let bytes = self.matching_bytes(key, action_digest)?;
        self.records.insert(
            key.clone(),
            Stored::FailedRetryable {
                action_digest: action_digest.clone(),
                bytes,
            },
        );
        Ok(())
    }

    fn reconcile(&self, key: &IdempotencyKey) -> GateResult<Option<T>> {
        Ok(match self.records.get(key) {
            Some(Stored::Committed { receipt, .. }) => Some(receipt.clone()),
            _ => None,
        })
    }

    fn mark_indeterminate(
        &mut self,
        key: &IdempotencyKey,
        action_digest: &ActionDigest,
        reference: ReconciliationReference,
    ) -> GateResult<()> {
        let bytes = self.matching_bytes(key, action_digest)?;
        self.records.insert(
            key.clone(),
            Stored::Indeterminate {
                action_digest: action_digest.clone(),
                reference,
                bytes,
            },
        );
        Ok(())
    }

    fn fail_terminal(
        &mut self,
        key: &IdempotencyKey,
        action_digest: &ActionDigest,
    ) -> GateResult<()> {
        let bytes = self.matching_bytes(key, action_digest)?;
        self.records.insert(
            key.clone(),
            Stored::FailedTerminal {
                action_digest: action_digest.clone(),
                bytes,
            },
        );
        Ok(())
    }
}

fn conflict() -> GateError {
    GateError::new(
        ErrorCode::IdempotencyConflict,
        "idempotency key action differs",
    )
}

fn accounting_error() -> GateError {
    GateError::new(
        ErrorCode::InternalInvariant,
        "idempotency accounting invariant failed",
    )
}

#[cfg(test)]
mod tests {
    use super::{BeginOutcome, BoundedIdempotencyStore, IdempotencyState, IdempotencyStore};
    use crate::error::ErrorCode;
    use crate::ids::{
        ActionDigest, IdempotencyKey, OperationId, ReceiptDigest, ReconciliationReference,
    };

    #[test]
    fn bounded_store_replays_and_rejects_digest_reuse() {
        let mut store = BoundedIdempotencyStore::new(1, 128);
        let key = IdempotencyKey::new("key");
        let digest = ActionDigest::new("digest-a");
        assert!(matches!(
            store
                .begin(
                    key.clone(),
                    OperationId::new("operation"),
                    digest.clone(),
                    1,
                    2,
                    64,
                )
                .expect("begin"),
            BeginOutcome::Started
        ));
        store
            .commit(
                &key,
                &digest,
                ReceiptDigest::new("receipt"),
                "value".to_owned(),
                "normalized".to_owned(),
                2,
            )
            .expect("commit");
        assert!(matches!(
            store.state(&key),
            IdempotencyState::Committed { .. }
        ));
        assert!(matches!(
            store
                .begin(
                    key.clone(),
                    OperationId::new("operation"),
                    digest,
                    1,
                    2,
                    64,
                )
                .expect("replay"),
            BeginOutcome::Replay(value) if value == "value"
        ));
        let error = store
            .begin(
                key,
                OperationId::new("operation"),
                ActionDigest::new("digest-b"),
                1,
                2,
                64,
            )
            .err()
            .expect("conflict");
        assert_eq!(error.code, ErrorCode::IdempotencyConflict);
    }

    #[test]
    fn indeterminate_and_terminal_states_are_observable() {
        let mut store = BoundedIdempotencyStore::<String>::new(2, 256);
        let key = IdempotencyKey::new("key-a");
        let digest = ActionDigest::new("digest-a");
        store
            .begin(
                key.clone(),
                OperationId::new("operation-a"),
                digest.clone(),
                1,
                2,
                64,
            )
            .expect("begin");
        store
            .mark_indeterminate(&key, &digest, ReconciliationReference::new("reference"))
            .expect("indeterminate");
        assert!(matches!(
            store.state(&key),
            IdempotencyState::Indeterminate { .. }
        ));

        let terminal_key = IdempotencyKey::new("key-b");
        let terminal_digest = ActionDigest::new("digest-b");
        store
            .begin(
                terminal_key.clone(),
                OperationId::new("operation-b"),
                terminal_digest.clone(),
                1,
                2,
                64,
            )
            .expect("begin");
        store
            .fail_terminal(&terminal_key, &terminal_digest)
            .expect("terminal");
        assert_eq!(store.state(&terminal_key), IdempotencyState::FailedTerminal);
    }

    #[test]
    fn expired_pending_lease_can_be_restarted() {
        let mut store = BoundedIdempotencyStore::<String>::new(1, 128);
        let key = IdempotencyKey::new("key");
        let digest = ActionDigest::new("digest");
        store
            .begin(
                key.clone(),
                OperationId::new("operation"),
                digest.clone(),
                10,
                20,
                64,
            )
            .expect("initial begin");
        assert!(matches!(
            store
                .begin(
                    key.clone(),
                    OperationId::new("operation"),
                    digest.clone(),
                    19,
                    30,
                    64,
                )
                .expect("pending"),
            BeginOutcome::Pending
        ));
        assert!(matches!(
            store
                .begin(key, OperationId::new("operation"), digest, 20, 30, 64,)
                .expect("restart"),
            BeginOutcome::Started
        ));
        assert_eq!(store.retained(), (1, 64));
    }
}
