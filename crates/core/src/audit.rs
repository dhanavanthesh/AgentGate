use std::sync::{Mutex, MutexGuard};

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::digest::{canonical_json, sha256_hex};
use crate::error::{ErrorCode, GateError, GateResult};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LatencyBreakdown {
    pub generation_ns: u64,
    pub parse_validate_ns: u64,
    pub authorize_ns: u64,
    pub approve_ns: u64,
    pub execute_ns: u64,
    pub policy_ns: u64,
    pub normalize_ns: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuditEntry {
    pub schema_version: u32,
    pub event_id: String,
    pub sequence: u64,
    pub timestamp_ms: u64,
    pub stage: String,
    pub principal: String,
    pub tenant: String,
    pub tool_id: String,
    pub tool_schema_version: String,
    pub oc_sidememory_version: String,
    pub engine_kind: String,
    pub engine_version: String,
    pub artifact_key: String,
    pub vocabulary_fingerprint: String,
    pub schema_digest: String,
    pub extension_digest: String,
    pub snapshot_id: String,
    pub snapshot_digest: String,
    pub source_revision: String,
    pub snapshot_expiry_ms: u64,
    pub generation_nonce: String,
    pub operation_id: String,
    pub action_digest: Option<String>,
    pub authorization: String,
    pub approval: String,
    pub policy_version: String,
    pub policy_digest: String,
    pub idempotency_digest: Option<String>,
    pub execution_outcome: String,
    pub error_code: Option<String>,
    pub latency: LatencyBreakdown,
    pub previous_digest: String,
    pub digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuditAnchor {
    pub sequence: u64,
    pub digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuditPage {
    pub anchor: AuditAnchor,
    pub entries: Vec<AuditEntry>,
}

#[derive(Clone, Debug)]
pub struct AuditDraft {
    pub timestamp_ms: u64,
    pub stage: String,
    pub principal: String,
    pub tenant: String,
    pub tool_id: String,
    pub tool_schema_version: String,
    pub vocabulary_fingerprint: String,
    pub schema_digest: String,
    pub extension_digest: String,
    pub engine_kind: String,
    pub engine_version: String,
    pub artifact_key: String,
    pub snapshot_id: String,
    pub snapshot_digest: String,
    pub source_revision: String,
    pub snapshot_expiry_ms: u64,
    pub generation_nonce: String,
    pub operation_id: String,
    pub action_digest: Option<String>,
    pub authorization: String,
    pub approval: String,
    pub policy_version: String,
    pub policy_digest: String,
    pub idempotency_digest: Option<String>,
    pub execution_outcome: String,
    pub error_code: Option<String>,
    pub latency: LatencyBreakdown,
}

#[derive(Default)]
struct State {
    entries: Vec<AuditEntry>,
    total_bytes: usize,
    appends_until_failure: Option<usize>,
}

pub struct AuditLog {
    state: Mutex<State>,
    max_entry_bytes: usize,
    max_entries: usize,
    max_total_bytes: usize,
}

impl AuditLog {
    pub fn new(max_entry_bytes: usize) -> Self {
        Self::with_limits(max_entry_bytes, 4096, 16 * 1024 * 1024)
    }

    pub fn with_limits(max_entry_bytes: usize, max_entries: usize, max_total_bytes: usize) -> Self {
        Self {
            state: Mutex::new(State::default()),
            max_entry_bytes,
            max_entries,
            max_total_bytes,
        }
    }

    pub fn append(&self, draft: AuditDraft) -> GateResult<AuditEntry> {
        let mut state = self.lock()?;
        if let Some(remaining) = state.appends_until_failure.as_mut() {
            if *remaining == 0 {
                state.appends_until_failure = None;
                return Err(GateError::new(
                    ErrorCode::AuditFailed,
                    "injected audit persistence failure",
                ));
            }
            *remaining -= 1;
        }
        let sequence = u64::try_from(state.entries.len())
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| GateError::new(ErrorCode::AuditFailed, "audit sequence overflow"))?;
        let previous_digest = state
            .entries
            .last()
            .map_or_else(|| "0".repeat(64), |entry| entry.digest.clone());
        let event_id = format!("event_{sequence:016x}");
        let mut entry = AuditEntry {
            schema_version: 1,
            event_id,
            sequence,
            timestamp_ms: draft.timestamp_ms,
            stage: draft.stage,
            principal: draft.principal,
            tenant: draft.tenant,
            tool_id: draft.tool_id,
            tool_schema_version: draft.tool_schema_version,
            oc_sidememory_version: "0.1.0".to_owned(),
            engine_kind: draft.engine_kind,
            engine_version: draft.engine_version,
            artifact_key: draft.artifact_key,
            vocabulary_fingerprint: draft.vocabulary_fingerprint,
            schema_digest: draft.schema_digest,
            extension_digest: draft.extension_digest,
            snapshot_id: draft.snapshot_id,
            snapshot_digest: draft.snapshot_digest,
            source_revision: draft.source_revision,
            snapshot_expiry_ms: draft.snapshot_expiry_ms,
            generation_nonce: draft.generation_nonce,
            operation_id: draft.operation_id,
            action_digest: draft.action_digest,
            authorization: draft.authorization,
            approval: draft.approval,
            policy_version: draft.policy_version,
            policy_digest: draft.policy_digest,
            idempotency_digest: draft.idempotency_digest,
            execution_outcome: draft.execution_outcome,
            error_code: draft.error_code,
            latency: draft.latency,
            previous_digest,
            digest: String::new(),
        };
        entry.digest = digest_entry(&entry)?;
        let bytes =
            canonical_json(&serde_json::to_value(&entry).map_err(|_| {
                GateError::new(ErrorCode::AuditFailed, "audit serialization failed")
            })?)?
            .len();
        if bytes > self.max_entry_bytes {
            return Err(GateError::new(
                ErrorCode::AuditFailed,
                "audit entry exceeds byte limit",
            ));
        }
        let next_total = state.total_bytes.checked_add(bytes).ok_or_else(|| {
            GateError::new(ErrorCode::AuditFailed, "audit byte accounting overflow")
        })?;
        if state.entries.len() >= self.max_entries || next_total > self.max_total_bytes {
            return Err(GateError::new(
                ErrorCode::AuditFailed,
                "audit retention limit reached",
            ));
        }
        state.entries.push(entry.clone());
        state.total_bytes = next_total;
        Ok(entry)
    }

    pub fn inject_failure(&self) -> GateResult<()> {
        self.lock()?.appends_until_failure = Some(0);
        Ok(())
    }

    pub fn inject_failure_after(&self, successful_appends: usize) -> GateResult<()> {
        self.lock()?.appends_until_failure = Some(successful_appends);
        Ok(())
    }

    pub fn entries(&self) -> GateResult<Vec<AuditEntry>> {
        Ok(self.lock()?.entries.clone())
    }

    pub fn page(&self, offset: usize, limit: usize) -> GateResult<Vec<AuditEntry>> {
        let state = self.lock()?;
        if offset >= state.entries.len() {
            return Ok(Vec::new());
        }
        let end = offset.saturating_add(limit).min(state.entries.len());
        Ok(state.entries[offset..end].to_vec())
    }

    pub fn page_with_anchor(&self, offset: usize, limit: usize) -> GateResult<AuditPage> {
        let state = self.lock()?;
        let anchor = if offset == 0 {
            AuditAnchor {
                sequence: 0,
                digest: "0".repeat(64),
            }
        } else {
            let previous = state.entries.get(offset - 1).ok_or_else(|| {
                GateError::new(
                    ErrorCode::AuditFailed,
                    "audit page offset is outside the log",
                )
            })?;
            AuditAnchor {
                sequence: previous.sequence,
                digest: previous.digest.clone(),
            }
        };
        let entries = if offset >= state.entries.len() {
            Vec::new()
        } else {
            let end = offset.saturating_add(limit).min(state.entries.len());
            state.entries[offset..end].to_vec()
        };
        Ok(AuditPage { anchor, entries })
    }

    pub fn retained(&self) -> GateResult<(usize, usize)> {
        let state = self.lock()?;
        Ok((state.entries.len(), state.total_bytes))
    }

    pub fn verify(entries: &[AuditEntry]) -> GateResult<()> {
        Self::verify_page(&AuditPage {
            anchor: AuditAnchor {
                sequence: 0,
                digest: "0".repeat(64),
            },
            entries: entries.to_vec(),
        })
    }

    pub fn verify_page(page: &AuditPage) -> GateResult<()> {
        let mut previous = page.anchor.digest.clone();
        let mut expected_sequence = page.anchor.sequence;
        for entry in &page.entries {
            expected_sequence = expected_sequence
                .checked_add(1)
                .ok_or_else(|| GateError::new(ErrorCode::AuditFailed, "audit sequence overflow"))?;
            if entry.sequence != expected_sequence
                || entry.previous_digest != previous
                || digest_entry(entry)? != entry.digest
            {
                return Err(GateError::new(
                    ErrorCode::AuditFailed,
                    "audit chain verification failed",
                ));
            }
            previous.clone_from(&entry.digest);
        }
        Ok(())
    }

    fn lock(&self) -> GateResult<MutexGuard<'_, State>> {
        self.state
            .lock()
            .map_err(|_| GateError::new(ErrorCode::AuditFailed, "audit state lock poisoned"))
    }
}

fn digest_entry(entry: &AuditEntry) -> GateResult<String> {
    let value = json!({
        "schema_version": entry.schema_version,
        "event_id": entry.event_id,
        "sequence": entry.sequence,
        "timestamp_ms": entry.timestamp_ms,
        "stage": entry.stage,
        "principal": entry.principal,
        "tenant": entry.tenant,
        "tool_id": entry.tool_id,
        "tool_schema_version": entry.tool_schema_version,
        "oc_sidememory_version": entry.oc_sidememory_version,
        "engine_kind": entry.engine_kind,
        "engine_version": entry.engine_version,
        "artifact_key": entry.artifact_key,
        "vocabulary_fingerprint": entry.vocabulary_fingerprint,
        "schema_digest": entry.schema_digest,
        "extension_digest": entry.extension_digest,
        "snapshot_id": entry.snapshot_id,
        "snapshot_digest": entry.snapshot_digest,
        "source_revision": entry.source_revision,
        "snapshot_expiry_ms": entry.snapshot_expiry_ms,
        "generation_nonce": entry.generation_nonce,
        "operation_id": entry.operation_id,
        "action_digest": entry.action_digest,
        "authorization": entry.authorization,
        "approval": entry.approval,
        "policy_version": entry.policy_version,
        "policy_digest": entry.policy_digest,
        "idempotency_digest": entry.idempotency_digest,
        "execution_outcome": entry.execution_outcome,
        "error_code": entry.error_code,
        "latency": entry.latency,
        "previous_digest": entry.previous_digest,
    });
    Ok(sha256_hex(canonical_json(&value)?.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::{AuditDraft, AuditLog, LatencyBreakdown};
    use crate::error::ErrorCode;

    fn draft(stage: &str) -> AuditDraft {
        AuditDraft {
            timestamp_ms: 10,
            stage: stage.to_owned(),
            principal: "principal".to_owned(),
            tenant: "tenant".to_owned(),
            tool_id: "github.comment_issue@1".to_owned(),
            tool_schema_version: "1".to_owned(),
            vocabulary_fingerprint: "vocabulary".to_owned(),
            schema_digest: "schema".to_owned(),
            extension_digest: "extension".to_owned(),
            engine_kind: "sidememory".to_owned(),
            engine_version: "0.1.0".to_owned(),
            artifact_key: "artifact".to_owned(),
            snapshot_id: "snapshot".to_owned(),
            snapshot_digest: "snapshot-digest".to_owned(),
            source_revision: "revision".to_owned(),
            snapshot_expiry_ms: 20,
            generation_nonce: "nonce".to_owned(),
            operation_id: "operation".to_owned(),
            action_digest: Some("action".to_owned()),
            authorization: "allow_atomic".to_owned(),
            approval: "allow".to_owned(),
            policy_version: "1".to_owned(),
            policy_digest: "policy".to_owned(),
            idempotency_digest: Some("idempotency".to_owned()),
            execution_outcome: "committed".to_owned(),
            error_code: None,
            latency: LatencyBreakdown::zero(),
        }
    }

    #[test]
    fn hash_chain_is_replayable_and_detects_changes() {
        let log = AuditLog::with_limits(4096, 4, 16_384);
        log.append(draft("pre_execution")).expect("first append");
        log.append(draft("executed")).expect("second append");
        let entries = log.page(0, 4).expect("page");
        AuditLog::verify(&entries).expect("valid chain");
        assert_eq!(entries[1].previous_digest, entries[0].digest);
        assert_eq!(
            entries[1].idempotency_digest.as_deref(),
            Some("idempotency")
        );

        let mut altered = entries;
        altered[0].authorization = "deny".to_owned();
        let error = AuditLog::verify(&altered).expect_err("alteration must fail");
        assert_eq!(error.code, ErrorCode::AuditFailed);
    }

    #[test]
    fn pagination_and_total_retention_are_bounded() {
        let log = AuditLog::with_limits(4096, 2, 8192);
        log.append(draft("one")).expect("first append");
        log.append(draft("two")).expect("second append");
        assert_eq!(log.page(1, 1).expect("page")[0].stage, "two");
        let anchored = log.page_with_anchor(1, 1).expect("anchored page");
        AuditLog::verify_page(&anchored).expect("anchored page verifies");
        assert_eq!(anchored.anchor.sequence, 1);
        let error = log.append(draft("three")).expect_err("entry bound");
        assert_eq!(error.code, ErrorCode::AuditFailed);
        assert_eq!(log.retained().expect("retained").0, 2);
    }

    #[test]
    fn entries_do_not_contain_prompt_or_tool_output_fields() {
        let log = AuditLog::with_limits(4096, 1, 4096);
        let entry = log.append(draft("executed")).expect("append");
        let encoded = serde_json::to_string(&entry).expect("serialize");
        assert!(!encoded.contains("prompt"));
        assert!(!encoded.contains("credentials"));
        assert!(!encoded.contains("comment body"));
    }
}
