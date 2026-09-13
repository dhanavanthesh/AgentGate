use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use oc_sidememory::ImportedMemory;
use serde_json::json;

use crate::digest::{canonical_json, sha256_hex};
use crate::error::{ErrorCode, GateError, GateResult};
use crate::ids::{
    GenerationNonce, OpaqueHandle, PrincipalId, SnapshotDigest, SnapshotId, SourceRevision,
    TenantId, ToolId,
};
use crate::registry::ToolSpec;
use crate::simulator::{AuthoritativeList, FakeGithub};

#[derive(Clone, Debug)]
pub struct Limits {
    pub max_snapshot_bytes: usize,
    pub max_adapter_bytes: usize,
    pub max_adapter_objects: usize,
    pub max_adapter_array_values: usize,
    pub max_json_depth: usize,
    pub max_sets: usize,
    pub max_values_per_set: usize,
    pub max_string_bytes: usize,
    pub max_ttl_ms: u64,
    pub max_comment_bytes: usize,
    pub max_audit_entry_bytes: usize,
    pub max_audit_entries: usize,
    pub max_audit_bytes: usize,
    pub max_workflow_records: usize,
    pub max_workflow_bytes: usize,
    pub max_idempotency_records: usize,
    pub max_idempotency_bytes: usize,
    pub max_approval_records: usize,
    pub max_concurrent_sessions: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_snapshot_bytes: 64 * 1024,
            max_adapter_bytes: 128 * 1024,
            max_adapter_objects: 1_025,
            max_adapter_array_values: 1_024,
            max_json_depth: 4,
            max_sets: 8,
            max_values_per_set: 1024,
            max_string_bytes: 1024,
            max_ttl_ms: 120_000,
            max_comment_bytes: 256,
            max_audit_entry_bytes: 32 * 1024,
            max_audit_entries: 4096,
            max_audit_bytes: 16 * 1024 * 1024,
            max_workflow_records: 1024,
            max_workflow_bytes: 2 * 1024 * 1024,
            max_idempotency_records: 4096,
            max_idempotency_bytes: 8 * 1024 * 1024,
            max_approval_records: 4096,
            max_concurrent_sessions: 32,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Snapshot {
    snapshot_id: SnapshotId,
    principal: PrincipalId,
    tenant: TenantId,
    tool_id: ToolId,
    source_revision: SourceRevision,
    created_at_ms: u64,
    expires_at_ms: u64,
    generation_nonce: GenerationNonce,
    sets: Arc<BTreeMap<String, Arc<[String]>>>,
    digest: SnapshotDigest,
    serialized_bytes: usize,
}

pub struct SnapshotRequest {
    pub principal: PrincipalId,
    pub tenant: TenantId,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
    pub generation_nonce: GenerationNonce,
}

impl Snapshot {
    pub fn snapshot_id(&self) -> &SnapshotId {
        &self.snapshot_id
    }

    pub fn principal(&self) -> &PrincipalId {
        &self.principal
    }

    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    pub fn tool_id(&self) -> &ToolId {
        &self.tool_id
    }

    pub fn source_revision(&self) -> &SourceRevision {
        &self.source_revision
    }

    pub fn created_at_ms(&self) -> u64 {
        self.created_at_ms
    }

    pub fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    pub fn generation_nonce(&self) -> &GenerationNonce {
        &self.generation_nonce
    }

    pub fn digest(&self) -> &SnapshotDigest {
        &self.digest
    }

    pub fn serialized_bytes(&self) -> usize {
        self.serialized_bytes
    }

    pub fn values(&self, name: &str) -> Option<&[String]> {
        self.sets.get(name).map(AsRef::as_ref)
    }

    pub fn is_fresh(&self, now_ms: u64) -> bool {
        now_ms >= self.created_at_ms && now_ms < self.expires_at_ms
    }

    pub fn to_imports(&self) -> GateResult<Arc<ImportedMemory>> {
        let value = self
            .sets
            .iter()
            .map(|(name, values)| {
                (
                    name.clone(),
                    serde_json::Value::Array(
                        values
                            .iter()
                            .cloned()
                            .map(serde_json::Value::String)
                            .collect(),
                    ),
                )
            })
            .collect::<serde_json::Map<_, _>>();
        let value = serde_json::Value::Object(value);
        let encoded = canonical_json(&value)?;
        ImportedMemory::from_json(
            self.snapshot_id.as_str(),
            self.source_revision.as_str(),
            &encoded,
        )
        .map(Arc::new)
        .map_err(|_| {
            GateError::new(
                ErrorCode::CatalogInvalid,
                "OC-Sidememory rejected snapshot imports",
            )
        })
    }
}

pub fn build_snapshot(
    adapter: &FakeGithub,
    spec: &ToolSpec,
    result: &AuthoritativeList,
    request: SnapshotRequest,
    limits: &Limits,
) -> GateResult<Snapshot> {
    let SnapshotRequest {
        principal,
        tenant,
        created_at_ms,
        expires_at_ms,
        generation_nonce,
    } = request;
    adapter.verify_provenance(result)?;
    let adapter_objects = result.issues.len().checked_add(1).ok_or_else(|| {
        GateError::new(ErrorCode::CatalogTooLarge, "adapter object count overflow")
    })?;
    if result.issues.len() > limits.max_adapter_array_values
        || adapter_objects > limits.max_adapter_objects
        || limits.max_json_depth < 4
    {
        return Err(GateError::new(
            ErrorCode::CatalogTooLarge,
            "adapter result shape exceeds limits",
        ));
    }
    if created_at_ms >= expires_at_ms {
        return Err(GateError::new(
            ErrorCode::CatalogInvalid,
            "snapshot expiry must follow creation",
        ));
    }
    let ttl = expires_at_ms
        .checked_sub(created_at_ms)
        .ok_or_else(|| GateError::new(ErrorCode::CatalogInvalid, "snapshot TTL underflow"))?;
    if ttl > limits.max_ttl_ms {
        return Err(GateError::new(
            ErrorCode::CatalogTooLarge,
            "snapshot TTL exceeds limit",
        ));
    }
    if spec.declared_sets.len() > limits.max_sets
        || spec.declared_sets.len() != 1
        || spec.declared_sets[0] != "writable_issue_handles"
    {
        return Err(GateError::new(
            ErrorCode::InvalidToolSpec,
            "snapshot sets differ from tool declaration",
        ));
    }
    if &tenant != adapter.tenant() {
        return Err(GateError::new(
            ErrorCode::SnapshotScopeMismatch,
            "snapshot tenant differs",
        ));
    }
    let repository_prefix = format!("{}:issue_", adapter.repository().as_str());
    let tenant_prefix = format!("github:{}:", tenant.as_str());
    let mut adapter_bytes = result.source_revision.as_str().len();
    let mut values = BTreeSet::new();
    for issue in &result.issues {
        adapter_bytes = adapter_bytes
            .checked_add(issue.handle.as_str().len())
            .and_then(|total| total.checked_add(issue.title.len()))
            .ok_or_else(|| {
                GateError::new(ErrorCode::CatalogTooLarge, "adapter byte count overflow")
            })?;
        if adapter_bytes > limits.max_adapter_bytes {
            return Err(GateError::new(
                ErrorCode::CatalogTooLarge,
                "adapter result exceeds byte limit",
            ));
        }
        let handle = issue.handle.as_str();
        if handle.len() > limits.max_string_bytes || !handle.starts_with(&tenant_prefix) {
            return Err(GateError::new(
                ErrorCode::CatalogInvalid,
                "malformed or cross-tenant handle",
            ));
        }
        if !handle.starts_with(&repository_prefix) || handle.split(':').count() != 4 {
            return Err(GateError::new(
                ErrorCode::CatalogInvalid,
                "cross-repository or malformed issue handle",
            ));
        }
        if issue.writable {
            values.insert(handle.to_owned());
        }
    }
    if values.len() > limits.max_values_per_set {
        return Err(GateError::new(
            ErrorCode::CatalogTooLarge,
            "snapshot value count exceeds limit",
        ));
    }
    let values: Vec<String> = values.into_iter().collect();
    let id_material = canonical_json(&json!({
        "principal": principal,
        "tenant": tenant,
        "created_at_ms": created_at_ms,
        "generation_nonce": generation_nonce,
    }))?;
    let snapshot_id = SnapshotId::new(format!(
        "snap_{}",
        &sha256_hex(id_material.as_bytes())[..20]
    ));
    let digest_value = json!({
        "snapshot_id": snapshot_id,
        "principal": principal,
        "tenant": tenant,
        "tool_id": spec.id.to_string(),
        "source_revision": result.source_revision,
        "created_at_ms": created_at_ms,
        "expires_at_ms": expires_at_ms,
        "generation_nonce": generation_nonce,
        "sets": {"writable_issue_handles": values},
    });
    let serialized = canonical_json(&digest_value)?;
    if serialized.len() > limits.max_snapshot_bytes {
        return Err(GateError::new(
            ErrorCode::CatalogTooLarge,
            "snapshot exceeds byte limit",
        ));
    }
    let digest = SnapshotDigest::new(sha256_hex(serialized.as_bytes()));
    let set_values = digest_value["sets"]["writable_issue_handles"]
        .as_array()
        .ok_or_else(|| {
            GateError::new(
                ErrorCode::InternalInvariant,
                "snapshot set serialization differs",
            )
        })?
        .iter()
        .map(|value| {
            value.as_str().map(str::to_owned).ok_or_else(|| {
                GateError::new(
                    ErrorCode::InternalInvariant,
                    "snapshot set value type differs",
                )
            })
        })
        .collect::<GateResult<Vec<_>>>()?;
    let mut sets = BTreeMap::new();
    sets.insert("writable_issue_handles".to_owned(), Arc::from(set_values));
    Ok(Snapshot {
        snapshot_id,
        principal,
        tenant,
        tool_id: spec.id.clone(),
        source_revision: result.source_revision.clone(),
        created_at_ms,
        expires_at_ms,
        generation_nonce,
        sets: Arc::new(sets),
        digest,
        serialized_bytes: serialized.len(),
    })
}

pub fn require_handle(value: &str) -> GateResult<OpaqueHandle> {
    if value.split(':').count() != 4 || !value.starts_with("github:") {
        return Err(GateError::new(
            ErrorCode::FinalValidationFailed,
            "issue handle is malformed",
        ));
    }
    Ok(OpaqueHandle::new(value))
}
