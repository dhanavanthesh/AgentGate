use serde_json::Value;

use crate::digest::{canonical_json, sha256_hex};
use crate::engine::EngineKind;
use crate::error::{ErrorCode, GateError, GateResult};
use crate::ids::ArtifactKey;

pub const KEY_FORMAT_VERSION: &str = "agentgate-artifact-v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactMaterial {
    pub canonical_schema: String,
    pub canonical_extensions: String,
    pub canonical_resources: String,
    pub original_schema_digest: String,
    pub original_extension_digest: String,
}

pub fn canonicalize_artifacts(
    schema: &str,
    extensions: &str,
    resources: &[(String, String)],
) -> GateResult<ArtifactMaterial> {
    let schema_value: Value = serde_json::from_str(schema)
        .map_err(|_| GateError::new(ErrorCode::UnsupportedSchema, "schema is not valid JSON"))?;
    let extension_value: Value = serde_json::from_str(extensions).map_err(|_| {
        GateError::new(
            ErrorCode::InvalidToolSpec,
            "extension document is not valid JSON",
        )
    })?;
    let version = extension_value
        .get("version")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            GateError::new(ErrorCode::InvalidToolSpec, "extension version is missing")
        })?;
    if version != 1 {
        return Err(GateError::new(
            ErrorCode::InvalidToolSpec,
            "unknown extension document version",
        ));
    }
    let mut normalized_resources = Vec::with_capacity(resources.len());
    for (uri, document) in resources {
        let value: Value = serde_json::from_str(document).map_err(|_| {
            GateError::new(
                ErrorCode::UnsupportedSchema,
                "external resource is not valid JSON",
            )
        })?;
        normalized_resources.push((uri.clone(), canonical_json(&value)?));
    }
    normalized_resources.sort_unstable();
    let canonical_resources =
        canonical_json(&serde_json::to_value(&normalized_resources).map_err(|_| {
            GateError::new(
                ErrorCode::InternalInvariant,
                "resource serialization failed",
            )
        })?)?;
    Ok(ArtifactMaterial {
        canonical_schema: canonical_json(&schema_value)?,
        canonical_extensions: canonical_json(&extension_value)?,
        canonical_resources,
        original_schema_digest: sha256_hex(schema.as_bytes()),
        original_extension_digest: sha256_hex(extensions.as_bytes()),
    })
}

pub fn artifact_key(
    engine: EngineKind,
    material: &ArtifactMaterial,
    vocabulary_fingerprint: &str,
    compile_options: &str,
    bind_policy: &str,
) -> GateResult<ArtifactKey> {
    let mut bytes = Vec::new();
    for field in [
        KEY_FORMAT_VERSION,
        engine.as_str(),
        engine.provenance(),
        &material.canonical_schema,
        &material.canonical_extensions,
        &material.canonical_resources,
        vocabulary_fingerprint,
        compile_options,
        bind_policy,
    ] {
        let len = u64::try_from(field.len()).map_err(|_| {
            GateError::new(ErrorCode::InvalidToolSpec, "artifact key field overflow")
        })?;
        bytes.extend_from_slice(&len.to_le_bytes());
        bytes.extend_from_slice(field.as_bytes());
    }
    Ok(ArtifactKey::new(sha256_hex(&bytes)))
}
