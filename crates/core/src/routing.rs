use std::sync::Arc;

use maskforge_core::{
    BindPolicy, CompileOptions as MaskForgeOptions, Compiler, SchemaResourceLimits,
};
use oc_earley::{CompileOptions as OcEarleyOptions, CompiledSchema as OcEarleyCompiledSchema};
use oc_sidememory::{compile_schema, CompileOptions as SideMemoryOptions, ExtensionPlanV1};
use serde_json::Value;

use crate::artifacts::{artifact_key, canonicalize_artifacts, ArtifactMaterial};
use crate::engine::{
    EngineArtifact, EngineKind, MaskForgeArtifact, OcEarleyArtifact, SideMemoryArtifact,
};
use crate::error::{ErrorCode, GateError, GateResult};
use crate::ids::ArtifactKey;
use crate::vocabulary::PreparedVocabulary;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SemanticRequirements {
    pub imported_membership: bool,
    pub cross_field_relations: bool,
    pub unique_items_required: bool,
    pub counted_contains_required: bool,
    pub recursive_json_schema: bool,
}

impl SemanticRequirements {
    #[must_use]
    pub const fn requires_side_memory(self) -> bool {
        self.imported_membership
            || self.cross_field_relations
            || self.unique_items_required
            || self.counted_contains_required
    }
}

pub struct RouteRequest<'a> {
    pub schema: &'a str,
    pub extensions: &'a str,
    pub resources: &'a [(String, String)],
    pub requirements: SemanticRequirements,
    pub compile_options_identity: &'a str,
    pub bind_policy_identity: &'a str,
}

pub struct CompiledRoute {
    pub engine_kind: EngineKind,
    pub artifact: Arc<EngineArtifact>,
    pub artifact_key: ArtifactKey,
    pub material: ArtifactMaterial,
    pub diagnostic: String,
    pub accounted_bytes: usize,
}

pub fn route_and_compile(
    request: &RouteRequest<'_>,
    vocabulary: &PreparedVocabulary,
    maskforge: &Compiler,
) -> GateResult<CompiledRoute> {
    let material = canonicalize_artifacts(request.schema, request.extensions, request.resources)?;
    let engine_kind = select_engine(
        &material.canonical_schema,
        &material.canonical_extensions,
        request.requirements,
    )?;
    let key = artifact_key(
        engine_kind,
        &material,
        vocabulary.spec().fingerprint(),
        request.compile_options_identity,
        request.bind_policy_identity,
    )?;
    let artifact = match engine_kind {
        EngineKind::SideMemory => {
            if !request.resources.is_empty() {
                return Err(GateError::new(
                    ErrorCode::UnsupportedSchema,
                    "OC-Sidememory route does not accept external resources",
                ));
            }
            let extension = ExtensionPlanV1::from_json(request.extensions).map_err(|error| {
                GateError::new(
                    ErrorCode::UnsupportedSchema,
                    format!("OC-Sidememory extension compilation failed: {error}"),
                )
            })?;
            let options = SideMemoryOptions {
                extension_plan: Some(extension),
                ..SideMemoryOptions::default()
            };
            let compiled = compile_schema(
                request.schema.as_bytes(),
                vocabulary.side_memory(),
                vocabulary.spec().model_width(),
                &options,
            )
            .map_err(|error| {
                GateError::new(
                    ErrorCode::UnsupportedSchema,
                    format!("OC-Sidememory schema compilation failed: {error}"),
                )
            })?;
            EngineArtifact::SideMemory(Arc::new(SideMemoryArtifact {
                compiled: Arc::new(compiled),
                model_width: vocabulary.spec().model_width(),
                eos_token_id: vocabulary.spec().eos_id(),
            }))
        }
        EngineKind::MaskForge => {
            let program = if request.resources.is_empty() {
                maskforge.compile_json_schema(request.schema)
            } else {
                maskforge.compile_json_schema_with_resources(
                    request.schema,
                    None,
                    request.resources,
                    MaskForgeOptions::default(),
                    SchemaResourceLimits::default(),
                )
            }
            .map_err(|error| {
                GateError::new(
                    ErrorCode::UnsupportedSchema,
                    format!("MaskForge schema compilation failed: {error}"),
                )
            })?;
            let bound = program.bind(vocabulary.maskforge()).map_err(|error| {
                GateError::new(
                    ErrorCode::UnsupportedSchema,
                    format!("MaskForge vocabulary binding failed: {error}"),
                )
            })?;
            EngineArtifact::MaskForge(Arc::new(MaskForgeArtifact { bound }))
        }
        EngineKind::OcEarley => {
            if !request.resources.is_empty() {
                return Err(GateError::new(
                    ErrorCode::UnsupportedSchema,
                    "OC-Earley recursive route accepts internal references only",
                ));
            }
            let compiled = OcEarleyCompiledSchema::compile(
                request.schema.as_bytes(),
                vocabulary.oc_earley(),
                &OcEarleyOptions::default(),
            )
            .map_err(|error| {
                GateError::new(
                    ErrorCode::UnsupportedSchema,
                    format!("OC-Earley schema compilation failed: {error}"),
                )
            })?;
            EngineArtifact::OcEarley(Arc::new(OcEarleyArtifact {
                compiled: Arc::new(compiled),
                model_width: vocabulary.spec().model_width(),
                eos_token_id: vocabulary.spec().eos_id(),
            }))
        }
    };
    let accounted_bytes = material
        .canonical_schema
        .len()
        .checked_add(material.canonical_extensions.len())
        .and_then(|bytes| bytes.checked_add(material.canonical_resources.len()))
        .and_then(|bytes| bytes.checked_add(512))
        .ok_or_else(|| GateError::new(ErrorCode::CatalogTooLarge, "artifact size overflow"))?;
    Ok(CompiledRoute {
        engine_kind,
        artifact: Arc::new(artifact),
        artifact_key: key,
        material,
        diagnostic: format!(
            "{} compilation and vocabulary binding succeeded",
            engine_kind.as_str()
        ),
        accounted_bytes,
    })
}

pub fn select_engine(
    schema: &str,
    extensions: &str,
    requirements: SemanticRequirements,
) -> GateResult<EngineKind> {
    validate_semantic_metadata(schema, extensions, requirements)?;
    if requirements.requires_side_memory() && requirements.recursive_json_schema {
        return Err(GateError::new(
            ErrorCode::InvalidToolSpec,
            "one action cannot request semantic imports and recursive routing",
        ));
    }
    Ok(if requirements.requires_side_memory() {
        EngineKind::SideMemory
    } else if requirements.recursive_json_schema {
        EngineKind::OcEarley
    } else {
        EngineKind::MaskForge
    })
}

fn validate_semantic_metadata(
    schema: &str,
    extensions: &str,
    requirements: SemanticRequirements,
) -> GateResult<()> {
    let document: Value = serde_json::from_str(extensions).map_err(|_| {
        GateError::new(
            ErrorCode::InvalidToolSpec,
            "extension document is not valid JSON",
        )
    })?;
    let objects = document
        .get("objects")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            GateError::new(ErrorCode::InvalidToolSpec, "extension objects are missing")
        })?;
    let mut imported_membership = false;
    let mut cross_field_relations = false;
    for object in objects {
        let relations = object
            .get("relations")
            .and_then(Value::as_array)
            .map_or(&[][..], Vec::as_slice);
        for relation in relations {
            let operator = relation
                .get("operator")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    GateError::new(ErrorCode::InvalidToolSpec, "relation operator is missing")
                })?;
            match operator {
                "memberOf" | "notMemberOf" => imported_membership = true,
                "equal" | "notEqual" => cross_field_relations = true,
                _ => {
                    return Err(GateError::new(
                        ErrorCode::InvalidToolSpec,
                        "relation operator is unknown",
                    ));
                }
            }
        }
    }
    let schema: Value = serde_json::from_str(schema)
        .map_err(|_| GateError::new(ErrorCode::UnsupportedSchema, "schema is not valid JSON"))?;
    let unique_items =
        contains_keyword(&schema, "uniqueItems", |value| value == &Value::Bool(true));
    let contains = contains_keyword(&schema, "contains", |_| true);
    let contains_count = contains
        && (contains_keyword(&schema, "minContains", |_| true)
            || contains_keyword(&schema, "maxContains", |_| true));
    let has_internal_reference = contains_keyword(&schema, "$ref", |value| {
        value
            .as_str()
            .is_some_and(|reference| reference.starts_with('#'))
    });
    if requirements.recursive_json_schema && !has_internal_reference {
        return Err(GateError::new(
            ErrorCode::InvalidToolSpec,
            "recursive routing requires an internal schema reference",
        ));
    }
    if imported_membership != requirements.imported_membership
        || cross_field_relations != requirements.cross_field_relations
        || unique_items != requirements.unique_items_required
        || contains_count != requirements.counted_contains_required
    {
        return Err(GateError::new(
            ErrorCode::InvalidToolSpec,
            "schema, extensions, and semantic requirements disagree",
        ));
    }
    Ok(())
}

fn contains_keyword(
    value: &Value,
    keyword: &str,
    predicate: impl Copy + Fn(&Value) -> bool,
) -> bool {
    match value {
        Value::Object(object) => {
            object.get(keyword).is_some_and(predicate)
                || object
                    .values()
                    .any(|child| contains_keyword(child, keyword, predicate))
        }
        Value::Array(values) => values
            .iter()
            .any(|child| contains_keyword(child, keyword, predicate)),
        _ => false,
    }
}

pub fn maskforge_compiler(executable_bytes: usize, trie_bytes: usize) -> Compiler {
    Compiler::new(
        maskforge_core::CompilerOptions::default()
            .with_executable_cache_bytes(executable_bytes)
            .with_trie_cache_bytes(trie_bytes)
            .with_bind_policy(BindPolicy::Adaptive),
    )
}
