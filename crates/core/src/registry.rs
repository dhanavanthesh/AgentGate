use std::collections::BTreeMap;
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::artifacts::{artifact_key, canonicalize_artifacts};
use crate::cache::{ArtifactCache, CacheStats};
use crate::engine::{EngineArtifact, EngineKind};
use crate::error::{ErrorCode, GateError, GateResult};
use crate::ids::{ArtifactKey, ToolId};
use crate::normalize::OutputLimits;
use crate::policy::RequiredApproval;
use crate::routing::{
    maskforge_compiler, route_and_compile, select_engine, RouteRequest, SemanticRequirements,
};
use crate::vocabulary::{PreparedVocabulary, VocabularySpec};
use crate::workflow::WorkflowTransition;

pub const LIST_TOOL: &str = "github.list_issues";
pub const INSPECT_TOOL: &str = "github.inspect_issue";
pub const COMMENT_TOOL: &str = "github.comment_issue";
pub const MODEL_WIDTH: usize = 257;
pub const EOS_ID: u32 = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Risk {
    Read,
    Write,
}

#[derive(Clone, Debug)]
pub struct TimeoutPolicy {
    pub generation_ms: u64,
    pub execution_ms: u64,
}

impl Default for TimeoutPolicy {
    fn default() -> Self {
        Self {
            generation_ms: 120_000,
            execution_ms: 10_000,
        }
    }
}

pub struct ToolSpec {
    pub id: ToolId,
    pub risk: Risk,
    pub schema: Arc<str>,
    pub extensions: Arc<str>,
    pub resources: Arc<[(String, String)]>,
    pub semantic_requirements: SemanticRequirements,
    pub declared_sets: Arc<[String]>,
    pub workflow_transition: WorkflowTransition,
    pub approval_requirement: RequiredApproval,
    pub timeout_policy: TimeoutPolicy,
    pub output_limits: OutputLimits,
    pub artifact_key: ArtifactKey,
    pub engine_kind: EngineKind,
    pub artifact: Arc<EngineArtifact>,
    pub schema_digest: String,
    pub extension_digest: String,
    pub vocabulary_digest: String,
    pub route_diagnostic: String,
    pub vocabulary: Arc<PreparedVocabulary>,
}

pub struct ToolDefinition<'a> {
    pub id: ToolId,
    pub risk: Risk,
    pub schema: &'a str,
    pub extensions: &'a str,
    pub resources: &'a [(String, String)],
    pub semantic_requirements: SemanticRequirements,
    pub declared_sets: &'a [&'a str],
    pub workflow_transition: WorkflowTransition,
    pub approval_requirement: RequiredApproval,
}

pub struct Registry {
    tools: RwLock<BTreeMap<ToolId, Arc<ToolSpec>>>,
    vocabulary: Arc<PreparedVocabulary>,
    cache: Arc<ArtifactCache>,
    maskforge: maskforge_core::Compiler,
}

impl Registry {
    pub fn github() -> GateResult<Self> {
        let vocabulary = Arc::new(PreparedVocabulary::new(VocabularySpec::byte_vocabulary()?)?);
        let registry = Self {
            tools: RwLock::new(BTreeMap::new()),
            vocabulary,
            cache: Arc::new(ArtifactCache::new(32, 8 * 1024 * 1024, 4)),
            maskforge: maskforge_compiler(8 * 1024 * 1024, 8 * 1024 * 1024),
        };
        registry.register(ToolDefinition {
            id: ToolId::new(LIST_TOOL, "1"),
            risk: Risk::Read,
            schema: include_str!("../../../schemas/github/list_issues.v1.schema.json"),
            extensions: include_str!("../../../schemas/github/list_issues.v1.extensions.json"),
            resources: &[],
            semantic_requirements: SemanticRequirements::default(),
            declared_sets: &[],
            workflow_transition: WorkflowTransition::List,
            approval_requirement: RequiredApproval::NotRequired,
        })?;
        registry.register(ToolDefinition {
            id: ToolId::new(INSPECT_TOOL, "1"),
            risk: Risk::Read,
            schema: include_str!("../../../schemas/github/inspect_issue.v1.schema.json"),
            extensions: include_str!("../../../schemas/github/inspect_issue.v1.extensions.json"),
            resources: &[],
            semantic_requirements: SemanticRequirements::default(),
            declared_sets: &[],
            workflow_transition: WorkflowTransition::Inspect,
            approval_requirement: RequiredApproval::NotRequired,
        })?;
        registry.register(ToolDefinition {
            id: ToolId::new(COMMENT_TOOL, "1"),
            risk: Risk::Write,
            schema: include_str!("../../../schemas/github/comment_issue.v1.schema.json"),
            extensions: include_str!("../../../schemas/github/comment_issue.v1.extensions.json"),
            resources: &[],
            semantic_requirements: SemanticRequirements {
                imported_membership: true,
                ..SemanticRequirements::default()
            },
            declared_sets: &["writable_issue_handles"],
            workflow_transition: WorkflowTransition::Comment,
            approval_requirement: RequiredApproval::Required,
        })?;
        Ok(registry)
    }

    pub fn register(&self, definition: ToolDefinition<'_>) -> GateResult<Arc<ToolSpec>> {
        if definition.id.name().as_str().is_empty() || definition.id.version().as_str().is_empty() {
            return Err(GateError::new(
                ErrorCode::InvalidToolSpec,
                "tool identity is empty",
            ));
        }
        if self.read_tools()?.contains_key(&definition.id) {
            return Err(GateError::new(
                ErrorCode::InvalidToolSpec,
                "duplicate tool id",
            ));
        }
        if definition.semantic_requirements.imported_membership
            && definition.declared_sets.is_empty()
        {
            return Err(GateError::new(
                ErrorCode::InvalidToolSpec,
                "membership route must declare an import set",
            ));
        }
        let material = canonicalize_artifacts(
            definition.schema,
            definition.extensions,
            definition.resources,
        )?;
        let engine_kind = select_engine(
            &material.canonical_schema,
            &material.canonical_extensions,
            definition.semantic_requirements,
        )?;
        let key = artifact_key(
            engine_kind,
            &material,
            self.vocabulary.spec().fingerprint(),
            "default-v1",
            "adaptive-v1",
        )?;
        let accounted_bytes = material
            .canonical_schema
            .len()
            .checked_add(material.canonical_extensions.len())
            .and_then(|bytes| bytes.checked_add(material.canonical_resources.len()))
            .and_then(|bytes| bytes.checked_add(512))
            .ok_or_else(|| GateError::new(ErrorCode::CatalogTooLarge, "artifact size overflow"))?;
        let route_request = RouteRequest {
            schema: definition.schema,
            extensions: definition.extensions,
            resources: definition.resources,
            requirements: definition.semantic_requirements,
            compile_options_identity: "default-v1",
            bind_policy_identity: "adaptive-v1",
        };
        let artifact = self.cache.get_or_build(key.clone(), accounted_bytes, || {
            route_and_compile(&route_request, &self.vocabulary, &self.maskforge)
                .map(|route| route.artifact)
        })?;
        if artifact.engine_kind() != engine_kind {
            return Err(GateError::new(
                ErrorCode::InternalInvariant,
                "artifact cache returned a different engine",
            ));
        }
        let spec = Arc::new(ToolSpec {
            id: definition.id.clone(),
            risk: definition.risk,
            schema: Arc::from(definition.schema),
            extensions: Arc::from(definition.extensions),
            resources: Arc::from(definition.resources),
            semantic_requirements: definition.semantic_requirements,
            declared_sets: definition
                .declared_sets
                .iter()
                .map(|name| (*name).to_owned())
                .collect::<Vec<_>>()
                .into(),
            workflow_transition: definition.workflow_transition,
            approval_requirement: definition.approval_requirement,
            timeout_policy: TimeoutPolicy::default(),
            output_limits: OutputLimits::default(),
            artifact_key: key,
            engine_kind,
            artifact,
            schema_digest: material.original_schema_digest,
            extension_digest: material.original_extension_digest,
            vocabulary_digest: self.vocabulary.spec().fingerprint().to_owned(),
            route_diagnostic: format!(
                "{} compilation and vocabulary binding succeeded",
                engine_kind.as_str()
            ),
            vocabulary: Arc::clone(&self.vocabulary),
        });
        let mut tools = self.write_tools()?;
        if tools.contains_key(&definition.id) {
            return Err(GateError::new(
                ErrorCode::InvalidToolSpec,
                "duplicate tool id",
            ));
        }
        tools.insert(definition.id, Arc::clone(&spec));
        Ok(spec)
    }

    pub fn require_exact(&self, id: &ToolId) -> GateResult<Arc<ToolSpec>> {
        let tools = self.read_tools()?;
        if let Some(spec) = tools.get(id) {
            return Ok(Arc::clone(spec));
        }
        if tools.keys().any(|known| known.name() == id.name()) {
            return Err(GateError::new(
                ErrorCode::ToolVersionMismatch,
                "tool version is not registered",
            ));
        }
        Err(GateError::new(
            ErrorCode::ToolNotFound,
            "tool is not registered",
        ))
    }

    pub fn cache_stats(&self) -> GateResult<CacheStats> {
        self.cache.stats()
    }

    #[must_use]
    pub fn vocabulary(&self) -> &Arc<PreparedVocabulary> {
        &self.vocabulary
    }

    #[must_use]
    pub fn vocabulary_digest(&self) -> &str {
        self.vocabulary.spec().fingerprint()
    }

    pub fn len(&self) -> GateResult<usize> {
        Ok(self.read_tools()?.len())
    }

    pub fn is_empty(&self) -> GateResult<bool> {
        Ok(self.read_tools()?.is_empty())
    }

    fn read_tools(&self) -> GateResult<RwLockReadGuard<'_, BTreeMap<ToolId, Arc<ToolSpec>>>> {
        self.tools
            .read()
            .map_err(|_| GateError::new(ErrorCode::InternalInvariant, "registry lock poisoned"))
    }

    fn write_tools(&self) -> GateResult<RwLockWriteGuard<'_, BTreeMap<ToolId, Arc<ToolSpec>>>> {
        self.tools
            .write()
            .map_err(|_| GateError::new(ErrorCode::InternalInvariant, "registry lock poisoned"))
    }
}
