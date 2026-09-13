use std::collections::BTreeSet;
use std::sync::Arc;

use crate::digest::sha256_hex;
use crate::error::{ErrorCode, GateError, GateResult};
use crate::ids::{OpaqueHandle, PolicyDigest, SourceRevision, ToolId};
use crate::registry::{COMMENT_TOOL, INSPECT_TOOL, LIST_TOOL};
use crate::workflow::{WorkflowKey, WorkflowState, WorkflowStore};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequiredApproval {
    NotRequired,
    Required,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyDecision {
    pub allowed: bool,
    pub reason_code: String,
    pub policy_version: String,
    pub policy_digest: PolicyDigest,
    pub required_approval: RequiredApproval,
}

pub struct PolicyContext<'a> {
    pub workflow: &'a WorkflowKey,
    pub tool_id: &'a ToolId,
    pub issue_handle: Option<&'a OpaqueHandle>,
    pub expected_revision: Option<&'a SourceRevision>,
    pub now_ms: u64,
}

pub trait PolicyEngine: Send + Sync {
    fn exposed_tools(&self, workflow: &WorkflowKey, now_ms: u64) -> GateResult<BTreeSet<ToolId>>;
    fn evaluate(&self, context: &PolicyContext<'_>) -> GateResult<PolicyDecision>;
    fn digest(&self) -> &PolicyDigest;
    fn version(&self) -> &str;
}

pub struct WorkflowPolicy {
    workflows: Arc<WorkflowStore>,
    version: String,
    digest: PolicyDigest,
}

impl WorkflowPolicy {
    #[must_use]
    pub fn new(workflows: Arc<WorkflowStore>) -> Self {
        let version = "github-workflow-v1".to_owned();
        let digest = PolicyDigest::new(sha256_hex(
            b"list->inspect-same-handle-and-revision->comment;commented->same-handle-and-revision-comment",
        ));
        Self {
            workflows,
            version,
            digest,
        }
    }

    #[must_use]
    pub fn workflows(&self) -> &Arc<WorkflowStore> {
        &self.workflows
    }
}

impl PolicyEngine for WorkflowPolicy {
    fn exposed_tools(&self, workflow: &WorkflowKey, now_ms: u64) -> GateResult<BTreeSet<ToolId>> {
        let state = self.workflows.get(workflow, now_ms)?;
        let mut tools = BTreeSet::new();
        tools.insert(ToolId::new(LIST_TOOL, "1"));
        match state {
            WorkflowState::Listed { .. } => {
                tools.insert(ToolId::new(INSPECT_TOOL, "1"));
            }
            WorkflowState::Inspected { .. } | WorkflowState::Commented { .. } => {
                tools.insert(ToolId::new(INSPECT_TOOL, "1"));
                tools.insert(ToolId::new(COMMENT_TOOL, "1"));
            }
            WorkflowState::Initial => {}
        }
        Ok(tools)
    }

    fn evaluate(&self, context: &PolicyContext<'_>) -> GateResult<PolicyDecision> {
        let exposed = self.exposed_tools(context.workflow, context.now_ms)?;
        if !exposed.contains(context.tool_id) {
            return Ok(self.decision(false, "TOOL_NOT_EXPOSED", RequiredApproval::NotRequired));
        }
        if context.tool_id.name().as_str() != COMMENT_TOOL {
            return Ok(self.decision(true, "READ_ALLOWED", RequiredApproval::NotRequired));
        }
        let state = self.workflows.get(context.workflow, context.now_ms)?;
        let (issue_handle, revision) = match state {
            WorkflowState::Inspected {
                issue_handle,
                revision,
                ..
            }
            | WorkflowState::Commented {
                issue_handle,
                revision,
                ..
            } => (issue_handle, revision),
            _ => {
                return Ok(self.decision(false, "INSPECTION_REQUIRED", RequiredApproval::Required));
            }
        };
        let allowed = context.issue_handle == Some(&issue_handle)
            && context.expected_revision == Some(&revision);
        Ok(self.decision(
            allowed,
            if allowed {
                "INSPECTION_MATCH"
            } else {
                "INSPECTION_MISMATCH"
            },
            RequiredApproval::Required,
        ))
    }

    fn digest(&self) -> &PolicyDigest {
        &self.digest
    }

    fn version(&self) -> &str {
        &self.version
    }
}

impl WorkflowPolicy {
    fn decision(
        &self,
        allowed: bool,
        reason: &str,
        required_approval: RequiredApproval,
    ) -> PolicyDecision {
        PolicyDecision {
            allowed,
            reason_code: reason.to_owned(),
            policy_version: self.version.clone(),
            policy_digest: self.digest.clone(),
            required_approval,
        }
    }
}

pub fn require_allowed(decision: &PolicyDecision) -> GateResult<()> {
    if decision.allowed {
        Ok(())
    } else {
        Err(GateError::new(
            ErrorCode::PolicyDenied,
            format!("workflow policy denied action: {}", decision.reason_code),
        ))
    }
}
