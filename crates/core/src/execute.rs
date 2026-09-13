use crate::deadline::Deadline;
use crate::ids::{
    ActionDigest, IdempotencyKey, OpaqueHandle, OperationId, PrincipalId, SourceRevision, TenantId,
    ToolId,
};
use crate::normalize::OutputLimits;

pub struct AuthorizedExecutionRequest<'a> {
    pub principal: &'a PrincipalId,
    pub tenant: &'a TenantId,
    pub operation_id: &'a OperationId,
    pub tool_id: &'a ToolId,
    pub issue_handle: &'a OpaqueHandle,
    pub body: &'a str,
    pub expected_revision: &'a SourceRevision,
    pub action_digest: &'a ActionDigest,
    pub idempotency_key: &'a IdempotencyKey,
    pub deadline: Deadline,
    pub output_limits: &'a OutputLimits,
}
