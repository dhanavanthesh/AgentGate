use agentgate_core::{
    ApprovalSemantics, ApprovalToken as CoreApprovalToken, CommentApprovalRequest, ConversationId,
    GenerationNonce, OperationId, PrincipalId, Runtime as CoreRuntime, Snapshot as CoreSnapshot,
    TenantId, ToolId, WriteRequest,
};
use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::PyDict;

create_exception!(_native, AgentGateError, PyException);
create_exception!(_native, UnsupportedSchemaError, AgentGateError);
create_exception!(_native, InvalidToolSpecError, AgentGateError);
create_exception!(_native, ToolNotFoundError, AgentGateError);
create_exception!(_native, ToolVersionMismatchError, AgentGateError);
create_exception!(_native, CatalogMissingError, AgentGateError);
create_exception!(_native, CatalogInvalidError, AgentGateError);
create_exception!(_native, CatalogTooLargeError, AgentGateError);
create_exception!(_native, CatalogStaleError, AgentGateError);
create_exception!(_native, SnapshotScopeMismatchError, AgentGateError);
create_exception!(_native, VocabMismatchError, AgentGateError);
create_exception!(_native, EmptyMaskError, AgentGateError);
create_exception!(_native, NoFiniteAllowedLogitError, AgentGateError);
create_exception!(_native, TokenRejectedError, AgentGateError);
create_exception!(_native, TokenBudgetExceededError, AgentGateError);
create_exception!(_native, NotAcceptingError, AgentGateError);
create_exception!(_native, ParseFailedError, AgentGateError);
create_exception!(_native, FinalValidationFailedError, AgentGateError);
create_exception!(_native, PolicyDeniedError, AgentGateError);
create_exception!(_native, AuthDeniedError, AgentGateError);
create_exception!(_native, ApprovalDeniedError, AgentGateError);
create_exception!(_native, IdempotencyConflictError, AgentGateError);
create_exception!(_native, ToolTimeoutError, AgentGateError);
create_exception!(_native, ToolFailedError, AgentGateError);
create_exception!(_native, AuditFailedError, AgentGateError);
create_exception!(_native, InternalInvariantError, AgentGateError);

#[pyclass(name = "Snapshot", frozen)]
struct PySnapshot {
    inner: CoreSnapshot,
}

#[pymethods]
impl PySnapshot {
    #[getter]
    fn snapshot_id(&self) -> &str {
        self.inner.snapshot_id().as_str()
    }

    #[getter]
    fn digest(&self) -> &str {
        self.inner.digest().as_str()
    }

    #[getter]
    fn source_revision(&self) -> &str {
        self.inner.source_revision().as_str()
    }

    #[getter]
    fn expires_at_ms(&self) -> u64 {
        self.inner.expires_at_ms()
    }

    #[getter]
    fn writable_issue_handles(&self) -> Vec<String> {
        self.inner
            .values("writable_issue_handles")
            .unwrap_or(&[])
            .to_vec()
    }
}

#[pyclass(name = "ApprovalToken", frozen)]
struct PyApprovalToken {
    inner: CoreApprovalToken,
}

#[pymethods]
impl PyApprovalToken {
    #[getter]
    fn approval_id(&self) -> &str {
        self.inner.approval_id().as_str()
    }

    #[getter]
    fn expires_at_ms(&self) -> u64 {
        self.inner.expires_at_ms()
    }
}

#[pyclass(name = "Runtime")]
struct PyRuntime {
    inner: CoreRuntime,
}

#[pymethods]
impl PyRuntime {
    #[new]
    fn new() -> PyResult<Self> {
        CoreRuntime::github()
            .map(|inner| Self { inner })
            .map_err(to_py_error)
    }

    #[pyo3(signature = (principal="user:42", tenant="tenant_acme", ttl_ms=60000, nonce="generation-1", conversation_id="conversation-1"))]
    fn list_issues(
        &self,
        principal: &str,
        tenant: &str,
        ttl_ms: u64,
        nonce: &str,
        conversation_id: &str,
    ) -> PyResult<PySnapshot> {
        self.inner
            .list_issues(
                PrincipalId::new(principal),
                TenantId::new(tenant),
                ttl_ms,
                GenerationNonce::new(nonce),
                ConversationId::new(conversation_id),
            )
            .map(|inner| PySnapshot { inner })
            .map_err(to_py_error)
    }

    #[pyo3(signature = (snapshot, issue_handle, principal="user:42", tenant="tenant_acme", conversation_id="conversation-1"))]
    fn inspect_issue<'py>(
        &self,
        py: Python<'py>,
        snapshot: &PySnapshot,
        issue_handle: &str,
        principal: &str,
        tenant: &str,
        conversation_id: &str,
    ) -> PyResult<Bound<'py, PyDict>> {
        let receipt = self
            .inner
            .inspect_issue(
                PrincipalId::new(principal),
                TenantId::new(tenant),
                &snapshot.inner,
                issue_handle,
                ConversationId::new(conversation_id),
            )
            .map_err(to_py_error)?;
        let result = PyDict::new(py);
        result.set_item("issue_handle", receipt.issue_handle)?;
        result.set_item("title", receipt.title)?;
        result.set_item("source_revision", receipt.source_revision)?;
        result.set_item("inspection_digest", receipt.inspection_digest)?;
        Ok(result)
    }

    #[pyo3(signature = (snapshot, issue_handle, body, operation_id="operation-1", principal="user:42", tenant="tenant_acme", conversation_id="conversation-1", ttl_ms=30000))]
    #[allow(clippy::too_many_arguments)]
    fn approve_comment(
        &self,
        snapshot: &PySnapshot,
        issue_handle: &str,
        body: &str,
        operation_id: &str,
        principal: &str,
        tenant: &str,
        conversation_id: &str,
        ttl_ms: u64,
    ) -> PyResult<PyApprovalToken> {
        self.inner
            .approval_for_comment(CommentApprovalRequest {
                principal: &PrincipalId::new(principal),
                tenant: &TenantId::new(tenant),
                snapshot: &snapshot.inner,
                issue_handle,
                body,
                operation_id: &OperationId::new(operation_id),
                conversation_id: &ConversationId::new(conversation_id),
                ttl_ms,
                semantics: ApprovalSemantics::OneTime,
            })
            .map(|inner| PyApprovalToken { inner })
            .map_err(to_py_error)
    }

    #[pyo3(signature = (snapshot, issue_handle, body, approval, operation_id="operation-1", principal="user:42", tenant="tenant_acme", conversation_id="conversation-1"))]
    #[allow(clippy::too_many_arguments)]
    fn comment_issue<'py>(
        &self,
        py: Python<'py>,
        snapshot: &PySnapshot,
        issue_handle: &str,
        body: &str,
        approval: &PyApprovalToken,
        operation_id: &str,
        principal: &str,
        tenant: &str,
        conversation_id: &str,
    ) -> PyResult<Bound<'py, PyDict>> {
        let action = format!(
            "{{\"tool\":\"github.comment_issue\",\"issue_handle\":{},\"body\":{}}}",
            serde_json::to_string(issue_handle)
                .map_err(|_| InternalInvariantError::new_err("INTERNAL_INVARIANT"))?,
            serde_json::to_string(body)
                .map_err(|_| InternalInvariantError::new_err("INTERNAL_INVARIANT"))?,
        );
        let receipt = self
            .inner
            .run_write(WriteRequest {
                principal: PrincipalId::new(principal),
                tenant: TenantId::new(tenant),
                action_json: action.as_bytes(),
                snapshot: &snapshot.inner,
                generation_nonce: snapshot.inner.generation_nonce(),
                operation_id: OperationId::new(operation_id),
                conversation_id: ConversationId::new(conversation_id),
                approval: &approval.inner,
            })
            .map_err(to_py_error)?;
        let result = PyDict::new(py);
        result.set_item("operation_id", receipt.operation_id.as_str())?;
        result.set_item("idempotency_key", receipt.idempotency_key.as_str())?;
        result.set_item("receipt_digest", receipt.receipt_digest.as_str())?;
        result.set_item("comment_count", receipt.comment_count)?;
        result.set_item("replayed", receipt.replayed)?;
        Ok(result)
    }

    #[pyo3(signature = (principal="user:42", tenant="tenant_acme", conversation_id="conversation-1"))]
    fn exposed_tools(
        &self,
        principal: &str,
        tenant: &str,
        conversation_id: &str,
    ) -> PyResult<Vec<String>> {
        self.inner
            .exposed_tools(
                PrincipalId::new(principal),
                TenantId::new(tenant),
                ConversationId::new(conversation_id),
            )
            .map(|tools| tools.into_iter().map(|tool| tool.to_string()).collect())
            .map_err(to_py_error)
    }

    fn engine_for_tool(&self, tool_name: &str, version: &str) -> PyResult<&'static str> {
        self.inner
            .registry()
            .require_exact(&ToolId::new(tool_name, version))
            .map(|spec| spec.engine_kind.as_str())
            .map_err(to_py_error)
    }

    fn artifact_key_for_tool(&self, tool_name: &str, version: &str) -> PyResult<String> {
        self.inner
            .registry()
            .require_exact(&ToolId::new(tool_name, version))
            .map(|spec| spec.artifact_key.to_string())
            .map_err(to_py_error)
    }

    fn comment_action_digest(&self, issue_handle: &str, body: &str) -> PyResult<String> {
        agentgate_core::runtime::normalized_comment_digest(issue_handle, body)
            .map(|digest| digest.to_string())
            .map_err(to_py_error)
    }

    fn execution_counts(&self) -> PyResult<(u64, u64)> {
        self.inner.adapter().counts().map_err(to_py_error)
    }

    #[pyo3(signature = (offset=0, limit=100))]
    fn audit_json(&self, offset: usize, limit: usize) -> PyResult<String> {
        let entries = self
            .inner
            .audit()
            .page(offset, limit)
            .map_err(to_py_error)?;
        serde_json::to_string(&entries).map_err(|_| AuditFailedError::new_err("AUDIT_FAILED"))
    }
}

fn to_py_error(error: agentgate_core::GateError) -> PyErr {
    use agentgate_core::ErrorCode;

    let message = format!("{}: {}", error.code.as_str(), error.message);
    match error.code {
        ErrorCode::UnsupportedSchema => UnsupportedSchemaError::new_err(message),
        ErrorCode::InvalidToolSpec => InvalidToolSpecError::new_err(message),
        ErrorCode::ToolNotFound => ToolNotFoundError::new_err(message),
        ErrorCode::ToolVersionMismatch => ToolVersionMismatchError::new_err(message),
        ErrorCode::CatalogMissing => CatalogMissingError::new_err(message),
        ErrorCode::CatalogInvalid => CatalogInvalidError::new_err(message),
        ErrorCode::CatalogTooLarge => CatalogTooLargeError::new_err(message),
        ErrorCode::CatalogStale => CatalogStaleError::new_err(message),
        ErrorCode::SnapshotScopeMismatch => SnapshotScopeMismatchError::new_err(message),
        ErrorCode::VocabMismatch => VocabMismatchError::new_err(message),
        ErrorCode::EmptyMask => EmptyMaskError::new_err(message),
        ErrorCode::NoFiniteAllowedLogit => NoFiniteAllowedLogitError::new_err(message),
        ErrorCode::TokenRejected => TokenRejectedError::new_err(message),
        ErrorCode::TokenBudgetExceeded => TokenBudgetExceededError::new_err(message),
        ErrorCode::NotAccepting => NotAcceptingError::new_err(message),
        ErrorCode::ParseFailed => ParseFailedError::new_err(message),
        ErrorCode::FinalValidationFailed => FinalValidationFailedError::new_err(message),
        ErrorCode::PolicyDenied => PolicyDeniedError::new_err(message),
        ErrorCode::AuthDenied => AuthDeniedError::new_err(message),
        ErrorCode::ApprovalDenied => ApprovalDeniedError::new_err(message),
        ErrorCode::IdempotencyConflict => IdempotencyConflictError::new_err(message),
        ErrorCode::ToolTimeout => ToolTimeoutError::new_err(message),
        ErrorCode::ToolFailed => ToolFailedError::new_err(message),
        ErrorCode::AuditFailed => AuditFailedError::new_err(message),
        ErrorCode::InternalInvariant => InternalInvariantError::new_err(message),
        _ => AgentGateError::new_err(message),
    }
}

#[pymodule(name = "_native", gil_used = false)]
fn native_module(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add("__version__", env!("CARGO_PKG_VERSION"))?;
    module.add("AgentGateError", module.py().get_type::<AgentGateError>())?;
    module.add(
        "UnsupportedSchemaError",
        module.py().get_type::<UnsupportedSchemaError>(),
    )?;
    module.add(
        "InvalidToolSpecError",
        module.py().get_type::<InvalidToolSpecError>(),
    )?;
    module.add(
        "ToolNotFoundError",
        module.py().get_type::<ToolNotFoundError>(),
    )?;
    module.add(
        "ToolVersionMismatchError",
        module.py().get_type::<ToolVersionMismatchError>(),
    )?;
    module.add(
        "CatalogMissingError",
        module.py().get_type::<CatalogMissingError>(),
    )?;
    module.add(
        "CatalogInvalidError",
        module.py().get_type::<CatalogInvalidError>(),
    )?;
    module.add(
        "CatalogTooLargeError",
        module.py().get_type::<CatalogTooLargeError>(),
    )?;
    module.add(
        "CatalogStaleError",
        module.py().get_type::<CatalogStaleError>(),
    )?;
    module.add(
        "SnapshotScopeMismatchError",
        module.py().get_type::<SnapshotScopeMismatchError>(),
    )?;
    module.add(
        "VocabMismatchError",
        module.py().get_type::<VocabMismatchError>(),
    )?;
    module.add("EmptyMaskError", module.py().get_type::<EmptyMaskError>())?;
    module.add(
        "NoFiniteAllowedLogitError",
        module.py().get_type::<NoFiniteAllowedLogitError>(),
    )?;
    module.add(
        "TokenRejectedError",
        module.py().get_type::<TokenRejectedError>(),
    )?;
    module.add(
        "TokenBudgetExceededError",
        module.py().get_type::<TokenBudgetExceededError>(),
    )?;
    module.add(
        "NotAcceptingError",
        module.py().get_type::<NotAcceptingError>(),
    )?;
    module.add(
        "ParseFailedError",
        module.py().get_type::<ParseFailedError>(),
    )?;
    module.add(
        "FinalValidationFailedError",
        module.py().get_type::<FinalValidationFailedError>(),
    )?;
    module.add(
        "PolicyDeniedError",
        module.py().get_type::<PolicyDeniedError>(),
    )?;
    module.add("AuthDeniedError", module.py().get_type::<AuthDeniedError>())?;
    module.add(
        "ApprovalDeniedError",
        module.py().get_type::<ApprovalDeniedError>(),
    )?;
    module.add(
        "IdempotencyConflictError",
        module.py().get_type::<IdempotencyConflictError>(),
    )?;
    module.add(
        "ToolTimeoutError",
        module.py().get_type::<ToolTimeoutError>(),
    )?;
    module.add("ToolFailedError", module.py().get_type::<ToolFailedError>())?;
    module.add(
        "AuditFailedError",
        module.py().get_type::<AuditFailedError>(),
    )?;
    module.add(
        "InternalInvariantError",
        module.py().get_type::<InternalInvariantError>(),
    )?;
    module.add_class::<PySnapshot>()?;
    module.add_class::<PyApprovalToken>()?;
    module.add_class::<PyRuntime>()?;
    Ok(())
}
