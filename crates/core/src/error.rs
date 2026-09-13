use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ErrorCode {
    UnsupportedSchema,
    InvalidToolSpec,
    ToolNotFound,
    ToolVersionMismatch,
    CatalogMissing,
    CatalogInvalid,
    CatalogTooLarge,
    CatalogStale,
    SnapshotScopeMismatch,
    VocabMismatch,
    EmptyMask,
    NoFiniteAllowedLogit,
    TokenRejected,
    TokenBudgetExceeded,
    NotAccepting,
    ParseFailed,
    FinalValidationFailed,
    PolicyDenied,
    AuthDenied,
    ApprovalDenied,
    IdempotencyConflict,
    ToolTimeout,
    ToolFailed,
    AuditFailed,
    InternalInvariant,
}

impl ErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnsupportedSchema => "UNSUPPORTED_SCHEMA",
            Self::InvalidToolSpec => "INVALID_TOOL_SPEC",
            Self::ToolNotFound => "TOOL_NOT_FOUND",
            Self::ToolVersionMismatch => "TOOL_VERSION_MISMATCH",
            Self::CatalogMissing => "CATALOG_MISSING",
            Self::CatalogInvalid => "CATALOG_INVALID",
            Self::CatalogTooLarge => "CATALOG_TOO_LARGE",
            Self::CatalogStale => "CATALOG_STALE",
            Self::SnapshotScopeMismatch => "SNAPSHOT_SCOPE_MISMATCH",
            Self::VocabMismatch => "VOCAB_MISMATCH",
            Self::EmptyMask => "EMPTY_MASK",
            Self::NoFiniteAllowedLogit => "NO_FINITE_ALLOWED_LOGIT",
            Self::TokenRejected => "TOKEN_REJECTED",
            Self::TokenBudgetExceeded => "TOKEN_BUDGET_EXCEEDED",
            Self::NotAccepting => "NOT_ACCEPTING",
            Self::ParseFailed => "PARSE_FAILED",
            Self::FinalValidationFailed => "FINAL_VALIDATION_FAILED",
            Self::PolicyDenied => "POLICY_DENIED",
            Self::AuthDenied => "AUTH_DENIED",
            Self::ApprovalDenied => "APPROVAL_DENIED",
            Self::IdempotencyConflict => "IDEMPOTENCY_CONFLICT",
            Self::ToolTimeout => "TOOL_TIMEOUT",
            Self::ToolFailed => "TOOL_FAILED",
            Self::AuditFailed => "AUDIT_FAILED",
            Self::InternalInvariant => "INTERNAL_INVARIANT",
        }
    }
}

#[derive(Clone, Debug, Error)]
#[error("{code}: {message}", code = .code.as_str())]
pub struct GateError {
    pub code: ErrorCode,
    pub message: String,
    pub reconciliation_key: Option<String>,
}

impl GateError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            reconciliation_key: None,
        }
    }

    pub fn indeterminate(message: impl Into<String>, key: String) -> Self {
        Self {
            code: ErrorCode::AuditFailed,
            message: message.into(),
            reconciliation_key: Some(key),
        }
    }

    pub fn safe_context(mut self, key: impl Into<String>) -> Self {
        self.reconciliation_key = Some(key.into());
        self
    }
}

pub type GateResult<T> = Result<T, GateError>;
