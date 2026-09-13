use agentgate_core::registry::{Registry, COMMENT_TOOL, INSPECT_TOOL, LIST_TOOL};
use agentgate_core::runtime::normalized_comment_digest;
use agentgate_core::{EngineKind, ErrorCode, ToolId};

const HANDLE: &str = "github:tenant_acme:repo_R1:issue_I12";

#[test]
fn rust_contract_has_stable_cross_language_values() {
    let registry = Registry::github().expect("registry");
    for (name, expected_engine) in [
        (LIST_TOOL, EngineKind::MaskForge),
        (INSPECT_TOOL, EngineKind::MaskForge),
        (COMMENT_TOOL, EngineKind::SideMemory),
    ] {
        let spec = registry
            .require_exact(&ToolId::new(name, "1"))
            .expect("tool");
        assert_eq!(spec.engine_kind, expected_engine);
        assert_eq!(spec.artifact_key.as_str().len(), 64);
    }
    assert_eq!(
        normalized_comment_digest(HANDLE, "Thanks!")
            .expect("digest")
            .as_str(),
        "7e15b4115d82d7463bca756f262f85605232bd3474732ab0517cae75ed29ef8a"
    );
    assert_eq!(ErrorCode::PolicyDenied.as_str(), "POLICY_DENIED");
    assert_eq!(ErrorCode::ApprovalDenied.as_str(), "APPROVAL_DENIED");
}
