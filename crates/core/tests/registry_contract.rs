use agentgate_core::policy::RequiredApproval;
use agentgate_core::registry::{Registry, Risk, ToolDefinition};
use agentgate_core::routing::SemanticRequirements;
use agentgate_core::workflow::WorkflowTransition;
use agentgate_core::{ErrorCode, ToolId};

const SCHEMA: &str = r#"{"type":"boolean"}"#;
const EXTENSIONS: &str = r#"{"version":1,"objects":[]}"#;

fn definition(id: ToolId, schema: &str) -> ToolDefinition<'_> {
    ToolDefinition {
        id,
        risk: Risk::Read,
        schema,
        extensions: EXTENSIONS,
        resources: &[],
        semantic_requirements: SemanticRequirements::default(),
        declared_sets: &[],
        workflow_transition: WorkflowTransition::None,
        approval_requirement: RequiredApproval::NotRequired,
    }
}

#[test]
fn failed_and_duplicate_registration_never_publish_partial_specs() {
    let registry = Registry::github().expect("registry");
    let initial_len = registry.len().expect("length");
    let failed = registry
        .register(definition(ToolId::new("test.invalid", "1"), "not-json"))
        .err()
        .expect("malformed schema");
    assert_eq!(failed.code, ErrorCode::UnsupportedSchema);
    assert_eq!(registry.len().expect("length"), initial_len);
    assert_eq!(
        registry
            .require_exact(&ToolId::new("test.invalid", "1"))
            .err()
            .expect("not published")
            .code,
        ErrorCode::ToolNotFound
    );

    registry
        .register(definition(ToolId::new("test.valid", "1"), SCHEMA))
        .expect("valid registration");
    let duplicate = registry
        .register(definition(ToolId::new("test.valid", "1"), SCHEMA))
        .err()
        .expect("duplicate");
    assert_eq!(duplicate.code, ErrorCode::InvalidToolSpec);
}

#[test]
fn exact_versions_and_old_arc_specs_remain_stable() {
    let registry = Registry::github().expect("registry");
    let old = registry
        .register(definition(ToolId::new("test.versioned", "1"), SCHEMA))
        .expect("version one");
    assert_eq!(
        registry
            .require_exact(&ToolId::new("test.versioned", "2"))
            .err()
            .expect("missing exact version")
            .code,
        ErrorCode::ToolVersionMismatch
    );
    registry
        .register(definition(
            ToolId::new("test.versioned", "2"),
            r#"{"type":"string"}"#,
        ))
        .expect("version two");
    assert_eq!(old.id, ToolId::new("test.versioned", "1"));
    assert_eq!(old.schema.as_ref(), SCHEMA);
}
