use agentgate_core::engine::EngineKind;
use agentgate_core::language_contract::{
    eos_is_allowed, language_contract, token_is_allowed, PropertyOrder, ReferencePolicy,
};
use agentgate_core::routing::{
    maskforge_compiler, route_and_compile, RouteRequest, SemanticRequirements,
};
use agentgate_core::{PreparedVocabulary, VocabularySpec};
use serde_json::Value;

const EXTENSIONS: &str = r#"{"version":1,"objects":[]}"#;
const SCHEMA: &str = r#"{"type":"object","properties":{"name":{"type":"string"},"active":{"type":"boolean"}},"required":["name","active"],"additionalProperties":false}"#;

fn oracle(candidate: &[u8]) -> bool {
    let Ok(Value::Object(object)) = serde_json::from_slice(candidate) else {
        return false;
    };
    object.len() == 2
        && object.get("name").is_some_and(Value::is_string)
        && object.get("active").is_some_and(Value::is_boolean)
}

fn engine_accepts(candidate: &[u8]) -> bool {
    let vocabulary =
        PreparedVocabulary::new(VocabularySpec::byte_vocabulary().expect("byte vocabulary"))
            .expect("prepared vocabulary");
    let route = route_and_compile(
        &RouteRequest {
            schema: SCHEMA,
            extensions: EXTENSIONS,
            resources: &[],
            requirements: SemanticRequirements::default(),
            compile_options_identity: "default-v1",
            bind_policy_identity: "adaptive-v1",
        },
        &vocabulary,
        &maskforge_compiler(1 << 20, 1 << 20),
    )
    .expect("compile schema");
    let mut session = route.artifact.start_session(None, 0).expect("session");
    for byte in candidate {
        if session.advance(u32::from(*byte)).is_err() {
            return false;
        }
    }
    session.is_accepting().unwrap_or(false)
}

#[test]
fn contracts_state_exact_engine_differences() {
    let side = language_contract(EngineKind::SideMemory);
    let mask = language_contract(EngineKind::MaskForge);
    let earley = language_contract(EngineKind::OcEarley);
    assert_eq!(side.property_order, PropertyOrder::ExtensionDefined);
    assert_eq!(side.references, ReferencePolicy::None);
    assert!(side.cross_token_rollback);
    assert!(side.prefix_completion_is_checked);
    assert_eq!(side.limits.max_generated_tokens, 1024);
    assert_eq!(side.profile_version, "sidememory-profile-v1");
    assert_eq!(mask.property_order, PropertyOrder::SchemaDefined);
    assert_eq!(mask.references, ReferencePolicy::ExplicitResourcesOnly);
    assert!(!mask.cross_token_rollback);
    assert!(mask.prefix_completion_is_checked);
    assert_eq!(earley.references, ReferencePolicy::InternalOnly);
    assert!(earley.cross_token_rollback);
    assert_eq!(
        earley.profile_version,
        "oc-earley-recursive-json-profile-v1"
    );
    assert!(token_is_allowed(true));
    assert!(!token_is_allowed(false));
    assert!(eos_is_allowed(true));
    assert!(!eos_is_allowed(false));
}

#[test]
fn independent_oracle_finds_zero_false_accepts() {
    let corpus: &[&[u8]] = &[
        br#"{"name":"Ada","active":true}"#,
        br#"{"active":false,"name":"Lin"}"#,
        br#"{"name":"Ada"}"#,
        br#"{"name":1,"active":true}"#,
        br#"{"name":"Ada","active":true,"extra":0}"#,
        br#"{"name":"\u00e9","active":false}"#,
        br#"{"name":"e\u0301","active":false}"#,
        br#"{"name":"Ada","active":tru"#,
        &[0xff, b'{', b'}'],
    ];
    let mut false_accepts = 0;
    for candidate in corpus {
        let accepted = engine_accepts(candidate);
        if accepted && !oracle(candidate) {
            false_accepts += 1;
        }
        if oracle(candidate) {
            assert!(accepted, "oracle-valid candidate was rejected");
        }
    }
    assert_eq!(false_accepts, 0);
}
