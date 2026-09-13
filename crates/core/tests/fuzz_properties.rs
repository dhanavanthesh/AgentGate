use agentgate_core::artifacts::{artifact_key, canonicalize_artifacts};
use agentgate_core::normalize::{parse_and_bound, OutputLimits};
use agentgate_core::routing::{
    maskforge_compiler, route_and_compile, RouteRequest, SemanticRequirements,
};
use agentgate_core::workflow::{WorkflowKey, WorkflowState, WorkflowStore};
use agentgate_core::{
    ConversationId, EngineKind, PreparedVocabulary, PrincipalId, SnapshotDigest, SourceRevision,
    TenantId, VocabularySpec,
};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn cache_key_changes_for_any_vocabulary_fingerprint(
        suffix in "[a-zA-Z0-9]{1,32}"
    ) {
        let material = canonicalize_artifacts(
            r#"{"type":"boolean"}"#,
            r#"{"version":1,"objects":[]}"#,
            &[],
        ).expect("material");
        let base = artifact_key(
            EngineKind::MaskForge,
            &material,
            "vocab-base",
            "options-v1",
            "bind-v1",
        ).expect("base");
        let changed = artifact_key(
            EngineKind::MaskForge,
            &material,
            &format!("vocab-{suffix}"),
            "options-v1",
            "bind-v1",
        ).expect("changed");
        prop_assert_ne!(base, changed);
    }

    #[test]
    fn arbitrary_bytes_never_escape_output_bounds(raw in proptest::collection::vec(any::<u8>(), 0..512)) {
        let limits = OutputLimits {
            max_serialized_bytes: 128,
            max_object_members: 16,
            max_array_values: 16,
            max_depth: 4,
            max_string_bytes: 32,
            max_records: 16,
            max_normalization_ns: 100_000_000,
        };
        let result = parse_and_bound(&raw, &limits);
        if raw.len() > limits.max_serialized_bytes {
            prop_assert!(result.is_err());
        }
        if let Ok(value) = result {
            let encoded = serde_json::to_vec(&value).expect("serialize parsed value");
            prop_assert!(serde_json::from_slice::<serde_json::Value>(&encoded).is_ok());
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn bounded_nonsemantic_schemas_compile_without_route_changes(
        scalar in prop_oneof![Just("boolean"), Just("string"), Just("integer")]
    ) {
        let schema = format!(r#"{{"type":"{scalar}"}}"#);
        let vocabulary = PreparedVocabulary::new(VocabularySpec::byte_vocabulary().expect("vocabulary"))
            .expect("prepared vocabulary");
        let compiled = route_and_compile(
            &RouteRequest {
                schema: &schema,
                extensions: r#"{"version":1,"objects":[]}"#,
                resources: &[],
                requirements: SemanticRequirements::default(),
                compile_options_identity: "default-v1",
                bind_policy_identity: "adaptive-v1",
            },
            &vocabulary,
            &maskforge_compiler(1 << 20, 1 << 20),
        ).expect("bounded schema");
        prop_assert_eq!(compiled.engine_kind, EngineKind::MaskForge);
    }

    #[test]
    fn workflow_keys_never_cross_random_scopes(
        principal_suffix in "[a-z0-9]{1,12}",
        tenant_suffix in "[a-z0-9]{1,12}",
        conversation_suffix in "[a-z0-9]{1,12}",
    ) {
        let store = WorkflowStore::new(4, 4096);
        let key = WorkflowKey {
            principal: PrincipalId::new(format!("principal-{principal_suffix}")),
            tenant: TenantId::new(format!("tenant-{tenant_suffix}")),
            conversation: ConversationId::new(format!("conversation-{conversation_suffix}")),
        };
        store.record_listed(
            key.clone(),
            SnapshotDigest::new("snapshot"),
            SourceRevision::new("revision"),
            100,
        ).expect("record");
        let other = WorkflowKey {
            principal: PrincipalId::new(format!("other-{principal_suffix}")),
            tenant: key.tenant.clone(),
            conversation: key.conversation.clone(),
        };
        prop_assert_eq!(store.get(&other, 1).expect("other state"), WorkflowState::Initial);
        let own_is_listed = matches!(
            store.get(&key, 1).expect("own state"),
            WorkflowState::Listed { .. }
        );
        prop_assert!(own_is_listed);
    }

    #[test]
    fn arbitrary_token_sequences_have_no_maskforge_false_accepts(
        bytes in proptest::collection::vec(0_u8..=127, 0..24)
    ) {
        let vocabulary = PreparedVocabulary::new(VocabularySpec::byte_vocabulary().expect("vocabulary"))
            .expect("prepared vocabulary");
        let compiled = route_and_compile(
            &RouteRequest {
                schema: r#"{"type":"boolean"}"#,
                extensions: r#"{"version":1,"objects":[]}"#,
                resources: &[],
                requirements: SemanticRequirements::default(),
                compile_options_identity: "default-v1",
                bind_policy_identity: "adaptive-v1",
            },
            &vocabulary,
            &maskforge_compiler(1 << 20, 1 << 20),
        ).expect("compiled");
        let mut session = compiled.artifact.start_session(None, 0).expect("session");
        let mut committed = Vec::new();
        for byte in bytes {
            if session.advance(u32::from(byte)).is_err() {
                break;
            }
            committed.push(byte);
        }
        if session.is_accepting().expect("accepting") {
            prop_assert!(serde_json::from_slice::<bool>(&committed).is_ok());
        }
    }
}
