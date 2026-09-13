use agentgate_core::engine::EngineKind;
use agentgate_core::routing::{
    maskforge_compiler, route_and_compile, select_engine, RouteRequest, SemanticRequirements,
};
use agentgate_core::{ErrorCode, PreparedVocabulary, VocabularySpec};

const EXTENSIONS: &str = r#"{"version":1,"objects":[]}"#;

fn prepared() -> PreparedVocabulary {
    PreparedVocabulary::new(VocabularySpec::byte_vocabulary().expect("byte vocabulary"))
        .expect("both engine vocabularies")
}

fn route(schema: &str, requirements: SemanticRequirements) -> Result<EngineKind, ErrorCode> {
    route_and_compile(
        &RouteRequest {
            schema,
            extensions: EXTENSIONS,
            resources: &[],
            requirements,
            compile_options_identity: "default-v1",
            bind_policy_identity: "adaptive-v1",
        },
        &prepared(),
        &maskforge_compiler(1 << 20, 1 << 20),
    )
    .map(|compiled| compiled.engine_kind)
    .map_err(|error| error.code)
}

#[test]
fn semantic_requirements_route_only_to_sidememory() {
    assert_eq!(
        select_engine(
            r#"{"type":"array","items":{"type":"string"},"uniqueItems":true}"#,
            EXTENSIONS,
            SemanticRequirements {
                unique_items_required: true,
                ..SemanticRequirements::default()
            },
        )
        .expect("uniqueItems metadata"),
        EngineKind::SideMemory
    );
    assert_eq!(
        select_engine(
            r#"{"type":"array","contains":{"type":"string"},"minContains":1,"maxContains":2}"#,
            EXTENSIONS,
            SemanticRequirements {
                counted_contains_required: true,
                ..SemanticRequirements::default()
            },
        )
        .expect("counted contains metadata"),
        EngineKind::SideMemory
    );
}

#[test]
fn imported_membership_routes_to_sidememory() {
    let schema = r#"{"type":"object","properties":{"value":{"type":"string"}},"required":["value"],"additionalProperties":false}"#;
    let extension = r#"{"version":1,"objects":[{"schemaPath":"$","propertyOrder":["value"],"relations":[{"targetProperty":"value","operator":"memberOf","import":"allowed"}]}]}"#;
    let compiled = route_and_compile(
        &RouteRequest {
            schema,
            extensions: extension,
            resources: &[],
            requirements: SemanticRequirements {
                imported_membership: true,
                ..SemanticRequirements::default()
            },
            compile_options_identity: "default-v1",
            bind_policy_identity: "adaptive-v1",
        },
        &prepared(),
        &maskforge_compiler(1 << 20, 1 << 20),
    )
    .expect("membership route");
    assert_eq!(compiled.engine_kind, EngineKind::SideMemory);
}

#[test]
fn capture_relations_route_to_sidememory_and_cannot_be_hidden() {
    let schema = r#"{"type":"object","properties":{"source":{"type":"string"},"target":{"type":"string"}},"required":["source","target"],"additionalProperties":false}"#;
    for operator in ["equal", "notEqual"] {
        let extension = format!(
            r#"{{"version":1,"objects":[{{"schemaPath":"$","propertyOrder":["source","target"],"captures":[{{"name":"saved","sourceProperty":"source"}}],"relations":[{{"targetProperty":"target","operator":"{operator}","capture":"saved"}}]}}]}}"#
        );
        let compiled = route_and_compile(
            &RouteRequest {
                schema,
                extensions: &extension,
                resources: &[],
                requirements: SemanticRequirements {
                    cross_field_relations: true,
                    ..SemanticRequirements::default()
                },
                compile_options_identity: "default-v1",
                bind_policy_identity: "adaptive-v1",
            },
            &prepared(),
            &maskforge_compiler(1 << 20, 1 << 20),
        )
        .expect("capture relation");
        assert_eq!(compiled.engine_kind, EngineKind::SideMemory);

        let hidden = route_and_compile(
            &RouteRequest {
                schema,
                extensions: &extension,
                resources: &[],
                requirements: SemanticRequirements::default(),
                compile_options_identity: "default-v1",
                bind_policy_identity: "adaptive-v1",
            },
            &prepared(),
            &maskforge_compiler(1 << 20, 1 << 20),
        );
        assert_eq!(
            hidden.err().expect("hidden semantics fail").code,
            ErrorCode::InvalidToolSpec
        );
    }
}

#[test]
fn broad_nonsemantic_schemas_route_to_maskforge() {
    let schemas = [
        r#"{"type":"object","properties":{"x":{"type":"string"}},"required":["x"],"additionalProperties":false}"#,
        r#"{"type":"array","prefixItems":[{"type":"integer"},{"type":"string"}],"items":false}"#,
        r##"{"$defs":{"x":{"type":"string"}},"$ref":"#/$defs/x"}"##,
        r#"{"type":"object","properties":{"a":{"type":"boolean"},"b":{"type":"string"}},"dependentSchemas":{"a":{"required":["b"]}}}"#,
    ];
    for schema in schemas {
        assert_eq!(
            route(schema, SemanticRequirements::default()),
            Ok(EngineKind::MaskForge),
            "{schema}"
        );
    }
}

#[test]
fn declared_recursive_profile_routes_only_to_oc_earley() {
    let schema = r##"{"$defs":{"node":{"type":"array","items":{"anyOf":[{"type":"integer"},{"$ref":"#/$defs/node"}]},"maxItems":4}},"$ref":"#/$defs/node"}"##;
    let compiled = route_and_compile(
        &RouteRequest {
            schema,
            extensions: EXTENSIONS,
            resources: &[],
            requirements: SemanticRequirements {
                recursive_json_schema: true,
                ..SemanticRequirements::default()
            },
            compile_options_identity: "recursive-json-v1",
            bind_policy_identity: "structural-v1",
        },
        &prepared(),
        &maskforge_compiler(1 << 20, 1 << 20),
    )
    .expect("declared recursive route");
    assert_eq!(compiled.engine_kind, EngineKind::OcEarley);

    let mut session = compiled.artifact.start_session(None, 32).expect("session");
    let mut mask = vec![0; session.mask_word_count()];
    for byte in b"[1,[2,3],4]" {
        session.write_mask(&mut mask).expect("mask");
        assert_ne!(
            mask[usize::from(*byte) / 32] & (1 << (usize::from(*byte) % 32)),
            0
        );
        session.advance(u32::from(*byte)).expect("advance");
    }
    assert!(session.is_accepting().expect("accepting"));
    session.advance(256).expect("EOS");
    assert!(session.is_terminated());
}

#[test]
fn recursive_route_is_explicit_and_cannot_mix_with_semantic_imports() {
    let non_recursive = r#"{"type":"array","items":{"type":"integer"}}"#;
    assert_eq!(
        route(
            non_recursive,
            SemanticRequirements {
                recursive_json_schema: true,
                ..SemanticRequirements::default()
            }
        ),
        Err(ErrorCode::InvalidToolSpec)
    );

    let recursive = r##"{"$defs":{"node":{"type":"array","items":{"$ref":"#/$defs/node"}}},"$ref":"#/$defs/node"}"##;
    assert_eq!(
        route(
            recursive,
            SemanticRequirements {
                imported_membership: true,
                recursive_json_schema: true,
                ..SemanticRequirements::default()
            }
        ),
        Err(ErrorCode::InvalidToolSpec)
    );
}

#[test]
fn unsupported_or_malformed_routes_fail_without_fallback() {
    let semantic_prefix_items = SemanticRequirements {
        imported_membership: true,
        ..SemanticRequirements::default()
    };
    assert_eq!(
        route(
            r#"{"type":"array","prefixItems":[{"type":"string"}]}"#,
            semantic_prefix_items,
        ),
        Err(ErrorCode::InvalidToolSpec)
    );
    assert_eq!(
        route("not-json", SemanticRequirements::default()),
        Err(ErrorCode::UnsupportedSchema)
    );

    let error = match route_and_compile(
        &RouteRequest {
            schema: r#"{"$ref":"https://example.invalid/missing.json"}"#,
            extensions: EXTENSIONS,
            resources: &[],
            requirements: SemanticRequirements::default(),
            compile_options_identity: "default-v1",
            bind_policy_identity: "adaptive-v1",
        },
        &prepared(),
        &maskforge_compiler(1 << 20, 1 << 20),
    ) {
        Ok(_) => panic!("missing external resource must fail"),
        Err(error) => error,
    };
    assert_eq!(error.code, ErrorCode::UnsupportedSchema);

    let error = match route_and_compile(
        &RouteRequest {
            schema: r#"{"type":"boolean"}"#,
            extensions: r#"{"version":2,"objects":[]}"#,
            resources: &[],
            requirements: SemanticRequirements::default(),
            compile_options_identity: "default-v1",
            bind_policy_identity: "adaptive-v1",
        },
        &prepared(),
        &maskforge_compiler(1 << 20, 1 << 20),
    ) {
        Ok(_) => panic!("unknown extension version must fail"),
        Err(error) => error,
    };
    assert_eq!(error.code, ErrorCode::InvalidToolSpec);
}

#[test]
fn runtime_rejection_never_changes_selected_engine() {
    let compiled = route_and_compile(
        &RouteRequest {
            schema: r#"{"type":"boolean"}"#,
            extensions: EXTENSIONS,
            resources: &[],
            requirements: SemanticRequirements::default(),
            compile_options_identity: "default-v1",
            bind_policy_identity: "adaptive-v1",
        },
        &prepared(),
        &maskforge_compiler(1 << 20, 1 << 20),
    )
    .expect("MaskForge route");
    let mut session = compiled.artifact.start_session(None, 0).expect("session");
    assert_eq!(session.engine_kind(), EngineKind::MaskForge);
    assert_eq!(
        session
            .advance(u32::from(b'x'))
            .expect_err("illegal token")
            .code,
        ErrorCode::TokenRejected
    );
    assert_eq!(session.engine_kind(), EngineKind::MaskForge);
}
