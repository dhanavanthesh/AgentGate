use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

use agentgate_core::artifacts::{artifact_key, canonicalize_artifacts};
use agentgate_core::cache::ArtifactCache;
use agentgate_core::engine::EngineKind;
use agentgate_core::routing::{
    maskforge_compiler, route_and_compile, RouteRequest, SemanticRequirements,
};
use agentgate_core::{ArtifactKey, ErrorCode, GateError, PreparedVocabulary, VocabularySpec};

const EXTENSIONS: &str = r#"{"version":1,"objects":[]}"#;
const SCHEMA: &str = r#"{"type":"boolean"}"#;

fn artifact() -> Arc<agentgate_core::EngineArtifact> {
    let vocabulary = PreparedVocabulary::new(VocabularySpec::byte_vocabulary().expect("spec"))
        .expect("prepared");
    route_and_compile(
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
    .expect("compiled")
    .artifact
}

#[test]
fn cache_hits_evicts_and_arc_survives() {
    let cache = ArtifactCache::new(1, 4096, 2);
    let first = artifact();
    let retained = cache
        .get_or_build(ArtifactKey::new("one"), 1024, || Ok(Arc::clone(&first)))
        .expect("insert");
    let hit = cache
        .get_or_build(ArtifactKey::new("one"), 1024, || {
            panic!("cache hit must not build")
        })
        .expect("hit");
    assert!(Arc::ptr_eq(&retained, &hit));
    cache
        .get_or_build(ArtifactKey::new("two"), 1024, || Ok(artifact()))
        .expect("eviction insert");
    let mut old_session = retained
        .start_session(None, 0)
        .expect("Arc-held artifact survives");
    assert_eq!(old_session.engine_kind(), EngineKind::MaskForge);
    old_session
        .advance(u32::from(b't'))
        .expect("old session works");
    let stats = cache.stats().expect("stats");
    assert_eq!(stats.entries, 1);
    assert_eq!(stats.hits, 1);
    assert_eq!(stats.evictions, 1);
}

#[test]
fn concurrent_miss_compiles_once() {
    let cache = Arc::new(ArtifactCache::new(4, 1 << 20, 2));
    let barrier = Arc::new(Barrier::new(8));
    let builds = Arc::new(AtomicUsize::new(0));
    let template = artifact();
    let mut threads = Vec::new();
    for _ in 0..8 {
        let cache = Arc::clone(&cache);
        let barrier = Arc::clone(&barrier);
        let builds = Arc::clone(&builds);
        let template = Arc::clone(&template);
        threads.push(thread::spawn(move || {
            barrier.wait();
            cache.get_or_build(ArtifactKey::new("shared"), 1024, || {
                builds.fetch_add(1, Ordering::AcqRel);
                thread::sleep(Duration::from_millis(20));
                Ok(template)
            })
        }));
    }
    for thread in threads {
        thread.join().expect("join").expect("artifact");
    }
    assert_eq!(builds.load(Ordering::Acquire), 1);
    let stats = cache.stats().expect("stats");
    assert_eq!(stats.builds, 1);
    assert_eq!(stats.joined_builds, 7);
}

#[test]
fn failed_build_wakes_waiters_and_can_retry() {
    let cache = Arc::new(ArtifactCache::new(4, 1 << 20, 2));
    let barrier = Arc::new(Barrier::new(4));
    let mut threads = Vec::new();
    for _ in 0..4 {
        let cache = Arc::clone(&cache);
        let barrier = Arc::clone(&barrier);
        threads.push(thread::spawn(move || {
            barrier.wait();
            cache.get_or_build(ArtifactKey::new("failed"), 100, || {
                thread::sleep(Duration::from_millis(20));
                Err(GateError::new(
                    ErrorCode::UnsupportedSchema,
                    "expected failure",
                ))
            })
        }));
    }
    for thread in threads {
        let error = match thread.join().expect("join") {
            Ok(_) => panic!("build must fail"),
            Err(error) => error,
        };
        assert_eq!(error.code, ErrorCode::UnsupportedSchema);
    }
    cache
        .get_or_build(ArtifactKey::new("failed"), 100, || Ok(artifact()))
        .expect("marker was cleared");
}

#[test]
fn every_key_contract_mutation_changes_identity() {
    let material = canonicalize_artifacts(SCHEMA, EXTENSIONS, &[]).expect("canonical material");
    let base = artifact_key(
        EngineKind::MaskForge,
        &material,
        "vocab-a",
        "opts-a",
        "bind-a",
    )
    .expect("key");
    let changed_schema =
        canonicalize_artifacts(r#"{"type":"string"}"#, EXTENSIONS, &[]).expect("schema");
    let changed_extension = canonicalize_artifacts(
        SCHEMA,
        r#"{"version":1,"objects":[{"schemaPath":"$","propertyOrder":[]}]}"#,
        &[],
    )
    .expect("extension");
    for key in [
        artifact_key(
            EngineKind::SideMemory,
            &material,
            "vocab-a",
            "opts-a",
            "bind-a",
        ),
        artifact_key(
            EngineKind::MaskForge,
            &changed_schema,
            "vocab-a",
            "opts-a",
            "bind-a",
        ),
        artifact_key(
            EngineKind::MaskForge,
            &changed_extension,
            "vocab-a",
            "opts-a",
            "bind-a",
        ),
        artifact_key(
            EngineKind::MaskForge,
            &material,
            "vocab-b",
            "opts-a",
            "bind-a",
        ),
        artifact_key(
            EngineKind::MaskForge,
            &material,
            "vocab-a",
            "opts-b",
            "bind-a",
        ),
        artifact_key(
            EngineKind::MaskForge,
            &material,
            "vocab-a",
            "opts-a",
            "bind-b",
        ),
    ] {
        assert_ne!(base, key.expect("mutated key"));
    }
}

#[test]
fn canonical_identity_ignores_json_formatting_but_preserves_provenance() {
    let compact = canonicalize_artifacts(
        r#"{"type":"object","properties":{"value":{"type":"string"}}}"#,
        EXTENSIONS,
        &[("urn:test".to_owned(), r#"{"type":"string"}"#.to_owned())],
    )
    .expect("compact");
    let formatted = canonicalize_artifacts(
        "{ \"properties\": { \"value\": { \"type\": \"string\" } }, \"type\": \"object\" }",
        "{ \"objects\": [], \"version\": 1 }",
        &[("urn:test".to_owned(), "{ \"type\": \"string\" }".to_owned())],
    )
    .expect("formatted");
    let compact_key = artifact_key(EngineKind::MaskForge, &compact, "vocab", "options", "bind")
        .expect("compact key");
    let formatted_key = artifact_key(
        EngineKind::MaskForge,
        &formatted,
        "vocab",
        "options",
        "bind",
    )
    .expect("formatted key");
    assert_eq!(compact_key, formatted_key);
    assert_ne!(
        compact.original_schema_digest,
        formatted.original_schema_digest
    );
    assert_ne!(
        compact.original_extension_digest,
        formatted.original_extension_digest
    );
}

#[test]
fn oversized_artifact_is_used_but_not_retained() {
    let cache = ArtifactCache::new(2, 100, 1);
    cache
        .get_or_build(ArtifactKey::new("large"), 101, || Ok(artifact()))
        .expect("oversized artifact is still returned");
    let stats = cache.stats().expect("stats");
    assert_eq!(stats.entries, 0);
    assert_eq!(stats.oversized_bypasses, 1);
}
