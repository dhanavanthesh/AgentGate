use std::sync::Arc;

use agentgate_core::registry::{ToolSpec, COMMENT_TOOL, LIST_TOOL};
use agentgate_core::session::{GenerationConfig, GuideSession, SamplingMode};
use agentgate_core::{
    ConversationId, ErrorCode, GenerationNonce, ManualClock, PrincipalId, Runtime, TenantId, ToolId,
};

const HANDLE: &str = "github:tenant_acme:repo_R1:issue_I12";

fn comment_parts() -> (
    Arc<ToolSpec>,
    Arc<oc_sidememory::sidememory::ImportedMemory>,
    Vec<u8>,
) {
    let clock = Arc::new(ManualClock::new(1_000, 0));
    let runtime = Runtime::github_with_clock(clock).expect("runtime");
    let snapshot = runtime
        .list_issues(
            PrincipalId::new("user:42"),
            TenantId::new("tenant_acme"),
            30_000,
            GenerationNonce::new("nonce"),
            ConversationId::new("conversation"),
        )
        .expect("snapshot");
    let spec = runtime
        .registry()
        .require_exact(&ToolId::new(COMMENT_TOOL, "1"))
        .expect("spec");
    let imports = snapshot.to_imports().expect("imports");
    (spec, imports, action(HANDLE, "hello"))
}

fn comment_session() -> (GuideSession, Vec<u8>) {
    let (spec, imports, target) = comment_parts();
    let session = GuideSession::new(
        Arc::clone(&spec),
        Some(imports),
        GenerationConfig::exact(&spec),
    )
    .expect("session");
    (session, target)
}

#[test]
fn mask_rejection_rollback_reset_and_eos_are_transactional() {
    let (mut session, target) = comment_session();
    let words = session.engine_mut().mask_word_count();
    let mut before = vec![0; words];
    session.engine_mut().write_mask(&mut before).expect("mask");
    let mut repeated = vec![0; words];
    session
        .engine_mut()
        .write_mask(&mut repeated)
        .expect("mask");
    assert_eq!(before, repeated);

    let error = session
        .engine_mut()
        .advance(u32::from(b'x'))
        .expect_err("illegal byte");
    assert_eq!(error.code, ErrorCode::TokenRejected);
    let mut after = vec![0; words];
    session
        .engine_mut()
        .write_mask(&mut after)
        .expect("mask after rejection");
    assert_eq!(before, after);

    let prefix = b"{\"tool\":";
    for byte in prefix {
        session
            .engine_mut()
            .advance(u32::from(*byte))
            .expect("prefix");
    }
    session.engine_mut().rollback(4).expect("rollback");
    for byte in &prefix[prefix.len() - 4..] {
        session
            .engine_mut()
            .advance(u32::from(*byte))
            .expect("replay prefix");
    }
    assert_eq!(
        session
            .engine_mut()
            .rollback(64)
            .expect_err("past history")
            .code,
        ErrorCode::InternalInvariant
    );
    session.engine_mut().reset().expect("reset");
    let generated = session
        .generate_target(&target)
        .expect("member after reset");
    assert_eq!(generated.bytes, target);
    assert!(session.is_accepting().expect("accepting"));
    session.engine_mut().advance(256).expect("legal EOS");
    assert!(session.engine_mut().is_terminated());
}

#[test]
fn imports_remain_bound_and_nonmember_never_accepts() {
    let (mut session, _) = comment_session();
    let nonmember = action("github:tenant_acme:repo_R1:issue_I99", "hello");
    assert_eq!(
        session
            .generate_target(&nonmember)
            .expect_err("nonmember")
            .code,
        ErrorCode::TokenRejected
    );
    session.engine_mut().reset().expect("reset");
    assert!(session.generate_target(&action(HANDLE, "hello")).is_ok());
}

#[test]
fn decoder_limits_and_vocabulary_identity_fail_closed() {
    let (spec, imports, target) = comment_parts();
    let mut wrong = GenerationConfig::exact(&spec);
    wrong.eos_id = 255;
    assert_eq!(
        GuideSession::new(Arc::clone(&spec), Some(Arc::clone(&imports)), wrong)
            .err()
            .expect("wrong EOS")
            .code,
        ErrorCode::VocabMismatch
    );
    let mut non_finite = GenerationConfig::exact(&spec);
    non_finite.finite_logits = false;
    let mut session = GuideSession::new(Arc::clone(&spec), Some(Arc::clone(&imports)), non_finite)
        .expect("session");
    assert_eq!(
        session
            .generate_target(&target)
            .expect_err("non-finite")
            .code,
        ErrorCode::NoFiniteAllowedLogit
    );
    let mut bounded = GenerationConfig::exact(&spec);
    bounded.max_new_tokens = 1;
    let mut session = GuideSession::new(spec, Some(imports), bounded).expect("session");
    assert_eq!(
        session.generate_target(&target).expect_err("budget").code,
        ErrorCode::TokenBudgetExceeded
    );
}

#[test]
fn maskforge_does_not_advertise_cross_token_rollback() {
    let runtime = Runtime::github().expect("runtime");
    let spec = runtime
        .registry()
        .require_exact(&ToolId::new(LIST_TOOL, "1"))
        .expect("list spec");
    let mut session = GuideSession::new(Arc::clone(&spec), None, GenerationConfig::exact(&spec))
        .expect("session");
    assert_eq!(
        session
            .engine_mut()
            .rollback(1)
            .expect_err("unsupported")
            .code,
        ErrorCode::InvalidToolSpec
    );
}

#[test]
fn seeded_sampling_and_budget_failures_are_explicit() {
    let (spec, imports, target) = comment_parts();
    let mut seeded = GenerationConfig::exact(&spec);
    seeded.sampling = SamplingMode::Seeded(42);
    let mut session = GuideSession::new(spec, Some(imports), seeded).expect("seeded");
    assert_eq!(
        session.generate_target(&target).expect("generated").bytes,
        target
    );
}

fn action(handle: &str, body: &str) -> Vec<u8> {
    format!(
        "{{\"tool\":\"github.comment_issue\",\"issue_handle\":{},\"body\":{}}}",
        serde_json::to_string(handle).expect("handle"),
        serde_json::to_string(body).expect("body")
    )
    .into_bytes()
}
