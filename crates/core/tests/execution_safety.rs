use std::sync::{Arc, Barrier};
use std::thread;

use agentgate_core::simulator::{AdapterFault, TransactionHook};
use agentgate_core::{
    ApprovalSemantics, Clock, CommentApprovalRequest, ConversationId, Deadline, ErrorCode,
    GenerationNonce, ManualClock, OpaqueHandle, OperationId, PrincipalId, Runtime, SourceRevision,
    TenantId, WriteRequest,
};

const HANDLE: &str = "github:tenant_acme:repo_R1:issue_I12";

struct Fixture {
    runtime: Runtime,
    clock: Arc<ManualClock>,
    principal: PrincipalId,
    tenant: TenantId,
    conversation: ConversationId,
    nonce: GenerationNonce,
    snapshot: agentgate_core::Snapshot,
}

impl Fixture {
    fn new(snapshot_ttl_ms: u64) -> Self {
        let clock = Arc::new(ManualClock::new(10_000, 0));
        let runtime = Runtime::github_with_clock(clock.clone()).expect("runtime");
        let principal = PrincipalId::new("user:42");
        let tenant = TenantId::new("tenant_acme");
        let conversation = ConversationId::new("conversation:a");
        let nonce = GenerationNonce::new("nonce:a");
        let snapshot = runtime
            .list_issues(
                principal.clone(),
                tenant.clone(),
                snapshot_ttl_ms,
                nonce.clone(),
                conversation.clone(),
            )
            .expect("list");
        runtime
            .inspect_issue(
                principal.clone(),
                tenant.clone(),
                &snapshot,
                HANDLE,
                conversation.clone(),
            )
            .expect("inspect");
        Self {
            runtime,
            clock,
            principal,
            tenant,
            conversation,
            nonce,
            snapshot,
        }
    }

    fn action(body: &str) -> Vec<u8> {
        format!(
            "{{\"tool\":\"github.comment_issue\",\"issue_handle\":\"{HANDLE}\",\"body\":{}}}",
            serde_json::to_string(body).expect("body JSON")
        )
        .into_bytes()
    }

    fn approve(
        &self,
        operation: &OperationId,
        body: &str,
        ttl_ms: u64,
        semantics: ApprovalSemantics,
    ) -> agentgate_core::ApprovalToken {
        self.runtime
            .approval_for_comment(CommentApprovalRequest {
                principal: &self.principal,
                tenant: &self.tenant,
                snapshot: &self.snapshot,
                issue_handle: HANDLE,
                body,
                operation_id: operation,
                conversation_id: &self.conversation,
                ttl_ms,
                semantics,
            })
            .expect("approval")
    }

    fn run(
        &self,
        operation: OperationId,
        action: &[u8],
        approval: &agentgate_core::ApprovalToken,
    ) -> agentgate_core::GateResult<agentgate_core::ExecutionReceipt> {
        self.runtime.run_write(WriteRequest {
            principal: self.principal.clone(),
            tenant: self.tenant.clone(),
            action_json: action,
            snapshot: &self.snapshot,
            generation_nonce: &self.nonce,
            operation_id: operation,
            conversation_id: self.conversation.clone(),
            approval,
        })
    }
}

#[test]
fn exact_retry_replays_without_a_second_side_effect() {
    let fixture = Fixture::new(30_000);
    let operation = OperationId::new("operation:retry");
    let action = Fixture::action("hello");
    let approval = fixture.approve(&operation, "hello", 10_000, ApprovalSemantics::OneTime);
    let first = fixture
        .run(operation.clone(), &action, &approval)
        .expect("first write");
    let replay = fixture.run(operation, &action, &approval).expect("replay");
    assert!(!first.replayed);
    assert!(replay.replayed);
    assert_eq!(first.receipt_digest, replay.receipt_digest);
    assert_eq!(fixture.runtime.adapter().counts().expect("counts"), (1, 1));
}

#[test]
fn revocation_and_revision_change_are_checked_inside_transaction() {
    let revoked = Fixture::new(30_000);
    let operation = OperationId::new("operation:revoked");
    let action = Fixture::action("blocked");
    let approval = revoked.approve(&operation, "blocked", 10_000, ApprovalSemantics::OneTime);
    revoked
        .runtime
        .adapter()
        .revoke(&OpaqueHandle::new(HANDLE))
        .expect("revoke");
    let error = revoked
        .run(operation, &action, &approval)
        .expect_err("revoked write");
    assert_eq!(error.code, ErrorCode::AuthDenied);
    assert_eq!(revoked.runtime.adapter().counts().expect("counts").1, 0);

    let stale = Fixture::new(30_000);
    let operation = OperationId::new("operation:stale");
    let approval = stale.approve(&operation, "blocked", 10_000, ApprovalSemantics::OneTime);
    stale
        .runtime
        .adapter()
        .change_revision(SourceRevision::new("repo_R1:rev_8"))
        .expect("revision");
    let error = stale
        .run(operation, &action, &approval)
        .expect_err("stale write");
    assert_eq!(error.code, ErrorCode::CatalogStale);
    assert_eq!(stale.runtime.adapter().counts().expect("counts").1, 0);
}

#[test]
fn snapshot_approval_and_action_digest_fail_closed() {
    let expired_snapshot = Fixture::new(10);
    let operation = OperationId::new("operation:snapshot-expiry");
    let action = Fixture::action("body");
    let approval = expired_snapshot.approve(&operation, "body", 1_000, ApprovalSemantics::OneTime);
    expired_snapshot.clock.advance_ms(10).expect("advance");
    let error = expired_snapshot
        .run(operation, &action, &approval)
        .expect_err("expired snapshot");
    assert_eq!(error.code, ErrorCode::CatalogStale);

    let expired_approval = Fixture::new(30_000);
    let operation = OperationId::new("operation:approval-expiry");
    let approval = expired_approval.approve(&operation, "body", 5, ApprovalSemantics::OneTime);
    expired_approval.clock.advance_ms(5).expect("advance");
    let error = expired_approval
        .run(operation, &action, &approval)
        .expect_err("expired approval");
    assert_eq!(error.code, ErrorCode::ApprovalDenied);
    assert_eq!(
        expired_approval.runtime.adapter().counts().expect("counts"),
        (0, 0)
    );

    let changed = Fixture::new(30_000);
    let operation = OperationId::new("operation:changed-action");
    let approval = changed.approve(&operation, "body-a", 1_000, ApprovalSemantics::OneTime);
    let error = changed
        .run(operation, &Fixture::action("body-b"), &approval)
        .expect_err("changed action");
    assert_eq!(error.code, ErrorCode::ApprovalDenied);
    assert_eq!(changed.runtime.adapter().counts().expect("counts"), (0, 0));
}

#[test]
fn timeout_outcomes_are_explicit_and_reconcilable() {
    let before = Fixture::new(30_000);
    let operation = OperationId::new("operation:timeout-before");
    let action = Fixture::action("body");
    let approval = before.approve(&operation, "body", 1_000, ApprovalSemantics::OneTime);
    before
        .runtime
        .adapter()
        .set_fault(AdapterFault::TimeoutBeforeCommit)
        .expect("fault");
    let error = before
        .run(operation, &action, &approval)
        .expect_err("timeout before commit");
    assert_eq!(error.code, ErrorCode::ToolTimeout);
    assert_eq!(before.runtime.adapter().counts().expect("counts"), (1, 0));

    let after = Fixture::new(30_000);
    let operation = OperationId::new("operation:timeout-after");
    let approval = after.approve(&operation, "body", 1_000, ApprovalSemantics::OneTime);
    after
        .runtime
        .adapter()
        .set_fault(AdapterFault::TimeoutAfterCommit)
        .expect("fault");
    let receipt = after
        .run(operation, &action, &approval)
        .expect("reconciled receipt");
    assert!(receipt.replayed);
    assert_eq!(after.runtime.adapter().counts().expect("counts"), (1, 1));
}

#[test]
fn pre_execution_audit_failure_prevents_adapter_entry() {
    let fixture = Fixture::new(30_000);
    let operation = OperationId::new("operation:audit-before");
    let action = Fixture::action("body");
    let approval = fixture.approve(&operation, "body", 1_000, ApprovalSemantics::OneTime);
    fixture.runtime.audit().inject_failure().expect("inject");
    let error = fixture
        .run(operation, &action, &approval)
        .expect_err("audit failure");
    assert_eq!(error.code, ErrorCode::AuditFailed);
    assert_eq!(fixture.runtime.adapter().counts().expect("counts"), (0, 0));

    let receipt = fixture
        .run(
            OperationId::new("operation:audit-before"),
            &action,
            &approval,
        )
        .expect("approval remains usable after safe audit failure");
    assert!(!receipt.replayed);
}

#[test]
fn final_audit_failure_reports_committed_indeterminate_state() {
    let fixture = Fixture::new(30_000);
    let operation = OperationId::new("operation:audit-after");
    let action = Fixture::action("body");
    let approval = fixture.approve(&operation, "body", 1_000, ApprovalSemantics::OneTime);
    fixture
        .runtime
        .audit()
        .inject_failure_after(1)
        .expect("inject after pre-audit");
    let error = fixture
        .run(operation, &action, &approval)
        .expect_err("final audit failure");
    assert_eq!(error.code, ErrorCode::AuditFailed);
    assert!(error.reconciliation_key.is_some());
    assert_eq!(fixture.runtime.adapter().counts().expect("counts"), (1, 1));
}

#[test]
fn scope_mismatches_never_enter_adapter_transaction() {
    let fixture = Fixture::new(30_000);
    let operation = OperationId::new("operation:scope");
    let action = Fixture::action("body");
    let approval = fixture.approve(&operation, "body", 1_000, ApprovalSemantics::OneTime);
    let error = fixture
        .runtime
        .run_write(WriteRequest {
            principal: PrincipalId::new("user:other"),
            tenant: fixture.tenant.clone(),
            action_json: &action,
            snapshot: &fixture.snapshot,
            generation_nonce: &fixture.nonce,
            operation_id: operation,
            conversation_id: fixture.conversation.clone(),
            approval: &approval,
        })
        .expect_err("principal mismatch");
    assert_eq!(error.code, ErrorCode::SnapshotScopeMismatch);
    assert_eq!(fixture.runtime.adapter().counts().expect("counts"), (0, 0));
}

#[test]
fn manual_clock_and_deadline_boundaries_are_exact() {
    let clock = ManualClock::new(100, 1_000);
    let deadline = Deadline::after_ms(&clock, 2).expect("deadline");
    assert_eq!(deadline.monotonic_ns(), 2_001_000);
    assert!(!deadline.is_expired(&clock).expect("clock"));
    clock.advance_ms(2).expect("advance");
    assert_eq!(clock.wall_time_ms().expect("clock"), 102);
    assert!(deadline.is_expired(&clock).expect("clock"));
    assert_eq!(
        deadline.check(&clock).expect_err("expired").code,
        ErrorCode::ToolTimeout
    );

    let overflow = ManualClock::new(u64::MAX, u64::MAX);
    assert_eq!(
        overflow.advance_ms(1).expect_err("overflow").code,
        ErrorCode::InternalInvariant
    );
    assert_eq!(
        Deadline::after_ms(&overflow, 1)
            .expect_err("deadline overflow")
            .code,
        ErrorCode::InternalInvariant
    );
}

#[test]
fn concurrent_exact_duplicates_commit_once() {
    let clock = Arc::new(ManualClock::new(20_000, 0));
    let runtime = Arc::new(Runtime::github_with_clock(clock).expect("runtime"));
    let principal = PrincipalId::new("user:42");
    let tenant = TenantId::new("tenant_acme");
    let conversation = ConversationId::new("conversation:concurrent");
    let nonce = GenerationNonce::new("nonce:concurrent");
    let snapshot = runtime
        .list_issues(
            principal.clone(),
            tenant.clone(),
            30_000,
            nonce.clone(),
            conversation.clone(),
        )
        .expect("list");
    runtime
        .inspect_issue(
            principal.clone(),
            tenant.clone(),
            &snapshot,
            HANDLE,
            conversation.clone(),
        )
        .expect("inspect");
    let operation = OperationId::new("operation:concurrent");
    let approval = runtime
        .approval_for_comment(CommentApprovalRequest {
            principal: &principal,
            tenant: &tenant,
            snapshot: &snapshot,
            issue_handle: HANDLE,
            body: "same",
            operation_id: &operation,
            conversation_id: &conversation,
            ttl_ms: 10_000,
            semantics: ApprovalSemantics::OneTime,
        })
        .expect("approval");
    let barrier = Arc::new(Barrier::new(9));
    let mut threads = Vec::new();
    for _ in 0..8 {
        let runtime = Arc::clone(&runtime);
        let snapshot = snapshot.clone();
        let principal = principal.clone();
        let tenant = tenant.clone();
        let conversation = conversation.clone();
        let nonce = nonce.clone();
        let operation = operation.clone();
        let approval = approval.clone();
        let barrier = Arc::clone(&barrier);
        threads.push(thread::spawn(move || {
            let action = Fixture::action("same");
            barrier.wait();
            runtime.run_write(WriteRequest {
                principal,
                tenant,
                action_json: &action,
                snapshot: &snapshot,
                generation_nonce: &nonce,
                operation_id: operation,
                conversation_id: conversation,
                approval: &approval,
            })
        }));
    }
    barrier.wait();
    let mut committed = 0;
    let mut replayed = 0;
    for worker in threads {
        let receipt = worker.join().expect("join").expect("write");
        if receipt.replayed {
            replayed += 1;
        } else {
            committed += 1;
        }
    }
    assert_eq!((committed, replayed), (1, 7));
    assert_eq!(runtime.adapter().counts().expect("counts"), (1, 1));
}

#[test]
fn revocation_attempted_during_transaction_is_serialized_after_commit() {
    let clock = Arc::new(ManualClock::new(30_000, 0));
    let runtime = Arc::new(Runtime::github_with_clock(clock).expect("runtime"));
    let principal = PrincipalId::new("user:42");
    let tenant = TenantId::new("tenant_acme");
    let conversation = ConversationId::new("conversation:transaction-race");
    let nonce = GenerationNonce::new("nonce:transaction-race");
    let snapshot = runtime
        .list_issues(
            principal.clone(),
            tenant.clone(),
            30_000,
            nonce.clone(),
            conversation.clone(),
        )
        .expect("list");
    runtime
        .inspect_issue(
            principal.clone(),
            tenant.clone(),
            &snapshot,
            HANDLE,
            conversation.clone(),
        )
        .expect("inspect");
    let operation = OperationId::new("operation:transaction-race");
    let approval = runtime
        .approval_for_comment(CommentApprovalRequest {
            principal: &principal,
            tenant: &tenant,
            snapshot: &snapshot,
            issue_handle: HANDLE,
            body: "linearized",
            operation_id: &operation,
            conversation_id: &conversation,
            ttl_ms: 10_000,
            semantics: ApprovalSemantics::OneTime,
        })
        .expect("approval");
    let hook = Arc::new(TransactionHook::new());
    runtime
        .adapter()
        .set_transaction_hook(Some(Arc::clone(&hook)))
        .expect("hook");
    let writer_runtime = Arc::clone(&runtime);
    let writer_snapshot = snapshot.clone();
    let writer = thread::spawn(move || {
        let action = Fixture::action("linearized");
        writer_runtime.run_write(WriteRequest {
            principal,
            tenant,
            action_json: &action,
            snapshot: &writer_snapshot,
            generation_nonce: &nonce,
            operation_id: operation,
            conversation_id: conversation,
            approval: &approval,
        })
    });
    hook.wait_until_entered();
    let revoke_started = Arc::new(Barrier::new(2));
    let revoker_runtime = Arc::clone(&runtime);
    let revoker_started = Arc::clone(&revoke_started);
    let revoker = thread::spawn(move || {
        revoker_started.wait();
        revoker_runtime.adapter().revoke(&OpaqueHandle::new(HANDLE))
    });
    revoke_started.wait();
    hook.release();
    writer
        .join()
        .expect("writer join")
        .expect("linearized write");
    revoker.join().expect("revoker join").expect("revoke");
    runtime
        .adapter()
        .set_transaction_hook(None)
        .expect("clear hook");
    assert_eq!(runtime.adapter().counts().expect("counts"), (1, 1));
}
