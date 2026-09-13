use std::sync::{Arc, Barrier};
use std::thread;

use agentgate_core::approval::{
    ApprovalProvider, ApprovalRequest, ApprovalReservation, ApprovalSemantics,
    InMemoryApprovalProvider,
};
use agentgate_core::clock::Clock;
use agentgate_core::error::{ErrorCode, GateError, GateResult};
use agentgate_core::{
    ActionDigest, IdempotencyKey, ManualClock, OperationId, PolicyDigest, PrincipalId,
    ReceiptDigest, SnapshotDigest, SourceRevision, TenantId, ToolId,
};

struct RequestValues {
    principal: PrincipalId,
    tenant: TenantId,
    operation: OperationId,
    tool: ToolId,
    action: ActionDigest,
    snapshot: SnapshotDigest,
    revision: SourceRevision,
    policy: PolicyDigest,
}

struct FailingClock;

impl Clock for FailingClock {
    fn wall_time_ms(&self) -> GateResult<u64> {
        Err(GateError::new(
            ErrorCode::InternalInvariant,
            "clock unavailable",
        ))
    }

    fn monotonic_ns(&self) -> GateResult<u64> {
        Err(GateError::new(
            ErrorCode::InternalInvariant,
            "clock unavailable",
        ))
    }
}

impl RequestValues {
    fn new(action: &str) -> Self {
        Self {
            principal: PrincipalId::new("principal:a"),
            tenant: TenantId::new("tenant:a"),
            operation: OperationId::new("operation:a"),
            tool: ToolId::new("tool.write", "1"),
            action: ActionDigest::new(action),
            snapshot: SnapshotDigest::new("snapshot:a"),
            revision: SourceRevision::new("revision:a"),
            policy: PolicyDigest::new("policy:a"),
        }
    }

    fn request(&self) -> ApprovalRequest<'_> {
        ApprovalRequest {
            principal: &self.principal,
            tenant: &self.tenant,
            operation_id: &self.operation,
            tool_id: &self.tool,
            action_digest: &self.action,
            snapshot_digest: &self.snapshot,
            source_revision: &self.revision,
            policy_digest: &self.policy,
        }
    }
}

#[test]
fn issued_handles_are_unique_and_request_changes_are_denied() {
    let provider = InMemoryApprovalProvider::new(4);
    let clock = ManualClock::new(100, 0);
    let values = RequestValues::new("action:a");
    let first = provider
        .issue(&values.request(), &clock, 100, ApprovalSemantics::OneTime)
        .expect("first approval");
    let second = provider
        .issue(&values.request(), &clock, 100, ApprovalSemantics::OneTime)
        .expect("second approval");
    assert_ne!(first.approval_id(), second.approval_id());

    let changed = RequestValues::new("action:b");
    assert!(provider.verify(&first, &changed.request(), &clock).is_err());
    provider
        .verify(&first, &values.request(), &clock)
        .expect("exact request");
}

#[test]
fn concurrent_reservation_has_one_initial_winner_and_exact_retries() {
    let provider = Arc::new(InMemoryApprovalProvider::new(2));
    let clock = Arc::new(ManualClock::new(100, 0));
    let values = Arc::new(RequestValues::new("action:a"));
    let token = Arc::new(
        provider
            .issue(
                &values.request(),
                clock.as_ref(),
                100,
                ApprovalSemantics::OneTime,
            )
            .expect("approval"),
    );
    let key = IdempotencyKey::new("key:a");
    let barrier = Arc::new(Barrier::new(9));
    let mut workers = Vec::new();
    for _ in 0..8 {
        let provider = Arc::clone(&provider);
        let clock = Arc::clone(&clock);
        let values = Arc::clone(&values);
        let token = Arc::clone(&token);
        let key = key.clone();
        let barrier = Arc::clone(&barrier);
        workers.push(thread::spawn(move || {
            barrier.wait();
            provider.reserve(&token, &values.request(), &key, clock.as_ref())
        }));
    }
    barrier.wait();
    let mut initial = 0;
    let mut retries = 0;
    for worker in workers {
        match worker.join().expect("join").expect("reservation") {
            ApprovalReservation::Reserved => initial += 1,
            ApprovalReservation::ExactRetry => retries += 1,
            ApprovalReservation::Completed(_) => panic!("not completed yet"),
        }
    }
    assert_eq!((initial, retries), (1, 7));

    let receipt = ReceiptDigest::new("receipt:a");
    provider.complete(&token, &key, &receipt).expect("complete");
    assert_eq!(
        provider
            .reserve(&token, &values.request(), &key, clock.as_ref())
            .expect("completed retry"),
        ApprovalReservation::Completed(receipt)
    );
    assert!(provider
        .reserve(
            &token,
            &values.request(),
            &IdempotencyKey::new("key:b"),
            clock.as_ref(),
        )
        .is_err());
}

#[test]
fn expired_records_are_pruned_before_enforcing_the_bound() {
    let provider = InMemoryApprovalProvider::new(1);
    let clock = ManualClock::new(100, 0);
    let first = RequestValues::new("action:a");
    provider
        .issue(&first.request(), &clock, 1, ApprovalSemantics::OneTime)
        .expect("first approval");
    clock.advance_ms(1).expect("advance");
    let second = RequestValues::new("action:b");
    provider
        .issue(&second.request(), &clock, 1, ApprovalSemantics::OneTime)
        .expect("expired record is pruned");
    assert_eq!(provider.retained_records().expect("retained"), 1);
}

#[test]
fn approval_issuance_fails_closed_when_time_is_unavailable() {
    let provider = InMemoryApprovalProvider::new(1);
    let values = RequestValues::new("action:a");
    let error = provider
        .issue(
            &values.request(),
            &FailingClock,
            100,
            ApprovalSemantics::OneTime,
        )
        .expect_err("clock failure");
    assert_eq!(error.code, ErrorCode::InternalInvariant);
    assert_eq!(provider.retained_records().expect("retained"), 0);
}

#[test]
fn expired_approval_cannot_reenter_even_after_completion() {
    let provider = InMemoryApprovalProvider::new(1);
    let clock = ManualClock::new(100, 0);
    let values = RequestValues::new("action:a");
    let token = provider
        .issue(&values.request(), &clock, 1, ApprovalSemantics::OneTime)
        .expect("approval");
    let key = IdempotencyKey::new("key:a");
    assert_eq!(
        provider
            .reserve(&token, &values.request(), &key, &clock)
            .expect("reservation"),
        ApprovalReservation::Reserved
    );
    provider
        .complete(&token, &key, &ReceiptDigest::new("receipt:a"))
        .expect("completion");
    clock.advance_ms(1).expect("advance");
    assert!(provider
        .reserve(&token, &values.request(), &key, &clock)
        .is_err());
}
