use std::sync::Arc;

use agentgate_core::{
    CommentApprovalRequest, ConversationId, ErrorCode, GenerationNonce, ManualClock, OperationId,
    PrincipalId, Runtime, TenantId, ToolId,
};

const HANDLE: &str = "github:tenant_acme:repo_R1:issue_I12";
const OTHER_HANDLE: &str = "github:tenant_acme:repo_R1:issue_I14";

fn ids() -> (PrincipalId, TenantId, ConversationId, GenerationNonce) {
    (
        PrincipalId::new("user:42"),
        TenantId::new("tenant_acme"),
        ConversationId::new("conversation:a"),
        GenerationNonce::new("nonce:a"),
    )
}

#[test]
fn exposure_requires_list_then_matching_inspection() {
    let clock = Arc::new(ManualClock::new(1_000, 0));
    let runtime = Runtime::github_with_clock(clock).expect("runtime");
    let (principal, tenant, conversation, nonce) = ids();

    let initial = runtime
        .exposed_tools(principal.clone(), tenant.clone(), conversation.clone())
        .expect("initial exposure");
    assert_eq!(initial.len(), 1);
    assert!(initial.contains(&ToolId::new("github.list_issues", "1")));

    let snapshot = runtime
        .list_issues(
            principal.clone(),
            tenant.clone(),
            30_000,
            nonce,
            conversation.clone(),
        )
        .expect("list");
    let listed = runtime
        .exposed_tools(principal.clone(), tenant.clone(), conversation.clone())
        .expect("listed exposure");
    assert!(listed.contains(&ToolId::new("github.inspect_issue", "1")));
    assert!(!listed.contains(&ToolId::new("github.comment_issue", "1")));

    let error = runtime
        .approval_for_comment(CommentApprovalRequest {
            principal: &principal,
            tenant: &tenant,
            snapshot: &snapshot,
            issue_handle: HANDLE,
            body: "body",
            operation_id: &OperationId::new("operation:early"),
            conversation_id: &conversation,
            ttl_ms: 1_000,
            semantics: agentgate_core::ApprovalSemantics::OneTime,
        })
        .expect_err("comment before inspection");
    assert_eq!(error.code, ErrorCode::PolicyDenied);

    runtime
        .inspect_issue(
            principal.clone(),
            tenant.clone(),
            &snapshot,
            HANDLE,
            conversation.clone(),
        )
        .expect("inspect");
    let inspected = runtime
        .exposed_tools(principal, tenant, conversation)
        .expect("inspected exposure");
    assert!(inspected.contains(&ToolId::new("github.comment_issue", "1")));
}

#[test]
fn workflow_is_tenant_principal_conversation_scoped_and_expires() {
    let clock = Arc::new(ManualClock::new(5_000, 0));
    let runtime = Runtime::github_with_clock(clock.clone()).expect("runtime");
    let (principal, tenant, conversation, nonce) = ids();
    runtime
        .list_issues(
            principal.clone(),
            tenant.clone(),
            10,
            nonce,
            conversation.clone(),
        )
        .expect("list");

    for (other_principal, other_tenant, other_conversation) in [
        (
            PrincipalId::new("user:other"),
            tenant.clone(),
            conversation.clone(),
        ),
        (
            principal.clone(),
            TenantId::new("tenant_other"),
            conversation.clone(),
        ),
        (
            principal.clone(),
            tenant.clone(),
            ConversationId::new("conversation:other"),
        ),
    ] {
        let exposed = runtime
            .exposed_tools(other_principal, other_tenant, other_conversation)
            .expect("scoped exposure");
        assert_eq!(exposed.len(), 1);
    }

    clock.advance_ms(10).expect("advance");
    let expired = runtime
        .exposed_tools(principal, tenant, conversation)
        .expect("expired exposure");
    assert_eq!(expired.len(), 1);
}

#[test]
fn inspection_for_one_allowed_issue_does_not_expose_comment_for_another() {
    let clock = Arc::new(ManualClock::new(8_000, 0));
    let runtime = Runtime::github_with_clock(clock).expect("runtime");
    let (principal, tenant, conversation, nonce) = ids();
    let snapshot = runtime
        .list_issues(
            principal.clone(),
            tenant.clone(),
            30_000,
            nonce,
            conversation.clone(),
        )
        .expect("list");
    assert!(snapshot
        .values("writable_issue_handles")
        .expect("handles")
        .iter()
        .any(|value| value == OTHER_HANDLE));
    runtime
        .inspect_issue(
            principal.clone(),
            tenant.clone(),
            &snapshot,
            HANDLE,
            conversation.clone(),
        )
        .expect("inspect first issue");
    let error = runtime
        .approval_for_comment(CommentApprovalRequest {
            principal: &principal,
            tenant: &tenant,
            snapshot: &snapshot,
            issue_handle: OTHER_HANDLE,
            body: "body",
            operation_id: &OperationId::new("operation:other-issue"),
            conversation_id: &conversation,
            ttl_ms: 1_000,
            semantics: agentgate_core::ApprovalSemantics::OneTime,
        })
        .expect_err("different issue must be denied");
    assert_eq!(error.code, ErrorCode::PolicyDenied);
    assert_eq!(runtime.adapter().counts().expect("counts"), (0, 0));
}
