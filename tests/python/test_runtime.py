import json

import agentgate
import pytest


HANDLE = "github:tenant_acme:repo_R1:issue_I12"


def prepared_runtime():
    runtime = agentgate.Runtime()
    snapshot = runtime.list_issues()
    inspection = runtime.inspect_issue(snapshot, HANDLE)
    assert inspection["issue_handle"] == HANDLE
    return runtime, snapshot


def test_offline_workflow_write_and_exact_retry():
    runtime, snapshot = prepared_runtime()
    approval = runtime.approve_comment(
        snapshot,
        HANDLE,
        "Thanks!",
        operation_id="same",
    )
    first = runtime.comment_issue(
        snapshot,
        HANDLE,
        "Thanks!",
        approval,
        operation_id="same",
    )
    retry = runtime.comment_issue(
        snapshot,
        HANDLE,
        "Thanks!",
        approval,
        operation_id="same",
    )

    assert first["operation_id"] == "same"
    assert first["receipt_digest"] == retry["receipt_digest"]
    assert first["replayed"] is False
    assert retry["replayed"] is True
    assert runtime.execution_counts() == (1, 1)
    audit = json.loads(runtime.audit_json(limit=100))
    assert all(entry["schema_digest"] for entry in audit)
    assert all(entry["snapshot_digest"] for entry in audit)
    assert "Thanks!" not in runtime.audit_json(limit=100)


def test_workflow_exposure_and_engine_parity_surface():
    runtime = agentgate.Runtime()
    assert runtime.exposed_tools() == ["github.list_issues@1"]
    assert runtime.engine_for_tool("github.list_issues", "1") == "maskforge"
    assert runtime.engine_for_tool("github.inspect_issue", "1") == "maskforge"
    assert runtime.engine_for_tool("github.comment_issue", "1") == "sidememory"
    assert runtime.comment_action_digest(HANDLE, "Thanks!") == (
        "7e15b4115d82d7463bca756f262f85605232bd3474732ab0517cae75ed29ef8a"
    )
    for tool in ["github.list_issues", "github.inspect_issue", "github.comment_issue"]:
        assert len(runtime.artifact_key_for_tool(tool, "1")) == 64
    snapshot = runtime.list_issues()
    assert "github.inspect_issue@1" in runtime.exposed_tools()
    assert "github.comment_issue@1" not in runtime.exposed_tools()
    runtime.inspect_issue(snapshot, HANDLE)
    assert "github.comment_issue@1" in runtime.exposed_tools()


def test_comment_before_inspection_and_nonmember_fail_closed():
    runtime = agentgate.Runtime()
    snapshot = runtime.list_issues()
    with pytest.raises(agentgate.PolicyDeniedError, match="POLICY_DENIED"):
        runtime.approve_comment(snapshot, HANDLE, "blocked")
    with pytest.raises(agentgate.AuthDeniedError, match="AUTH_DENIED"):
        runtime.inspect_issue(snapshot, "github:tenant_acme:repo_R1:issue_I99")
    assert runtime.execution_counts() == (0, 0)


def test_approval_is_bound_to_action_and_operation():
    runtime, snapshot = prepared_runtime()
    approval = runtime.approve_comment(
        snapshot,
        HANDLE,
        "body-a",
        operation_id="operation-a",
    )
    with pytest.raises(agentgate.ApprovalDeniedError, match="APPROVAL_DENIED"):
        runtime.comment_issue(
            snapshot,
            HANDLE,
            "body-b",
            approval,
            operation_id="operation-a",
        )
    with pytest.raises(agentgate.ApprovalDeniedError, match="APPROVAL_DENIED"):
        runtime.comment_issue(
            snapshot,
            HANDLE,
            "body-a",
            approval,
            operation_id="operation-b",
        )
    assert runtime.execution_counts() == (0, 0)
