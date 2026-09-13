from __future__ import annotations

import agentgate


def main() -> None:
    runtime = agentgate.Runtime()
    snapshot = runtime.list_issues()
    handle = snapshot.writable_issue_handles[0]
    body = "Thanks from the offline simulator!"
    runtime.inspect_issue(snapshot, handle)
    approval = runtime.approve_comment(snapshot, handle, body)
    receipt = runtime.comment_issue(snapshot, handle, body, approval)
    print({"snapshot": snapshot.snapshot_id, "handle": handle, "receipt": receipt})


if __name__ == "__main__":
    main()
