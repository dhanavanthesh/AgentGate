from typing import TypedDict


class ExecutionReceipt(TypedDict):
    operation_id: str
    idempotency_key: str
    receipt_digest: str
    comment_count: int
    replayed: bool


class InspectionReceipt(TypedDict):
    issue_handle: str
    title: str
    source_revision: str
    inspection_digest: str
