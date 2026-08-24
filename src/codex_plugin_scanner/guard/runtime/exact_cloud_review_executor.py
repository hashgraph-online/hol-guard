"""Queue executor for the separately authorized exact Cloud Review operation."""

from __future__ import annotations

from collections.abc import Callable

from ..store import GuardStore
from .exact_cloud_review import ExactCloudReviewError, apply_exact_cloud_review
from .remote_approval_execution import remote_resume_confirmed

ResumeAfterApproval = Callable[..., dict[str, object]]


def execute_exact_cloud_review_operation(
    *,
    payload: dict[str, object],
    store: GuardStore,
    generated_at: str,
    resume_after_approval: ResumeAfterApproval,
) -> dict[str, object]:
    signed_decision = _mapping(payload.get("remoteApproval"))
    if not signed_decision:
        raise ValueError("remote_exact_approval_missing")
    try:
        resolution = apply_exact_cloud_review(
            store,
            remote_approval=signed_decision,
            expected_harness=_text(payload.get("harness")),
            now=generated_at,
        )
    except ExactCloudReviewError as error:
        raise ValueError(error.code) from error
    request_row = store.get_approval_request(resolution.request_id)
    if not isinstance(request_row, dict):
        raise ValueError("remote_exact_request_not_pending")
    resume_metadata = resume_after_approval(
        store=store,
        request_row=request_row,
        request_id=resolution.request_id,
        action=resolution.action,
        now=generated_at,
    )
    response: dict[str, object] = {
        "action": resolution.action,
        "daemonAckStatus": "resolved"
        if remote_resume_confirmed(resume_metadata, resolution.action)
        else "resolved_unconfirmed",
        "localRequestId": resolution.request_id,
        "receiptId": resolution.receipt_id,
        "remoteDecision": resolution.action,
        "resolution": {"resolvedDuplicateIds": [], "resolvedRequest": resolution.resolved_request},
        "status": "completed",
    }
    response.update(resume_metadata)
    return {"data": response, "generatedAt": generated_at}


def _mapping(value: object) -> dict[str, object]:
    return dict(value) if isinstance(value, dict) else {}


def _text(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


__all__ = ["execute_exact_cloud_review_operation"]
