"""Queue executor for the separately authorized exact Cloud Review operation."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import cast

from ..store import GuardStore
from .exact_cloud_review import ExactCloudReviewError
from .exact_cloud_review_apply import apply_exact_cloud_review

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
    continuation_status = _text(resume_metadata.get("continuationStatus"))
    continuation_reason = _text(resume_metadata.get("continuationReason"))
    if continuation_status is None:
        continuation_status = "blocked_not_resumed" if resolution.action == "block" else "manual_retry_required"
        continuation_reason = (
            "remote_block_applied" if resolution.action == "block" else "continuation_transport_unavailable"
        )
    response: dict[str, object] = {
        "action": resolution.action,
        "applicationReason": None,
        "applicationStatus": "applied",
        "applicationUpdatedAt": generated_at,
        "continuationReason": continuation_reason,
        "continuationStatus": continuation_status,
        "continuationUpdatedAt": _text(resume_metadata.get("continuationCompletedAt")) or generated_at,
        "localRequestId": resolution.request_id,
        "receiptId": resolution.receipt_id,
        "remoteDecision": resolution.action,
        "resolution": {"resolvedDuplicateIds": [], "resolvedRequest": resolution.resolved_request},
        "status": "completed",
    }
    for key in ("codexResume", "harnessResume"):
        if key in resume_metadata:
            response[key] = resume_metadata[key]
    return {"data": response, "generatedAt": generated_at}


def _mapping(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping):
        return {}
    raw = cast(Mapping[object, object], value)
    if any(not isinstance(key, str) for key in raw):
        return {}
    return {cast(str, key): nested for key, nested in raw.items()}


def _text(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


__all__ = ["execute_exact_cloud_review_operation"]
