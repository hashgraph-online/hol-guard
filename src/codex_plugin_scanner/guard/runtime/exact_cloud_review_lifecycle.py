"""Optional structural lifecycle observations for exact Cloud Review."""

from __future__ import annotations

import logging
from collections.abc import Callable

ExactReviewLifecycleObserver = Callable[[dict[str, object]], None]

_LOGGER = logging.getLogger(__name__)
_EVENTS = {
    "command_leased",
    "command_result",
    "continuation_completed",
    "local_resolved",
}


def observe_exact_review_lease(
    observer: ExactReviewLifecycleObserver | None,
    job: dict[str, object],
    *,
    occurred_at: str,
) -> None:
    observe_exact_review_lifecycle(
        observer,
        event="command_leased",
        correlation_id=_required_text(job, "id"),
        occurred_at=occurred_at,
        details={"leaseId": _required_text(job, "leaseId")},
    )


def observe_exact_review_execution(
    observer: ExactReviewLifecycleObserver | None,
    job: dict[str, object],
    execution: dict[str, object],
    *,
    occurred_at: str,
) -> None:
    if job.get("operation") != "guard.review.resolveExact":
        return
    data = execution.get("data")
    if not isinstance(data, dict) or not isinstance(data.get("localRequestId"), str):
        return
    correlation_id = _required_text(job, "id")
    request_id = str(data["localRequestId"])
    observe_exact_review_lifecycle(
        observer,
        event="local_resolved",
        correlation_id=correlation_id,
        occurred_at=occurred_at,
        details={"action": str(data.get("action") or "unknown"), "localRequestId": request_id},
    )
    observe_exact_review_lifecycle(
        observer,
        event="continuation_completed",
        correlation_id=correlation_id,
        occurred_at=occurred_at,
        details={"localRequestId": request_id, "resumeStatus": str(data.get("resumeStatus") or "unknown")},
    )


def observe_exact_review_result(
    observer: ExactReviewLifecycleObserver | None,
    job: dict[str, object],
    *,
    occurred_at: str,
    status: object,
) -> None:
    observe_exact_review_lifecycle(
        observer,
        event="command_result",
        correlation_id=_required_text(job, "id"),
        occurred_at=occurred_at,
        details={"status": str(status or "unknown")},
    )


def observe_exact_review_lifecycle(
    observer: ExactReviewLifecycleObserver | None,
    *,
    event: str,
    correlation_id: str,
    occurred_at: str,
    details: dict[str, object] | None = None,
) -> None:
    """Notify an optional observer without making telemetry execution authority."""

    if observer is None:
        return
    if event not in _EVENTS:
        raise ValueError("exact_review_lifecycle_event_invalid")
    observation: dict[str, object] = {
        "contractVersion": "guard.review-exact-lifecycle.v1",
        "correlationId": correlation_id,
        "event": event,
        "occurredAt": occurred_at,
        "operation": "guard.review.resolveExact",
    }
    if details:
        observation["details"] = details
    try:
        observer(observation)
    except Exception:
        _LOGGER.warning("Exact Cloud Review lifecycle observer failed: event=%s", event)


def _required_text(payload: dict[str, object], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"exact_review_lifecycle_{key}_missing")
    return value


__all__ = [
    "ExactReviewLifecycleObserver",
    "observe_exact_review_execution",
    "observe_exact_review_lease",
    "observe_exact_review_lifecycle",
    "observe_exact_review_result",
]
