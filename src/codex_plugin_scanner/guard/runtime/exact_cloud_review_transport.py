"""Wire helpers for the isolated Cloud Review exact-command transport."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from typing import TypedDict

from .exact_cloud_review import EXACT_CLOUD_REVIEW_OPERATION

EXACT_CLOUD_REVIEW_COMMAND_API_BASE = "/api/guard/review/v2/commands"
EXACT_CLOUD_REVIEW_TRANSPORT = "cloud_review_v2"
_TRANSPORT_MARKER = "_guardCommandTransport"
_RESULT_CONTRACT_VERSION = "guard-cloud-review-command-result-v2"


class LeaseOptions(TypedDict):
    operations: tuple[str, ...]
    wait_ms: int


def exact_transport_job(job: dict[str, object]) -> dict[str, object]:
    """Attach a local-only route marker to a leased exact-review job."""

    return {**job, _TRANSPORT_MARKER: EXACT_CLOUD_REVIEW_TRANSPORT}


def uses_exact_transport(job: dict[str, object]) -> bool:
    return job.get(_TRANSPORT_MARKER) == EXACT_CLOUD_REVIEW_TRANSPORT


def exact_result(execution: dict[str, object]) -> dict[str, object]:
    """Convert a successful exact executor response to the v2 result contract."""

    data = execution.get("data")
    generated_at = _text(execution.get("generatedAt")) or datetime.now(timezone.utc).isoformat()
    if not isinstance(data, dict):
        return _result(
            application_status="failed_terminal",
            application_reason="exact_result_invalid",
            continuation_status="failed",
            continuation_reason="exact_result_invalid",
            updated_at=generated_at,
        )
    application_status = (
        "applied"
        if _text(data.get("daemonAckStatus"))
        in {
            "resolved",
            "resolved_unconfirmed",
        }
        else "failed_terminal"
    )
    application_reason = (
        None
        if application_status == "applied"
        else (_text(data.get("daemonAckStatus")) or "exact_application_unconfirmed")
    )
    continuation_status, continuation_reason = _continuation_result(data)
    return _result(
        application_status=application_status,
        application_reason=application_reason,
        continuation_status=continuation_status,
        continuation_reason=continuation_reason,
        updated_at=generated_at,
    )


def exact_operation_only(operations: tuple[str, ...]) -> bool:
    return operations == (EXACT_CLOUD_REVIEW_OPERATION,)


def generic_operations(operations: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(operation for operation in operations if operation != EXACT_CLOUD_REVIEW_OPERATION)


def lease_next_job(
    *,
    operations: tuple[str, ...],
    wait_ms: int,
    exact_request: Callable[[LeaseOptions], dict[str, object]],
    queue_request: Callable[[LeaseOptions], dict[str, object]],
) -> dict[str, object] | None:
    generic = generic_operations(operations)
    if EXACT_CLOUD_REVIEW_OPERATION in operations:
        exact_response = exact_request(
            {
                "operations": (EXACT_CLOUD_REVIEW_OPERATION,),
                "wait_ms": wait_ms if exact_operation_only(operations) else 0,
            }
        )
        item = exact_response.get("item")
        if isinstance(item, dict):
            return exact_transport_job(item)
    if not generic:
        return None
    item = queue_request({"operations": generic, "wait_ms": wait_ms}).get("item")
    return item if isinstance(item, dict) else None


def _continuation_result(data: dict[str, object]) -> tuple[str, str | None]:
    status = _text(data.get("resumeStatus"))
    if status in {"resumed", "sent"}:
        return "resumed", None
    if status == "already_sent":
        return "already_resumed", None
    if status == "blocked":
        return "blocked_not_resumed", None
    if status == "not_applicable":
        return "not_applicable", None
    if status in {"pending", "waiting"}:
        return "waiting", _text(data.get("resumeReason"))
    if status == "skipped" and _blocked_skip(data):
        return "blocked_not_resumed", None
    if status in {None, "skipped"}:
        return "manual_retry_required", _text(data.get("resumeReason")) or "continuation_not_confirmed"
    return "failed", _text(data.get("resumeReason")) or status


def _blocked_skip(data: dict[str, object]) -> bool:
    detail = data.get("codexResume") or data.get("harnessResume")
    return isinstance(detail, dict) and detail.get("reason") == "blocked_not_resumed"


def _result(
    *,
    application_status: str,
    application_reason: str | None,
    continuation_status: str,
    continuation_reason: str | None,
    updated_at: str,
) -> dict[str, object]:
    return {
        "applicationReason": application_reason,
        "applicationStatus": application_status,
        "applicationUpdatedAt": updated_at,
        "continuationReason": continuation_reason,
        "continuationStatus": continuation_status,
        "continuationUpdatedAt": updated_at,
        "contractVersion": _RESULT_CONTRACT_VERSION,
    }


def _text(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


__all__ = [
    "EXACT_CLOUD_REVIEW_COMMAND_API_BASE",
    "exact_operation_only",
    "exact_result",
    "exact_transport_job",
    "generic_operations",
    "lease_next_job",
    "uses_exact_transport",
]
