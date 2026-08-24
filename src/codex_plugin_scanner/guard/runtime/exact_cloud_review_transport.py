"""Wire helpers for the isolated Cloud Review exact-command transport."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from typing import TypedDict
from urllib.error import HTTPError

from ..contracts.guard_cloud_review import COMMAND_RESULT_CONTRACT_VERSION, validate_exact_command_result
from .exact_cloud_review import EXACT_CLOUD_REVIEW_OPERATION

EXACT_CLOUD_REVIEW_COMMAND_API_BASE = "/api/guard/review/v2/commands"
EXACT_CLOUD_REVIEW_TRANSPORT = "cloud_review"
_TRANSPORT_MARKER = "_guardCommandTransport"


class LeaseOptions(TypedDict):
    operations: tuple[str, ...]
    wait_ms: int


def exact_transport_job(job: dict[str, object]) -> dict[str, object]:
    """Attach a local-only route marker to a leased exact-review job."""

    return {**job, _TRANSPORT_MARKER: EXACT_CLOUD_REVIEW_TRANSPORT}


def uses_exact_transport(job: dict[str, object]) -> bool:
    return job.get(_TRANSPORT_MARKER) == EXACT_CLOUD_REVIEW_TRANSPORT


def exact_result(job: dict[str, object], execution: dict[str, object]) -> dict[str, object]:
    """Convert a successful exact executor response to the versioned result contract."""

    correlation_id = _required_text(job.get("id"), "exact_result_correlation_missing")
    signed_decision = _mapping(_mapping(job.get("payload")).get("remoteApproval"))
    bound_request_id = _required_text(
        _mapping(job.get("serverResolvedBinding")).get("localRequestId"),
        "exact_result_local_request_binding_missing",
    )
    decision_request_id = _required_text(
        signed_decision.get("localRequestId"),
        "exact_result_local_request_missing",
    )
    receipt_id = _required_text(signed_decision.get("receiptId"), "exact_result_receipt_missing")
    if bound_request_id != decision_request_id:
        raise ValueError("exact_result_local_request_binding_mismatch")
    data = execution.get("data")
    generated_at = _text(execution.get("generatedAt")) or datetime.now(timezone.utc).isoformat()
    if not isinstance(data, dict):
        return _result(
            correlation_id=correlation_id,
            local_request_id=bound_request_id,
            receipt_id=receipt_id,
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
    data_request_id = _required_text(data.get("localRequestId"), "exact_result_local_request_missing")
    data_receipt_id = _required_text(data.get("receiptId"), "exact_result_receipt_missing")
    if data_request_id != bound_request_id or data_receipt_id != receipt_id:
        raise ValueError("exact_result_execution_binding_mismatch")
    return _result(
        correlation_id=correlation_id,
        local_request_id=bound_request_id,
        receipt_id=receipt_id,
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
    exact_route_failure: Callable[[HTTPError], None] | None = None,
    exact_route_success: Callable[[], None] | None = None,
) -> dict[str, object] | None:
    generic = generic_operations(operations)
    if EXACT_CLOUD_REVIEW_OPERATION in operations:
        try:
            exact_response = exact_request(
                {
                    "operations": (EXACT_CLOUD_REVIEW_OPERATION,),
                    "wait_ms": wait_ms if exact_operation_only(operations) else 0,
                }
            )
        except HTTPError as error:
            if not generic:
                raise
            if exact_route_failure is not None:
                exact_route_failure(error)
        else:
            if exact_route_success is not None:
                exact_route_success()
            item = exact_response.get("item")
            if isinstance(item, dict):
                return exact_transport_job(item)
    if not generic:
        return None
    item = queue_request({"operations": generic, "wait_ms": wait_ms}).get("item")
    return item if isinstance(item, dict) else None


def _continuation_result(data: dict[str, object]) -> tuple[str, str | None]:
    status = _text(data.get("continuationStatus"))
    reason = _text(data.get("continuationReason"))
    if status in {
        "already_resumed",
        "blocked_not_resumed",
        "failed",
        "manual_retry_required",
        "not_applicable",
        "resumed",
        "unsupported",
        "waiting",
    }:
        return status, reason
    return "failed", reason or "continuation_status_missing"


def _result(
    *,
    correlation_id: str,
    local_request_id: str,
    receipt_id: str,
    application_status: str,
    application_reason: str | None,
    continuation_status: str,
    continuation_reason: str | None,
    updated_at: str,
) -> dict[str, object]:
    result = {
        "applicationReason": application_reason,
        "applicationStatus": application_status,
        "applicationUpdatedAt": updated_at,
        "continuationReason": continuation_reason,
        "continuationStatus": continuation_status,
        "continuationUpdatedAt": updated_at,
        "contractVersion": COMMAND_RESULT_CONTRACT_VERSION,
        "correlationId": correlation_id,
        "localRequestId": local_request_id,
        "receiptId": receipt_id,
    }
    validate_exact_command_result(result)
    return result


def _text(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def _mapping(value: object) -> dict[str, object]:
    return dict(value) if isinstance(value, dict) else {}


def _required_text(value: object, error: str) -> str:
    result = _text(value)
    if result is None:
        raise ValueError(error)
    return result


__all__ = [
    "EXACT_CLOUD_REVIEW_COMMAND_API_BASE",
    "exact_operation_only",
    "exact_result",
    "exact_transport_job",
    "generic_operations",
    "lease_next_job",
    "uses_exact_transport",
]
