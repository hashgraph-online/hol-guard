"""Serialization and validation helpers for continuation evidence."""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import datetime, timezone
from hashlib import sha256
from typing import Final, cast
from uuid import uuid4

from .continuation_contract import ContinuationAction, ContinuationOffer, ContinuationResult, ContinuationStatus

_PERSISTED_STATUSES: Final = frozenset(
    {"resumed", "already_resumed", "manual_retry_required", "blocked_not_resumed", "unsupported", "failed", "waiting"}
)


def continuation_payload(offer: ContinuationOffer, result: ContinuationResult, *, replayed: bool) -> dict[str, object]:
    status = public_status(result.status)
    if offer.harness == "codex" and result.status in {"manual_retry_required", "blocked_not_resumed"}:
        status = "skipped"
    reason = public_reason(offer, result)
    detail = {
        "capability": offer.capability,
        "completedAt": result.completed_at.isoformat(),
        "correlationId": offer.correlation_id,
        "evidenceId": result.evidence_id,
        "harness": offer.harness,
        "message": public_message(offer, result),
        "reason": reason,
        "status": status,
        "strategy": continuation_strategy(offer, result),
        "supported": result.status != "blocked_not_resumed"
        and offer.capability in {"suspended-response", "session-resume"},
    }
    payload: dict[str, object] = {
        "correlationId": offer.correlation_id,
        "continuationCapability": offer.capability,
        "continuationCompletedAt": result.completed_at.isoformat(),
        "continuationEvidenceId": result.evidence_id,
        "continuationReason": result.reason,
        "continuationStatus": result.status,
    }
    if offer.harness == "codex":
        payload["codexResume"] = detail
    else:
        payload["harnessResume"] = detail
    if result.status == "manual_retry_required" and not replayed:
        payload["localManualRetryNotification"] = True
    return payload


def continuation_result(
    offer: ContinuationOffer,
    status: ContinuationStatus,
    reason: str,
    observed_at: str,
) -> ContinuationResult:
    return ContinuationResult(
        correlation_id=offer.correlation_id,
        capability=offer.capability,
        status=status,
        reason=bounded_reason(reason),
        completed_at=parse_aware_timestamp(observed_at),
        evidence_id=f"evidence-{uuid4().hex}",
    )


def offer_hash(offer: ContinuationOffer) -> str:
    document = {
        "capability": offer.capability,
        "contractVersion": offer.contract_version,
        "correlationId": offer.correlation_id,
        "harness": offer.harness,
        "hookAttached": offer.original_hook_attached,
        "target": offer.opaque_target_id,
        "waitDeadline": offer.wait_deadline.isoformat() if offer.wait_deadline is not None else None,
    }
    encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256(encoded).hexdigest()


def public_status(value: str) -> str:
    return {
        "waiting": "pending",
        "resumed": "sent",
        "already_resumed": "already_sent",
        "blocked_not_resumed": "blocked",
    }.get(value, value)


def persisted_resume_status(offer: ContinuationOffer, result: ContinuationResult) -> str:
    if offer.harness == "codex" and result.status in {"manual_retry_required", "blocked_not_resumed"}:
        return "skipped"
    return public_status(result.status)


def public_reason(offer: ContinuationOffer, result: ContinuationResult) -> str:
    if offer.harness == "codex" and result.status == "blocked_not_resumed":
        return "blocked_not_resumed"
    if offer.harness == "codex" and result.status == "waiting":
        return "live_hook_waiting"
    return result.reason


def public_message(offer: ContinuationOffer, result: ContinuationResult) -> str | None:
    if offer.harness != "codex":
        return None
    if result.status == "waiting":
        return (
            "Decision saved. Codex is still waiting for this browser decision, so HOL Guard will let the "
            "original Codex action continue without starting a second headless run."
        )
    if result.status == "manual_retry_required":
        return (
            "Decision saved. HOL Guard could not find the original Codex chat to message. Return to Codex and retry "
            "the same request; this approval is now saved."
        )
    if result.status == "failed":
        return (
            "Decision saved. HOL Guard could not send Codex a continuation message in the original chat. Return to "
            "Codex and retry the same request; this approval is now saved."
        )
    if result.status == "blocked_not_resumed":
        return (
            "Decision saved. HOL Guard blocked this Codex request and will not resume or retry it. "
            "Do not retry that action in Codex. Ask for a safe alternative instead."
        )
    return None


def continuation_strategy(offer: ContinuationOffer, result: ContinuationResult) -> str:
    if result.status == "blocked_not_resumed":
        return "manual-only"
    if offer.capability == "suspended-response":
        return "codex-live-hook"
    if offer.capability == "session-resume":
        return "codex-app-server-thread"
    return "manual-only"


def attempt_count(value: Mapping[str, object] | None) -> int:
    previous = value.get("attempt_count") if isinstance(value, Mapping) else None
    return previous + 1 if isinstance(previous, int) and not isinstance(previous, bool) else 1


def previous_result(
    value: Mapping[str, object] | None,
    *,
    offer: ContinuationOffer,
    action: ContinuationAction,
) -> ContinuationResult | None:
    if not isinstance(value, Mapping):
        return None
    if value.get("continuation_offer_hash") != offer_hash(offer) or value.get("continuation_action") != action:
        return None
    status = persisted_result_status(text_value(value.get("continuation_status")))
    if status is None:
        return None
    completed_at = first_aware_timestamp(value, ("continuation_completed_at",))
    evidence = mapping_list(value.get("continuation_evidence"))
    evidence_id = text_value(evidence[0].get("evidenceId")) if evidence else None
    if completed_at is None or evidence_id is None:
        return None
    return ContinuationResult(
        correlation_id=offer.correlation_id,
        capability=offer.capability,
        status=status,
        reason=bounded_reason(text_value(value.get("continuation_reason")) or status),
        completed_at=completed_at,
        evidence_id=evidence_id,
    )


def operation_update_payload(
    operation: Mapping[str, object] | None,
    *,
    result: ContinuationResult,
    action: ContinuationAction,
    now: str,
) -> dict[str, object] | None:
    if not isinstance(operation, Mapping):
        return None
    required = tuple(
        text_value(operation.get(key)) for key in ("operation_id", "session_id", "operation_type", "harness")
    )
    operation_id, session_id, operation_type, harness = required
    if operation_id is None or session_id is None or operation_type is None or harness is None:
        return None
    metadata = dict(mapping_value(operation.get("metadata")))
    metadata["continuation"] = {
        "action": action,
        "capability": result.capability,
        "correlationId": result.correlation_id,
        "evidence_id": result.evidence_id,
        "reason": result.reason,
        "status": result.status,
    }
    status = {
        "resumed": "resumed",
        "already_resumed": "resumed",
        "manual_retry_required": "manual_retry_required",
        "blocked_not_resumed": "blocked",
        "failed": "continuation_failed",
    }.get(result.status, "waiting_on_approval")
    return {
        "operation_id": operation_id,
        "session_id": session_id,
        "harness": harness,
        "operation_type": operation_type,
        "status": status,
        "approval_request_ids": string_list(operation.get("approval_request_ids")),
        "resume_token": text_value(operation.get("resume_token")),
        "metadata": metadata,
        "now": now,
    }


def continuation_events(
    *,
    request_id: str,
    operation_id: str | None,
    action: ContinuationAction,
    offer: ContinuationOffer,
    result: ContinuationResult,
) -> list[tuple[str, dict[str, object]]]:
    events: list[tuple[str, dict[str, object]]] = [
        (
            "review.continuation.attempt",
            {
                "action": action,
                "capability": offer.capability,
                "correlationId": offer.correlation_id,
                "evidence_id": result.evidence_id,
                "harness": offer.harness,
                "request_id": request_id,
                "status": result.status,
            },
        )
    ]
    if result.status != "waiting":
        events.append(
            (
                "review.continuation.terminal",
                {
                    "correlationId": offer.correlation_id,
                    "evidence_id": result.evidence_id,
                    "request_id": request_id,
                    "status": result.status,
                },
            )
        )
    if offer.harness != "codex":
        events.append(
            (
                "harness/operation_resume",
                {
                    "action": "allow" if action == "allow_once" else "block",
                    "correlationId": offer.correlation_id,
                    "harness": offer.harness,
                    "operation_id": operation_id,
                    "request_id": request_id,
                    "status": public_status(result.status),
                },
            )
        )
    if result.status == "manual_retry_required":
        events.append(
            (
                "review.continuation.manual_retry_required",
                {
                    "correlationId": offer.correlation_id,
                    "evidence_id": result.evidence_id,
                    "harness": offer.harness,
                    "request_id": request_id,
                    "reason": result.reason,
                },
            )
        )
    return events


def parse_aware_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("continuation_time_invalid") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("continuation_time_invalid")
    return parsed.astimezone(timezone.utc)


def first_aware_timestamp(mapping: Mapping[str, object], keys: tuple[str, ...]) -> datetime | None:
    for key in keys:
        value = text_value(mapping.get(key))
        if value is None:
            continue
        try:
            return parse_aware_timestamp(value)
        except ValueError:
            continue
    return None


def mapping_value(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        return {}
    mapping = cast(Mapping[object, object], value)
    return {key: item for key, item in mapping.items() if isinstance(key, str)}


def mapping_list(value: object) -> list[Mapping[str, object]]:
    if not isinstance(value, list):
        return []
    return [mapping_value(cast(object, item)) for item in cast(list[object], value) if isinstance(item, Mapping)]


def string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in cast(list[object], value) if isinstance(item, str)]


def text_value(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def bounded_reason(value: str) -> str:
    return value[:128] if value else "continuation_failed"


def persisted_result_status(value: str | None) -> ContinuationStatus | None:
    if value not in _PERSISTED_STATUSES:
        return None
    return cast(ContinuationStatus, value)
