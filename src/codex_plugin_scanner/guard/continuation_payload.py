"""Public continuation carriers projected by the native authority."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
from typing import cast
from uuid import uuid4

from .continuation_contract import ContinuationAction, ContinuationOffer, ContinuationResult, ContinuationStatus
from .native_continuation_authority import continuation_authority, offer_wire, project, result_dto

_PERSISTED_STATUSES = frozenset(
    {"resumed", "already_resumed", "manual_retry_required", "blocked_not_resumed", "unsupported", "failed", "waiting"}
)


def continuation_payload(offer: ContinuationOffer, result: ContinuationResult, *, replayed: bool) -> dict[str, object]:
    return project(offer, result)["replayed_payload" if replayed else "payload"]


def continuation_result(
    offer: ContinuationOffer, status: ContinuationStatus, reason: str, observed_at: str
) -> ContinuationResult:
    return ContinuationResult(
        offer.correlation_id,
        offer.capability,
        status,
        bounded_reason(reason),
        parse_aware_timestamp(observed_at),
        f"evidence-{uuid4().hex}",
    )


def offer_hash(offer: ContinuationOffer) -> str:
    return continuation_authority("identity", offer=offer_wire(offer))["offer_hash"]


def public_status(value: str) -> str:
    return continuation_authority("status", value=value)["status"]


def persisted_resume_status(offer: ContinuationOffer, result: ContinuationResult) -> str:
    return project(offer, result)["persisted_status"]


def public_reason(offer: ContinuationOffer, result: ContinuationResult) -> str:
    projected = project(offer, result)["payload"]
    return projected["codexResume" if offer.harness == "codex" else "harnessResume"]["reason"]


def public_message(offer: ContinuationOffer, result: ContinuationResult) -> str | None:
    projected = project(offer, result)["payload"]
    return projected["codexResume" if offer.harness == "codex" else "harnessResume"]["message"]


def continuation_strategy(offer: ContinuationOffer, result: ContinuationResult) -> str:
    return project(offer, result)["strategy"]


def attempt_count(value: Mapping[str, object] | None) -> int:
    return continuation_authority("attempt", prior=value)["attempt_count"]


def previous_result(
    value: Mapping[str, object] | None, *, offer: ContinuationOffer, action: ContinuationAction
) -> ContinuationResult | None:
    return result_dto(continuation_authority("replay", prior=value, offer=offer_wire(offer), action=action)["result"])


def operation_update_payload(
    operation: Mapping[str, object] | None, *, result: ContinuationResult, action: ContinuationAction, now: str
) -> dict[str, object] | None:
    offer = ContinuationOffer(
        result.correlation_id,
        "",
        result.capability,
        result.capability == "suspended-response",
        result.completed_at if result.capability == "suspended-response" else None,
        "target-transport" if result.capability == "session-resume" else None,
    )
    return project(offer, result, operation=operation, action=action, now=now)["operation_update"]


def continuation_events(
    *,
    request_id: str,
    operation_id: str | None,
    action: ContinuationAction,
    offer: ContinuationOffer,
    result: ContinuationResult,
) -> list[tuple[str, dict[str, object]]]:
    events = project(offer, result, operation={"operation_id": operation_id}, request_id=request_id, action=action)[
        "events"
    ]
    return [(name, payload) for name, payload in events]


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
