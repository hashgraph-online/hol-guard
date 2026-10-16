"""Public continuation carriers projected by the native authority."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
from typing import cast
from uuid import uuid4

from .continuation_contract import ContinuationAction, ContinuationOffer, ContinuationResult, ContinuationStatus
from .native_continuation_authority import continuation_authority, offer_wire, project, result_dto


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


def attempt_count(value: Mapping[str, object] | None) -> int:
    return continuation_authority("attempt", prior=value)["attempt_count"]


def previous_result(
    value: Mapping[str, object] | None, *, offer: ContinuationOffer, action: ContinuationAction
) -> ContinuationResult | None:
    return result_dto(continuation_authority("replay", prior=value, offer=offer_wire(offer), action=action)["result"])


def parse_aware_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("continuation_time_invalid") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("continuation_time_invalid")
    return parsed.astimezone(timezone.utc)


def mapping_value(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        return {}
    mapping = cast(Mapping[object, object], value)
    return {key: item for key, item in mapping.items() if isinstance(key, str)}


def text_value(value: object) -> str | None:
    return value.strip() if isinstance(value, str) and value.strip() else None


def bounded_reason(value: str) -> str:
    return value[:128] if value else "continuation_failed"
