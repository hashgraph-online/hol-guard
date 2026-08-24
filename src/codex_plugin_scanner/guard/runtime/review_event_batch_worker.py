"""Batch sizing, error classification, and timing for Review event delivery."""

from __future__ import annotations

import json
import random
import urllib.error
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Final

DEFAULT_REVIEW_EVENT_BATCH_SIZE: Final = 50
MAX_REVIEW_EVENT_BATCH_SIZE: Final = 250
DEFAULT_REVIEW_EVENT_BATCH_MAX_BYTES: Final = 256 * 1024
MAX_REVIEW_EVENT_BACKOFF_SECONDS: Final = 300.0


@dataclass(frozen=True)
class ReviewEventBatch:
    events: list[dict[str, object]]
    sequences: list[int]
    byte_size: int


def bounded_batch_size(value: object, *, fallback: int = DEFAULT_REVIEW_EVENT_BATCH_SIZE) -> int:
    """Accept only positive server hints inside the published client contract."""

    if isinstance(value, bool) or not isinstance(value, int):
        return fallback
    return max(1, min(value, MAX_REVIEW_EVENT_BATCH_SIZE))


def encoded_batch_size(events: list[dict[str, object]]) -> int:
    return len(json.dumps(events, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))


def take_bounded_batch(
    entries: list[tuple[int, dict[str, object]]],
    *,
    maximum_events: int,
    maximum_bytes: int,
) -> tuple[ReviewEventBatch, list[int]]:
    """Return the ordered sendable prefix and oversized row sequences.

    An individual event larger than the limit is never sent because a server can
    only reject it again. Later events remain eligible for future contiguous
    recovery after an operator retries the dead letter.
    """

    events: list[dict[str, object]] = []
    sequences: list[int] = []
    oversized: list[int] = []
    for sequence, event in entries:
        if len(events) >= maximum_events:
            break
        candidate = [*events, event]
        candidate_size = encoded_batch_size(candidate)
        if candidate_size > maximum_bytes:
            if not events:
                oversized.append(sequence)
            break
        events.append(event)
        sequences.append(sequence)
    return ReviewEventBatch(events=events, sequences=sequences, byte_size=encoded_batch_size(events)), oversized


def classify_review_event_sync_error(error: BaseException) -> str:
    """Map transport failures to stable, non-sensitive operational categories."""

    if isinstance(error, urllib.error.HTTPError):
        if error.code in {401, 403}:
            return "authorization"
        if error.code == 429:
            return "rate_limit"
        if error.code in {400, 404, 409, 410, 422}:
            return "schema" if error.code in {400, 404, 422} else "binding"
        return "server"
    if isinstance(error, (urllib.error.URLError, OSError, TimeoutError)):
        return "network"
    message = str(error).lower()
    if any(token in message for token in ("binding", "identity", "workspace", "installation", "subject")):
        return "binding"
    name = type(error).__name__.lower()
    if "authorization" in name or "oauth" in name or "token" in name:
        return "authorization"
    if "binding" in name or "identity" in name or "workspace" in name:
        return "binding"
    if "schema" in name or "contract" in name or "decode" in name or "json" in name:
        return "schema"
    return "server"


def next_review_event_backoff_seconds(
    failures: int,
    *,
    base_seconds: float = 1.0,
    maximum_seconds: float = MAX_REVIEW_EVENT_BACKOFF_SECONDS,
    jitter: float | None = None,
) -> float:
    """Return capped exponential backoff with bounded full jitter."""

    exponent = max(0, min(int(failures) - 1, 12))
    ceiling = min(maximum_seconds, max(0.0, base_seconds) * (2**exponent))
    return max(0.0, ceiling * (random.random() if jitter is None else max(0.0, min(jitter, 1.0))))


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def record_review_event_latency(
    state: dict[str, object],
    events: list[dict[str, object]],
    *,
    metric: str,
    now: str,
) -> None:
    """Accumulate bounded enqueue-to-send or enqueue-to-ack latency metrics."""

    sampled = [_event_latency_milliseconds(event, now) for event in events]
    values = [value for value in sampled if value is not None]
    if not values:
        return
    count_key = f"{metric}_sample_count"
    total_key = f"{metric}_total_ms"
    maximum_key = f"{metric}_max_ms"
    previous_count = _state_metric_value(state.get(count_key))
    previous_total = _state_metric_value(state.get(total_key))
    total = previous_total + sum(values)
    count = previous_count + len(values)
    state[count_key] = count
    state[total_key] = total
    state[f"{metric}_average_ms"] = total // count
    state[maximum_key] = max(_state_metric_value(state.get(maximum_key)), max(values))


def _event_latency_milliseconds(event: dict[str, object], now: str) -> int | None:
    occurred_at = event.get("occurredAt")
    if not isinstance(occurred_at, str):
        encoded_payload = event.get("eventPayloadJson")
        try:
            payload = json.loads(encoded_payload) if isinstance(encoded_payload, str) else None
        except json.JSONDecodeError:
            payload = None
        occurred_at = payload.get("occurredAt") if isinstance(payload, dict) else None
    if not isinstance(occurred_at, str):
        return None
    try:
        created = datetime.fromisoformat(occurred_at.replace("Z", "+00:00"))
        observed = datetime.fromisoformat(now.replace("Z", "+00:00"))
    except ValueError:
        return None
    if created.tzinfo is None or observed.tzinfo is None:
        return None
    return max(0, int((observed - created).total_seconds() * 1_000))


def _state_metric_value(value: object) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0
