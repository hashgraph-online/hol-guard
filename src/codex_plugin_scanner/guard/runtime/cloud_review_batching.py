"""Bounded batching policy for durable Cloud Review event delivery."""

from __future__ import annotations

from dataclasses import dataclass

from .cloud_review_event_delivery import encoded_review_events_payload

CLOUD_REVIEW_DEFAULT_BATCH_EVENTS = 50
CLOUD_REVIEW_MAX_BATCH_EVENTS = 250
CLOUD_REVIEW_MAX_BATCH_BYTES = 512 * 1024


@dataclass(frozen=True)
class CloudReviewBatchLimits:
    """Effective limits for one Cloud Review upload request."""

    events: int = CLOUD_REVIEW_DEFAULT_BATCH_EVENTS
    bytes: int = CLOUD_REVIEW_MAX_BATCH_BYTES


def select_review_event_batch(
    events: list[dict[str, object]],
    limits: CloudReviewBatchLimits,
) -> list[dict[str, object]]:
    """Return the largest ordered prefix that fits the effective limits."""
    selected: list[dict[str, object]] = []
    for event in events[: limits.events]:
        candidate = [*selected, event]
        if len(encoded_review_events_payload(candidate)) > limits.bytes:
            break
        selected = candidate
    if events and not selected:
        raise RuntimeError("A Cloud Review event exceeds the negotiated upload byte limit.")
    return selected


def next_review_batch_limits(
    current: CloudReviewBatchLimits,
    response: dict[str, object],
) -> CloudReviewBatchLimits:
    """Grow after success while honoring authenticated server-advertised caps."""
    server_events = _positive_int(response.get("maxBatchEvents"), CLOUD_REVIEW_MAX_BATCH_EVENTS)
    server_bytes = _positive_int(response.get("maxBatchBytes"), CLOUD_REVIEW_MAX_BATCH_BYTES)
    event_cap = min(server_events, CLOUD_REVIEW_MAX_BATCH_EVENTS)
    byte_cap = min(server_bytes, CLOUD_REVIEW_MAX_BATCH_BYTES)
    return CloudReviewBatchLimits(
        events=min(max(current.events * 2, CLOUD_REVIEW_DEFAULT_BATCH_EVENTS), event_cap),
        bytes=byte_cap,
    )


def _positive_int(value: object, fallback: int) -> int:
    return value if type(value) is int and value > 0 else fallback


__all__ = [
    "CLOUD_REVIEW_DEFAULT_BATCH_EVENTS",
    "CLOUD_REVIEW_MAX_BATCH_BYTES",
    "CLOUD_REVIEW_MAX_BATCH_EVENTS",
    "CloudReviewBatchLimits",
    "next_review_batch_limits",
    "select_review_event_batch",
]
