"""Bounded background replay of requests affected by retry identity drift."""

from __future__ import annotations

from datetime import datetime, timezone

from ..store import GuardStore
from .cloud_request_native import cloud_error_texts

_REPLAY_MARKER = "guard_cloud_review_retry_identity_replay"
# Read by tests; the native store owns the counters and the cap.
_REJECTION_COUNTS_KEY = "guard_cloud_review_rejection_counts"
MAX_REJECTED_DELIVERY_ATTEMPTS = 12
_RESULT_TEXT_FIELDS = ("code", "eventId", "status")
_EVENT_FIELDS = ("eventId", "eventType", "localRequestId")
# No known Cloud code or event id is longer; longer values never match.
_MAX_FIELD_CHARS = 512
_MAX_SAFE_STREAM_SEQUENCE = 2**53 - 1


def retry_result_message(items: list[dict[str, object]]) -> str:
    details: list[str] = []
    for item in items:
        detail = ": ".join(
            cloud_error_texts(
                [value for value in (item.get("code"), item.get("error")) if isinstance(value, str) and value.strip()]
            )
        )
        if detail and detail not in details:
            details.append(detail)
    message = f"{len(items)} Cloud Review events require retry."
    if details:
        return f"{message} Cloud reported: {'; '.join(details[:3])}."
    return message


def prepare_retry_identity_replay(store: GuardStore, *, binding: dict[str, str]) -> int:
    marker_key = f"{_REPLAY_MARKER}:{store.guard_source}"
    marker = store.get_sync_payload(marker_key)
    if isinstance(marker, dict) and marker.get("binding") == binding:
        return 0
    return store.requeue_pending_review_events_with_marker(
        changed_at=datetime.now(timezone.utc).isoformat(),
        marker_key=marker_key,
        marker_payload={"binding": binding},
        require_binding=True,
        only_retry_identity_drift=True,
    )


def _texts(source: dict[str, object], fields: tuple[str, ...]) -> dict[str, object]:
    return {
        field: value
        for field in fields
        if isinstance(value := source.get(field), str) and len(value) <= _MAX_FIELD_CHARS
    }


def forget_rejection_counts(store: GuardStore, sequences: list[int]) -> None:
    """Drop the rejection counters of events that left the retry path."""
    store.forget_review_rejection_counts(sequences=sequences, changed_at=datetime.now(timezone.utc).isoformat())


def settle_rejected_review_events(
    store: GuardStore,
    *,
    sequences: list[int],
    results: list[dict[str, object]],
    events: dict[int, dict[str, object]],
    acknowledged: list[int],
    acknowledged_through: object,
    binding: dict[str, str],
) -> tuple[list[int], list[dict[str, object]], bool]:
    """Repair, quarantine or dead-letter rejected events of one batch.

    The native store decides each rejection in one transaction. Returns the
    events that stay retryable with their results, and whether the batch made
    progress: Cloud accepted or acknowledged something, or a rejected event
    left the retry path.
    """
    rejected = set(sequences)
    projected = []
    for result in results:
        item = _texts(result, _RESULT_TEXT_FIELDS)
        retry_after = result.get("retryAfterMs")
        if type(retry_after) is int and retry_after > 0:
            item["retryAfterMs"] = min(retry_after, _MAX_SAFE_STREAM_SEQUENCE)
        projected.append(item)
    through = acknowledged_through
    retained, progressed = store.settle_rejected_review_events(
        sequences=sequences,
        results=projected,
        events=[[sequence, _texts(event, _EVENT_FIELDS)] for sequence, event in events.items() if sequence in rejected],
        acknowledged=acknowledged,
        acknowledged_through=through if type(through) is int and 0 <= through <= _MAX_SAFE_STREAM_SEQUENCE else None,
        binding=binding,
        changed_at=datetime.now(timezone.utc).isoformat(),
    )
    return [sequences[index] for index in retained], [results[index] for index in retained], progressed
