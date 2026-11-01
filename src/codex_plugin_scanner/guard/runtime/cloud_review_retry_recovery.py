"""Bounded background replay of requests affected by retry identity drift."""

from __future__ import annotations

from datetime import datetime, timezone

from ..store import GuardStore
from .cloud_request_native import cloud_error_texts

_REPLAY_MARKER = "guard_cloud_review_retry_identity_replay"
# Cloud stores these quarantines against the event id and never revalidates
# them, so every retry of the same event returns the same result.
_TERMINAL_QUARANTINE_CODES = frozenset({"review_event_runtime_grant_missing"})
# Cloud keeps the same stored quarantine for these codes once it has recorded
# them, so re-sending the unchanged event cannot succeed. Only a result whose
# status is "quarantined" is treated as that stored decision.
_STORED_QUARANTINE_CODES = frozenset(
    {
        "review_event_payload_hash_mismatch",
        "review_event_snapshot_claim_mismatch",
        "review_event_request_correlation_mismatch",
    }
)
# A newer snapshot event can heal these, but only while the local request is
# still pending and can be requeued.
_SNAPSHOT_REPAIR_CODES = frozenset({"review_event_snapshot_required", "missing_request_snapshot"})
_RETRY_EXHAUSTED_REASON = "review_event_retry_exhausted"
_REJECTION_COUNTS_KEY = "guard_cloud_review_rejection_counts"
# Server rejections tolerated for one event before it is dead-lettered locally.
MAX_REJECTED_DELIVERY_ATTEMPTS = 12


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


def recover_rejected_review_events(
    store: GuardStore,
    *,
    sequences: list[int],
    results: list[dict[str, object]],
    events: dict[int, dict[str, object]],
    binding: dict[str, str],
    acknowledged_through: object,
) -> tuple[list[int], list[dict[str, object]]]:
    collisions = {
        sequence: event_id
        for sequence, result in zip(sequences, results, strict=True)
        if result.get("code") == "review_event_snapshot_sequence_collision"
        and isinstance(event_id := result.get("eventId"), str)
        and event_id == events.get(sequence, {}).get("eventId")
    }
    repaired: dict[int, int] = {}
    # Zero is a valid Cloud high-water mark for a fresh rejected stream.
    if collisions and type(acknowledged_through) is int and 0 <= acknowledged_through <= 2**53 - 1:
        repaired = store.recover_review_snapshot_sequences(
            collisions=collisions, acknowledged_through=acknowledged_through, binding=binding
        )
    retained = [(s, r) for s, r in zip(sequences, results, strict=True) if s not in repaired]
    sequences, results = repair_retry_identity_failures(
        store, sequences=[s for s, _ in retained], results=[r for _, r in retained], binding=binding
    )
    return quarantine_terminal_binding_failures(
        store, sequences=sequences, results=results, events=events, binding=binding
    )


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


def repair_retry_identity_failures(
    store: GuardStore,
    *,
    sequences: list[int],
    results: list[dict[str, object]],
    binding: dict[str, str],
) -> tuple[list[int], list[dict[str, object]]]:
    repaired = {
        sequence
        for sequence, result in zip(sequences, results, strict=True)
        if result.get("code") == "review_event_canonical_correlation_required"
        and store.repair_rejected_review_correlation(
            event_sequence=sequence,
            binding=binding,
            changed_at=datetime.now(timezone.utc).isoformat(),
        )
        > 0
    }
    retained = [
        (sequence, result) for sequence, result in zip(sequences, results, strict=True) if sequence not in repaired
    ]
    return [sequence for sequence, _ in retained], [result for _, result in retained]


def quarantine_terminal_binding_failures(
    store: GuardStore,
    *,
    sequences: list[int],
    results: list[dict[str, object]],
    events: dict[int, dict[str, object]],
    binding: dict[str, str],
) -> tuple[list[int], list[dict[str, object]]]:
    """Retain retryable results and quarantine results Cloud will never change.

    A failed store transition stays retryable so concurrent delivery or a
    changed binding cannot silently discard unacknowledged evidence.
    Unknown event sequences also stay retryable instead of aborting the batch.
    """
    retained: list[tuple[int, dict[str, object]]] = []
    for sequence, result in zip(sequences, results, strict=True):
        event_type = events.get(sequence, {}).get("eventType")
        # A frozen terminal result cannot acquire a different continuation
        # binding through retries. Keep the rejected evidence unacknowledged.
        if (
            result.get("code") == "review_continuation_binding_mismatch"
            and isinstance(event_type, str)
            and event_type.startswith("continuation_")
            and store.quarantine_review_event(
                sequence,
                reason="review_continuation_binding_mismatch",
                error="Cloud rejected the immutable continuation binding; retained for diagnostics.",
                **binding,
            )
            > 0
        ):
            continue
        code = result.get("code")
        if (
            isinstance(code, str)
            and (
                code in _TERMINAL_QUARANTINE_CODES
                or (code in _STORED_QUARANTINE_CODES and result.get("status") == "quarantined")
                or (code in _SNAPSHOT_REPAIR_CODES and _snapshot_cannot_be_requeued(store, events, sequences, sequence))
            )
            and store.quarantine_review_event(
                sequence,
                reason=code,
                error="Cloud quarantined this event permanently; retained for diagnostics.",
                **binding,
            )
            > 0
        ):
            continue
        retained.append((sequence, result))
    return [sequence for sequence, _ in retained], [result for _, result in retained]


def _snapshot_cannot_be_requeued(
    store: GuardStore, events: dict[int, dict[str, object]], rejected: list[int], sequence: int
) -> bool:
    """True when no snapshot can reach Cloud for the request behind a rejection.

    Requeueing only repairs pending requests, so a resolved, expired, or
    missing request can only get the snapshot Cloud asks for from an event
    that is already queued for it. ``rejected`` are the sequences Cloud
    rejected in this batch; any other queued event of the request, for example
    one in backoff, may still carry that snapshot.
    """
    event = events.get(sequence)
    request_id = event.get("localRequestId") if isinstance(event, dict) else None
    if not isinstance(request_id, str) or not request_id:
        return False
    request = store.get_approval_request(request_id, derive_scope=False)
    if request is not None and request.get("status") == "pending":
        return False
    rejected_here = sum(1 for other in rejected if events.get(other, {}).get("localRequestId") == request_id)
    return len(store.list_review_event_snapshots(request_id)) <= rejected_here


def _load_rejection_counts(store: GuardStore) -> dict[str, int]:
    stored = store.get_sync_payload(f"{_REJECTION_COUNTS_KEY}:{store.guard_source}")
    if not isinstance(stored, dict):
        return {}
    return {
        name: value
        for name, value in stored.items()
        if isinstance(name, str) and name.isdecimal() and type(value) is int and value > 0
    }


def _save_rejection_counts(store: GuardStore, counts: dict[str, int], original: dict[str, int]) -> None:
    if counts != original:
        store.set_sync_payload(
            f"{_REJECTION_COUNTS_KEY}:{store.guard_source}", counts, datetime.now(timezone.utc).isoformat()
        )


def forget_rejection_counts(store: GuardStore, sequences: list[int]) -> None:
    """Drop the rejection counters of events that left the retry path."""
    counts = _load_rejection_counts(store)
    original = dict(counts)
    for sequence in sequences:
        counts.pop(str(sequence), None)
    _save_rejection_counts(store, counts, original)


def _is_uncounted_rejection(store: GuardStore, result: dict[str, object], event: dict[str, object] | None) -> bool:
    """True for a rejection that is not evidence the event can never be accepted.

    That is a per-event ``retryAfterMs`` hint, or a snapshot request for a
    request that is still pending, which the requeue repair resolves.
    """
    retry_after = result.get("retryAfterMs")
    if type(retry_after) is int and retry_after > 0:
        return True
    request_id = event.get("localRequestId") if isinstance(event, dict) else None
    if result.get("code") not in _SNAPSHOT_REPAIR_CODES or not isinstance(request_id, str) or not request_id:
        return False
    request = store.get_approval_request(request_id, derive_scope=False)
    return request is not None and request.get("status") == "pending"


def dead_letter_exhausted_review_events(
    store: GuardStore,
    *,
    sequences: list[int],
    results: list[dict[str, object]],
    events: dict[int, dict[str, object]],
    cleared: list[int],
    binding: dict[str, str],
) -> tuple[list[int], int]:
    """Quarantine events Cloud has rejected too many times; keep local evidence.

    ``sequences`` and ``results`` are the events Cloud rejected in this batch,
    and ``cleared`` are events that left the retry path another way. A result
    that asks for a later retry (``retryAfterMs``) or for a snapshot a pending
    request can still produce is not counted, and transport failures never
    reach this function, so an outage cannot dead-letter healthy events.
    Returns the sequences that stay retryable and the number dead-lettered.
    """
    counts = _load_rejection_counts(store)
    original = dict(counts)
    for sequence in cleared:
        counts.pop(str(sequence), None)
    retained: list[int] = []
    dead_lettered = 0
    for sequence, result in zip(sequences, results, strict=True):
        if _is_uncounted_rejection(store, result, events.get(sequence)):
            retained.append(sequence)
            continue
        attempts = counts.get(str(sequence), 0) + 1
        if attempts >= MAX_REJECTED_DELIVERY_ATTEMPTS and store.quarantine_review_event(
            sequence,
            reason=_RETRY_EXHAUSTED_REASON,
            error=f"Cloud rejected this event {attempts} times; retained for diagnostics.",
            **binding,
        ):
            counts.pop(str(sequence), None)
            dead_lettered += 1
            continue
        counts[str(sequence)] = attempts
        retained.append(sequence)
    _save_rejection_counts(store, counts, original)
    return retained, dead_lettered


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

    Returns the events that stay retryable with their results, and whether the
    batch made progress: Cloud accepted or acknowledged something, or a
    rejected event left the retry path.
    """
    retry_sequences, retry_results = recover_rejected_review_events(
        store,
        sequences=sequences,
        results=results,
        events=events,
        binding=binding,
        acknowledged_through=acknowledged_through,
    )
    resolved_locally = [sequence for sequence in sequences if sequence not in set(retry_sequences)]
    still_retryable, dead_lettered = dead_letter_exhausted_review_events(
        store,
        sequences=retry_sequences,
        results=retry_results,
        events=events,
        cleared=[*acknowledged, *resolved_locally],
        binding=binding,
    )
    retryable = set(still_retryable)
    kept = [(s, r) for s, r in zip(retry_sequences, retry_results, strict=True) if s in retryable]
    progressed = bool(acknowledged or resolved_locally or dead_lettered)
    return [s for s, _ in kept], [r for _, r in kept], progressed
