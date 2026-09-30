"""Bounded background replay of requests affected by retry identity drift."""

from __future__ import annotations

from datetime import datetime, timezone

from ..store import GuardStore

_REPLAY_MARKER = "guard_cloud_review_retry_identity_replay"


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
    """Retain retryable results and quarantine immutable continuation mismatches.

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
        retained.append((sequence, result))
    return [sequence for sequence, _ in retained], [result for _, result in retained]
