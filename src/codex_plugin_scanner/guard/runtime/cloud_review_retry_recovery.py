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
