"""Aibom sync helpers preserving the public CLI dependency seams."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

from .aibom_models import (
    _AIBOM_MAX_REQUEST_BODY_BYTES,
    _AIBOM_SYNC_BATCH_SIZE,
)


def _sync_summary(store: Any) -> dict[str, object]:
    """Return a typed view of the most recent stored AIBOM synchronization."""
    payload = store.get_sync_payload("aibom_sync_summary")
    return payload if isinstance(payload, dict) else {}


def _inventory_events_request_body(events: list[dict[str, object]]) -> bytes:
    """Serialize one bounded batch using the existing inventory event envelope."""
    return json.dumps({"events": events}).encode("utf-8")


def _batch_inventory_events(
    events: list[dict[str, object]],
    *,
    max_batch_size: int = _AIBOM_SYNC_BATCH_SIZE,
    max_body_bytes: int = _AIBOM_MAX_REQUEST_BODY_BYTES,
) -> tuple[list[list[dict[str, object]]], list[dict[str, object]]]:
    """Batch whole inventory snapshots without changing replacement semantics."""
    from . import aibom_cli as api

    if max_batch_size < 1 or max_body_bytes < 1:
        raise ValueError("AIBOM request batch limits must be positive.")

    serializer = api._inventory_events_request_body
    if serializer is not _inventory_events_request_body:
        # The public CLI seam can replace the envelope or encoding. Its byte
        # lengths need not be additive, so retain its original planning path.
        return _batch_inventory_events_with_serializer(
            events, serializer, max_batch_size=max_batch_size, max_body_bytes=max_body_bytes
        )

    # json.dumps uses the same encoding inside a singleton and a larger list.
    # Count each complete event once, then add the exact envelope and ", "
    # separators. Do not retain serialized bodies or split an atomic snapshot.
    envelope_bytes = len(b'{"events": []}')
    batches: list[list[dict[str, object]]] = []
    oversized_events: list[dict[str, object]] = []
    batch: list[dict[str, object]] = []
    batch_bytes = envelope_bytes
    for event in events:
        single_bytes = len(serializer([event]))
        if single_bytes > max_body_bytes:
            oversized_events.append(event)
            continue
        event_bytes = single_bytes - envelope_bytes
        candidate_bytes = batch_bytes + event_bytes + (2 if batch else 0)
        if batch and (len(batch) + 1 > max_batch_size or candidate_bytes > max_body_bytes):
            batches.append(batch)
            batch = []
            candidate_bytes = single_bytes
        batch.append(event)
        batch_bytes = candidate_bytes
    if batch:
        batches.append(batch)
    return batches, oversized_events


def _batch_inventory_events_with_serializer(
    events: list[dict[str, object]],
    serializer: Callable[[list[dict[str, object]]], bytes],
    *,
    max_batch_size: int,
    max_body_bytes: int,
) -> tuple[list[list[dict[str, object]]], list[dict[str, object]]]:
    """Preserve count-dependent custom request serializers at the CLI seam."""
    batches: list[list[dict[str, object]]] = []
    oversized_events: list[dict[str, object]] = []
    batch: list[dict[str, object]] = []
    for event in events:
        if len(serializer([event])) > max_body_bytes:
            oversized_events.append(event)
            continue

        candidate = [*batch, event]
        candidate_too_large = len(serializer(candidate)) > max_body_bytes
        if batch and (len(candidate) > max_batch_size or candidate_too_large):
            batches.append(batch)
            batch = [event]
        else:
            batch = candidate

    if batch:
        batches.append(batch)
    return batches, oversized_events


def _sync_timestamp_from_payload(payload: dict[str, object]) -> str | None:
    """Read a compatible acknowledgment timestamp without guessing one."""
    for key in ("syncedAt", "synced_at", "acceptedAt"):
        value = payload.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _accepted_snapshot_ids(
    batch: list[dict[str, object]],
    payload: dict[str, object],
) -> set[str]:
    """Map explicit or legacy aggregate event acknowledgments to accepted snapshots."""
    snapshot_by_event_id: dict[str, str] = {}
    for event in batch:
        event_id = event.get("eventId")
        event_payload = event.get("payload")
        snapshot_payload = event_payload.get("snapshot") if isinstance(event_payload, dict) else None
        snapshot_id = snapshot_payload.get("snapshotId") if isinstance(snapshot_payload, dict) else None
        if isinstance(event_id, str) and isinstance(snapshot_id, str):
            snapshot_by_event_id[event_id] = snapshot_id
    accepted_event_ids: set[str] = set()
    statuses = payload.get("statuses")
    if isinstance(statuses, list):
        for status in statuses:
            if not isinstance(status, dict) or status.get("status") != "accepted":
                continue
            event_id = status.get("eventId")
            if isinstance(event_id, str):
                accepted_event_ids.add(event_id)
    if not accepted_event_ids and payload.get("accepted") == len(batch):
        accepted_event_ids = set(snapshot_by_event_id)
    return {snapshot_by_event_id[event_id] for event_id in accepted_event_ids if event_id in snapshot_by_event_id}
