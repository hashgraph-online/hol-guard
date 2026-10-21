"""Cloud inventory events that keep each harness under its own agent type."""

from __future__ import annotations

import uuid
from collections.abc import Sequence

from .inventory_contract import GuardAgentInventorySnapshot, serialize_inventory_snapshot


def cloud_syncable_snapshots(
    snapshots: Sequence[GuardAgentInventorySnapshot],
) -> tuple[GuardAgentInventorySnapshot, ...]:
    """Every harness snapshot carries its own agent type, so none is held back."""
    return tuple(snapshots)


def inventory_snapshot_event(
    *,
    snapshot: GuardAgentInventorySnapshot,
    workspace_id: str,
    device_id: object,
    generated_at: str,
) -> dict[str, object]:
    """Create a cloud inventory event labelled with the snapshot's own agent type."""
    event_id = str(uuid.uuid4())
    return {
        "eventId": event_id,
        "eventType": "agent.inventory_snapshot",
        "idempotencyKey": snapshot.snapshot_id,
        "occurredAt": generated_at,
        "source": "edge",
        "workspaceId": workspace_id,
        "deviceId": device_id if isinstance(device_id, str) else None,
        "payload": {"snapshot": serialize_inventory_snapshot(snapshot)},
    }
