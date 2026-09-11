"""Consumer-compatible inventory events without relabeling local-only agents."""

from __future__ import annotations

import uuid
from collections.abc import Sequence

from .inventory_contract import GuardAgentInventorySnapshot, serialize_inventory_snapshot


def cloud_syncable_snapshots(
    snapshots: Sequence[GuardAgentInventorySnapshot],
) -> tuple[GuardAgentInventorySnapshot, ...]:
    """Paseo's composite stays local until the cloud consumer accepts its type.

    Native provider snapshots already carry the tools, policies and receipts.
    Do not mislabel a Paseo snapshot as a different cloud-supported agent type.
    """
    return tuple(snapshot for snapshot in snapshots if snapshot.agent_type != "paseo")


def inventory_snapshot_event(
    *,
    snapshot: GuardAgentInventorySnapshot,
    workspace_id: str,
    device_id: object,
    generated_at: str,
) -> dict[str, object]:
    """Create a cloud-compatible event and reject local-only composite inventories."""
    if snapshot.agent_type == "paseo":
        raise ValueError("Paseo composite inventory is local-only; sync its native provider inventories instead.")
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
