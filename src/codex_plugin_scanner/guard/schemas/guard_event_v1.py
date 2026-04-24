"""Guard Cloud event schema shared by the edge runtime and v1 ingest API."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal, cast

GuardEventSource = Literal["edge", "approval-center", "policy", "protect-api"]
GuardEventType = Literal["receipt.created", "approval.created", "approval.resolved", "policy.changed"]


@dataclass(frozen=True, slots=True)
class GuardEventV1:
    """Versioned event envelope for replay-safe Guard Cloud sync."""

    event_id: str
    idempotency_key: str
    event_type: GuardEventType
    source: GuardEventSource
    occurred_at: str
    workspace_id: str | None = None
    device_id: str | None = None
    payload: dict[str, object] = field(default_factory=dict)
    schema_version: str = "guard.event.v1"

    def to_dict(self) -> dict[str, object]:
        return {
            "schemaVersion": self.schema_version,
            "eventId": self.event_id,
            "idempotencyKey": self.idempotency_key,
            "eventType": self.event_type,
            "source": self.source,
            "occurredAt": self.occurred_at,
            "workspaceId": self.workspace_id,
            "deviceId": self.device_id,
            "payload": self.payload,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, object]) -> GuardEventV1:
        schema_version = str(payload.get("schemaVersion") or "")
        if schema_version != "guard.event.v1":
            raise ValueError("Guard event schemaVersion must be guard.event.v1")
        event_id = _required_string(payload, "eventId")
        idempotency_key = _required_string(payload, "idempotencyKey")
        event_type = _required_string(payload, "eventType")
        source = _required_string(payload, "source")
        occurred_at = _required_string(payload, "occurredAt")
        event_payload = payload.get("payload")
        if not isinstance(event_payload, dict):
            raise ValueError("Guard event payload must be an object")
        if event_type not in {"receipt.created", "approval.created", "approval.resolved", "policy.changed"}:
            raise ValueError(f"Unsupported Guard event type: {event_type}")
        if source not in {"edge", "approval-center", "policy", "protect-api"}:
            raise ValueError(f"Unsupported Guard event source: {source}")
        workspace_id = payload.get("workspaceId")
        device_id = payload.get("deviceId")
        return cls(
            event_id=event_id,
            idempotency_key=idempotency_key,
            event_type=cast(GuardEventType, event_type),
            source=cast(GuardEventSource, source),
            occurred_at=occurred_at,
            workspace_id=workspace_id if isinstance(workspace_id, str) else None,
            device_id=device_id if isinstance(device_id, str) else None,
            payload={str(key): value for key, value in event_payload.items()},
        )


def _required_string(payload: dict[str, object], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Guard event {key} must be a non-empty string")
    return value
