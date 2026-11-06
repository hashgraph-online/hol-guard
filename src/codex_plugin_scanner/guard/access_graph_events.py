"""Local access graph snapshot event queueing for Guard Cloud."""

from __future__ import annotations

from .edge_events import build_access_graph_snapshot_event
from .models import HarnessDetection
from .redaction import redact_sensitive_text
from .store import GuardStore

# Artifact fields the resident reads; only string values travel.
_ARTIFACT_TEXT_FIELDS = ("artifact_id", "artifact_type", "artifact_name", "source_scope", "policy_action")


def queue_access_graph_snapshot(
    *,
    store: GuardStore,
    detection: HarnessDetection,
    artifacts: list[dict[str, object]],
    now: str,
) -> None:
    """Queue the detection's access graph; the resident builds its entities and edges."""

    workspace_id = store.get_cloud_workspace_id()
    device_id = store.get_or_create_installation_id()
    try:
        from .native_runner_authority import native_runner_authority

        answer = native_runner_authority(
            "access_graph_snapshot",
            {
                "harness": detection.harness,
                "installed": bool(detection.installed),
                "command_available": bool(detection.command_available),
                "workspace_id": workspace_id,
                "device_id": device_id,
                "now": now,
                "artifacts": [_artifact_fields(artifact) for artifact in artifacts],
            },
        )
        snapshot_id = answer["snapshot_id"]
        payload = answer["payload"]
        if not isinstance(snapshot_id, str) or not isinstance(payload, dict):
            raise ValueError("access_graph_snapshot answer is malformed")
        store.add_guard_event_v1(
            build_access_graph_snapshot_event(
                snapshot_id=snapshot_id,
                occurred_at=now,
                payload=payload,
                workspace_id=workspace_id,
                device_id=device_id,
            )
        )
    except Exception as error:
        store.add_event(
            "access_graph_snapshot_queue_failed",
            {
                "error_type": type(error).__name__,
                "message": redact_sensitive_text(str(error)),
            },
            now,
        )


def _artifact_fields(artifact: dict[str, object]) -> dict[str, object]:
    fields: dict[str, object] = {
        key: value for key in _ARTIFACT_TEXT_FIELDS if isinstance(value := artifact.get(key), str)
    }
    if artifact.get("removed") is True:
        fields["removed"] = True
    return fields
