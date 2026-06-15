"""Local access graph snapshot event queueing for Guard Cloud."""

from __future__ import annotations

import json

from .edge_events import build_access_graph_snapshot_event
from .models import HarnessDetection
from .redaction import redact_sensitive_text
from .stable_digest import stable_digest_hex
from .store import GuardStore


def queue_access_graph_snapshot(
    *,
    store: GuardStore,
    detection: HarnessDetection,
    artifacts: list[dict[str, object]],
    now: str,
) -> None:
    workspace_id = store.get_cloud_workspace_id()
    device_id = store.get_or_create_installation_id()
    device_fingerprint = f"device:{device_id}"
    harness_fingerprint = f"harness:{detection.harness}"
    agent_id = f"{detection.harness}:local-agent"
    agent_fingerprint = f"agent:{agent_id}"
    entities: list[dict[str, object]] = []
    edges: list[dict[str, object]] = []
    seen_fingerprints: set[str] = set()

    def add_entity(entity: dict[str, object]) -> None:
        fingerprint = entity.get("fingerprint")
        if not isinstance(fingerprint, str) or fingerprint in seen_fingerprints:
            return
        seen_fingerprints.add(fingerprint)
        entities.append(entity)

    _add_device_harness_and_agent(
        add_entity=add_entity,
        edges=edges,
        device_id=device_id,
        device_fingerprint=device_fingerprint,
        detection=detection,
        harness_fingerprint=harness_fingerprint,
        agent_id=agent_id,
        agent_fingerprint=agent_fingerprint,
        now=now,
    )
    _add_artifact_entities(
        add_entity=add_entity,
        edges=edges,
        artifacts=artifacts,
        agent_fingerprint=agent_fingerprint,
        harness=detection.harness,
        agent_id=agent_id,
        now=now,
    )
    snapshot_seed = {
        "workspace": workspace_id,
        "device": device_id,
        "harness": detection.harness,
        "generatedAt": now,
    }
    snapshot_hash = stable_digest_hex(
        json.dumps(snapshot_seed, sort_keys=True).encode("utf-8"),
        length=24,
    )
    snapshot_id = f"access-graph-{snapshot_hash}"
    payload: dict[str, object] = {
        "snapshotId": snapshot_id,
        "generatedAt": now,
        "entities": entities,
        "edges": edges,
    }
    try:
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


def _add_device_harness_and_agent(
    *,
    add_entity,
    edges: list[dict[str, object]],
    device_id: str,
    device_fingerprint: str,
    detection: HarnessDetection,
    harness_fingerprint: str,
    agent_id: str,
    agent_fingerprint: str,
    now: str,
) -> None:
    add_entity(
        {
            "entityType": "device",
            "entityId": device_id,
            "displayName": "Local machine",
            "fingerprint": device_fingerprint,
            "metadata": {},
            "firstSeenAt": now,
            "lastSeenAt": now,
        }
    )
    add_entity(
        {
            "entityType": "harness",
            "entityId": detection.harness,
            "displayName": detection.harness,
            "fingerprint": harness_fingerprint,
            "metadata": {"installed": detection.installed, "commandAvailable": detection.command_available},
            "firstSeenAt": now,
            "lastSeenAt": now,
        }
    )
    edges.append(
        {
            "sourceFingerprint": device_fingerprint,
            "targetFingerprint": harness_fingerprint,
            "edgeType": "device_runs_harness",
            "confidence": 100,
            "metadata": {},
            "firstSeenAt": now,
            "lastSeenAt": now,
        }
    )
    add_entity(
        {
            "entityType": "agent",
            "entityId": agent_id,
            "displayName": f"{detection.harness} local agent",
            "fingerprint": agent_fingerprint,
            "metadata": {"harness": detection.harness},
            "firstSeenAt": now,
            "lastSeenAt": now,
        }
    )
    edges.append(
        {
            "sourceFingerprint": harness_fingerprint,
            "targetFingerprint": agent_fingerprint,
            "edgeType": "harness_runs_agent",
            "confidence": 90,
            "metadata": {},
            "firstSeenAt": now,
            "lastSeenAt": now,
        }
    )


def _add_artifact_entities(
    *,
    add_entity,
    edges: list[dict[str, object]],
    artifacts: list[dict[str, object]],
    agent_fingerprint: str,
    harness: str,
    agent_id: str,
    now: str,
) -> None:
    for artifact in artifacts:
        artifact_id = _non_empty_string(artifact.get("artifact_id"))
        if artifact_id is None:
            continue
        artifact_type = _non_empty_string(artifact.get("artifact_type")) or "tool"
        entity_type = _access_graph_entity_type(artifact_type)
        fingerprint = f"{entity_type}:{artifact_id}"
        add_entity(
            {
                "entityType": entity_type,
                "entityId": artifact_id,
                "displayName": _non_empty_string(artifact.get("artifact_name")) or artifact_id,
                "fingerprint": fingerprint,
                "metadata": {
                    "agentId": agent_id,
                    # agentType and harness both carry the harness slug for portal topology resolution.
                    "agentType": harness,
                    "artifactType": artifact_type,
                    "harness": harness,
                    "sourceScope": _non_empty_string(artifact.get("source_scope")),
                    "policyAction": _non_empty_string(artifact.get("policy_action")),
                    "present": artifact.get("removed") is not True,
                },
                "firstSeenAt": now,
                "lastSeenAt": now,
            }
        )
        edge_type = _access_graph_artifact_edge_type(entity_type)
        if edge_type is not None:
            edges.append(
                {
                    "sourceFingerprint": agent_fingerprint,
                    "targetFingerprint": fingerprint,
                    "edgeType": edge_type,
                    "confidence": 80,
                    "metadata": {},
                    "firstSeenAt": now,
                    "lastSeenAt": now,
                }
            )


def _access_graph_entity_type(artifact_type: str) -> str:
    if artifact_type in {"skill", "mcp_server", "tool", "repository", "agent", "policy", "integration"}:
        return artifact_type
    return "tool"


def _access_graph_artifact_edge_type(entity_type: str) -> str | None:
    if entity_type == "skill":
        return "agent_uses_skill"
    if entity_type == "mcp_server":
        return "agent_uses_mcp_server"
    return None


def _non_empty_string(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value
    return None
