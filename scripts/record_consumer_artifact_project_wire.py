"""Artifact construction and wire helpers for the projection vector recorder."""

from __future__ import annotations

from typing import Any

from record_consumer_artifact_project_data import ID, PATH, SUMMARY_KEYS


def make(base: dict[str, Any], overrides: dict[str, Any] | None = None) -> Any:
    from codex_plugin_scanner.guard.models import GuardArtifact

    fields = {
        "artifact_id": ID,
        "name": "tool",
        "harness": "codex",
        "source_scope": "project",
        "config_path": PATH,
        **base,
        **(overrides or {}),
    }
    return GuardArtifact(**fields)


def wire_artifact(artifact: Any) -> dict[str, Any]:
    """The wire shape of the artifact, mirroring ``projection.wire_artifact``."""

    keys = (
        *SUMMARY_KEYS,
        "env_keys",
        "codex_hook_identity",
        "watch_only_observation",
        "watch_only_authoritative_action",
    )
    metadata = {key: artifact.metadata[key] for key in keys if key in artifact.metadata}
    rendered = {}
    for key in SUMMARY_KEYS:
        if key in metadata and not isinstance(metadata[key], str):
            rendered[key] = str(metadata.pop(key) or "")
    if rendered:
        metadata["capability_text_summaries"] = rendered
    if "mcp_tool_identity" in artifact.metadata:
        metadata["mcp_tool_identity"] = True
    return {
        "artifact_id": artifact.artifact_id,
        "name": artifact.name,
        "harness": artifact.harness,
        "artifact_type": artifact.artifact_type,
        "source_scope": artifact.source_scope,
        "config_path": artifact.config_path,
        "command": artifact.command,
        "args": list(artifact.args),
        "url": artifact.url,
        "transport": artifact.transport,
        "publisher": artifact.publisher,
        "metadata": metadata,
    }


class Store:
    def __init__(self, history: dict[str, Any]) -> None:
        self.history = history

    def find_inventory_item(self, _artifact_id: str) -> dict[str, Any] | None:
        return self.history["item"]

    def receipt_decision_counts(self, _harness: str, _artifact_id: str) -> dict[str, int]:
        return dict(self.history["counts"])

    def list_events(self, limit: int = 100) -> list[dict[str, Any]]:
        return list(self.history["events"])[:limit]

    def list_cached_advisories(self, limit: int = 100) -> list[dict[str, Any]]:
        return list(self.history["advisories"])[:limit]


def wire_history(history: dict[str, Any], publisher: str | None) -> dict[str, Any]:
    item = history["item"]
    wire_item = (
        {key: item[key] if isinstance(item.get(key), str) else None for key in ("first_seen_at", "last_seen_at")}
        if isinstance(item, dict)
        else None
    )
    names = [
        event["event_name"]
        for event in history["events"]
        if isinstance(event.get("payload"), dict)
        and event["payload"].get("artifact_id") == ID
        and isinstance(event.get("event_name"), str)
    ]
    advisories = [
        {
            "severity": str(item.get("severity", "")),
            "signature_verified": bool(item.get("signatureVerified")),
            "attestation_verified": bool(item.get("attestationVerified")),
            "advisory_id": str(item["advisoryId"])
            if isinstance(item.get("advisoryId"), str) and item["advisoryId"]
            else None,
        }
        for item in history["advisories"]
        if publisher is not None and item.get("publisher") == publisher
    ]
    return {
        "inventory_item": wire_item,
        "decision_counts": dict(history["counts"]),
        "event_names": names,
        "advisories": advisories,
    }


def snapshot(service: Any, before: Any, edit: str) -> dict[str, Any]:
    snapshot = {**service._serialize_artifact(before), "artifact_hash": service.artifact_hash(before)}
    if edit == "drop-env-keys":
        snapshot.pop("env_keys", None)
    elif edit == "drop-hash":
        snapshot.pop("artifact_hash")
    elif edit == "other-hash":
        snapshot["artifact_hash"] = "f" * 64
    elif edit == "hook-identity-drift":
        snapshot["metadata"] = {**snapshot["metadata"], "codex_hook_identity": "hook-1"}
    return snapshot
