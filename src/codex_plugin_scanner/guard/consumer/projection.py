"""Store reads and resident queries for the consumer artifact projection.

Python reads the store and the harness and sends typed evidence. The resident
owns what that evidence means (capability delta, diff, history, provenance,
incident copy and the result rows), so nothing here interprets it.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from ..models import GuardArtifact
from ..native_consumer_artifact_project import native_consumer_project
from ..store import GuardStore

_METADATA_KEYS = (
    "request_summary",
    "runtime_request_summary",
    "prompt_summary",
    "env_keys",
    "codex_hook_identity",
    "watch_only_observation",
    "watch_only_authoritative_action",
)
_SUMMARY_KEYS = ("request_summary", "runtime_request_summary", "prompt_summary")
_EVENT_SCAN_LIMIT = 1000
_ADVISORY_SCAN_LIMIT = 200


def wire_artifact(artifact: GuardArtifact) -> dict[str, object]:
    """The artifact fields the capability and incident logic read."""

    metadata: dict[str, object] = {key: artifact.metadata[key] for key in _METADATA_KEYS if key in artifact.metadata}
    rendered: dict[str, str] = {}
    for key in _SUMMARY_KEYS:
        if key in metadata and not isinstance(metadata[key], str):
            # Launch and incident copy only ever used string summaries; the capability text
            # still saw Python's rendering, so that travels under its own key.
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


def _event_artifact_id(event: Mapping[str, object]) -> object:
    payload = event.get("payload")
    return payload.get("artifact_id") if isinstance(payload, dict) else None


def _history(store: GuardStore, harness: str, artifact_id: str, publisher: str | None) -> dict[str, object]:
    item = store.find_inventory_item(artifact_id)
    names = [
        event["event_name"]
        for event in store.list_events(limit=_EVENT_SCAN_LIMIT)
        if _event_artifact_id(event) == artifact_id and isinstance(event.get("event_name"), str)
    ]
    advisories = [
        {
            "severity": str(advisory.get("severity", "")),
            "signature_verified": bool(advisory.get("signatureVerified")),
            "attestation_verified": bool(advisory.get("attestationVerified")),
            "advisory_id": advisory["advisoryId"]
            if isinstance(advisory.get("advisoryId"), str) and advisory["advisoryId"]
            else None,
        }
        for advisory in (store.list_cached_advisories(limit=_ADVISORY_SCAN_LIMIT) if publisher is not None else ())
        if advisory.get("publisher") == publisher
    ]
    return {
        "inventory_item": (
            {key: item[key] if isinstance(item.get(key), str) else None for key in ("first_seen_at", "last_seen_at")}
            if isinstance(item, dict)
            else None
        ),
        "decision_counts": dict(store.receipt_decision_counts(harness, artifact_id)),
        "event_names": names,
        "advisories": advisories,
    }


def _home(store: GuardStore) -> Path | None:
    return getattr(store, "guard_home", None)


_NO_HISTORY: dict[str, object] = {
    "inventory_item": None,
    "decision_counts": {},
    "event_names": [],
    "advisories": [],
}


def artifact_evidence(
    store: GuardStore | None,
    artifact: GuardArtifact,
    *,
    payload: Mapping[str, object],
    content_hash: str,
    previous: Mapping[str, object] | None,
    with_history: bool = True,
    guard_home: Path | None = None,
) -> dict[str, Any]:
    """Diff, capability snapshot and delta, history and provenance of one artifact.

    ``store=None`` (a bare diff) and ``with_history=False`` (inventory-only
    skills, which never read history) send the empty history.
    """

    capabilities = store.get_artifact_capability(artifact.harness, artifact.artifact_id) if store is not None else None
    history = (
        _history(store, artifact.harness, artifact.artifact_id, artifact.publisher)
        if store is not None and with_history
        else dict(_NO_HISTORY)
    )
    return native_consumer_project(
        "artifact_evidence",
        {
            "artifact": wire_artifact(artifact),
            "current_payload": dict(payload),
            "payload_keys": list(payload),
            "current_hash": content_hash,
            "previous_snapshot": dict(previous) if previous is not None else None,
            "previous_capabilities": capabilities.to_dict() if capabilities is not None else None,
            "history": history,
        },
        guard_home=_home(store) if store is not None else guard_home,
    )


def artifact_result(
    store: GuardStore,
    harness: str,
    artifact: GuardArtifact,
    evidence: Mapping[str, object],
    **decision: object,
) -> dict[str, Any]:
    """Result row of a detected artifact."""

    return native_consumer_project(
        "artifact_result",
        {"harness": harness, "artifact": wire_artifact(artifact), "evidence": dict(evidence), **decision},
        guard_home=_home(store),
    )


def removed_result(store: GuardStore, harness: str, **fields: object) -> dict[str, Any]:
    """Receipt strings and result row of an artifact removed from the harness."""

    return native_consumer_project("removed_result", {"harness": harness, **fields}, guard_home=_home(store))


def incident_context(
    *,
    harness: str,
    artifact: GuardArtifact | None,
    changed_fields: Sequence[str],
    guard_home: Path | None = None,
    **fields: object,
) -> dict[str, str]:
    """Incident copy for one artifact decision."""

    answer = native_consumer_project(
        "incident_context",
        {
            "harness": harness,
            "artifact": wire_artifact(artifact) if artifact is not None else None,
            "changed_fields": list(changed_fields),
            **fields,
        },
        guard_home=guard_home,
    )
    return {key: str(value) for key, value in answer.items()}
