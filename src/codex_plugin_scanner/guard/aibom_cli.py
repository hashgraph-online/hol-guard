"""AIBOM CLI helpers for status, export, inventory enrichment, and cloud sync."""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .adapters.base import HarnessContext
from .consumer import detect_all
from .inventory_contract import (
    GuardAgentInventorySnapshot,
    extract_aibom_metadata_extensions,
    inventory_snapshot_from_detection,
    redact_local_path,
    serialize_inventory_snapshot,
)
from .store import GuardStore

AibomExportFormat = Literal["json", "markdown"]


@dataclass(frozen=True, slots=True)
class AibomCliOptions:
    include_symlinks: bool = True
    follow_unsafe_symlinks: bool = False


def collect_aibom_snapshots(
    context: HarnessContext,
    *,
    generated_at: str,
    options: AibomCliOptions | None = None,
) -> tuple[GuardAgentInventorySnapshot, ...]:
    resolved = options or AibomCliOptions()
    snapshots: list[GuardAgentInventorySnapshot] = []
    for detection in detect_all(context):
        if not detection.installed and not detection.artifacts:
            continue
        snapshots.append(
            inventory_snapshot_from_detection(
                detection,
                generated_at=generated_at,
                home_dir=context.home_dir,
                workspace_dir=context.workspace_dir,
                include_symlinks=resolved.include_symlinks,
                follow_unsafe_symlinks=resolved.follow_unsafe_symlinks,
            )
        )
    return tuple(snapshots)


def build_inventory_json_payload(
    store: GuardStore,
    context: HarnessContext,
    *,
    generated_at: str,
    options: AibomCliOptions | None = None,
) -> dict[str, object]:
    snapshots = collect_aibom_snapshots(context, generated_at=generated_at, options=options)
    metadata_by_artifact = _metadata_lookup_from_snapshots(snapshots)
    items: list[dict[str, object]] = []
    for item in store.list_inventory():
        enriched = _redact_inventory_store_item(item, home_dir=context.home_dir)
        artifact_id = str(item.get("artifact_id") or "")
        harness = str(item.get("harness") or "")
        extensions = metadata_by_artifact.get((harness, artifact_id))
        if extensions:
            enriched.update(extensions)
        items.append(enriched)
    redaction_report = _aggregate_redaction_report(snapshots)
    return {
        "generated_at": generated_at,
        "items": items,
        "snapshots": [serialize_inventory_snapshot(snapshot) for snapshot in snapshots],
        "redaction_report": redaction_report,
    }


def build_aibom_status_payload(
    store: GuardStore,
    context: HarnessContext,
    *,
    generated_at: str,
    options: AibomCliOptions | None = None,
) -> dict[str, object]:
    snapshots = collect_aibom_snapshots(context, generated_at=generated_at, options=options)
    sync_summary = _sync_summary(store)
    layer_summary, trust_summary, drift_summary = summarize_aibom_layers(
        snapshots,
        generated_at=generated_at,
    )
    return {
        "generated_at": generated_at,
        "status": _aibom_connection_status(store),
        "layer_summary": layer_summary,
        "trust_summary": trust_summary,
        "drift_summary": drift_summary,
        "redaction_report": _aggregate_redaction_report(snapshots),
        "last_sync_at": sync_summary.get("synced_at"),
        "snapshot_count": len(snapshots),
        "artifact_inventory_count": len(store.list_inventory()),
    }


def build_aibom_export_payload(
    store: GuardStore,
    context: HarnessContext,
    *,
    generated_at: str,
    options: AibomCliOptions | None = None,
    export_format: AibomExportFormat = "json",
) -> dict[str, object]:
    snapshots = collect_aibom_snapshots(context, generated_at=generated_at, options=options)
    serialized_snapshots = [serialize_inventory_snapshot(snapshot) for snapshot in snapshots]
    artifacts = _artifact_rows_from_store(store, snapshots)
    layer_summary, trust_summary, drift_summary = summarize_aibom_layers(
        snapshots,
        generated_at=generated_at,
    )
    sync_summary = _sync_summary(store)
    payload: dict[str, object] = {
        "generated_at": generated_at,
        "artifact_count": len(artifacts),
        "artifacts": artifacts,
        "snapshots": serialized_snapshots,
        "layer_summary": layer_summary,
        "trust_summary": trust_summary,
        "drift_summary": drift_summary,
        "redaction_report": _aggregate_redaction_report(snapshots),
        "last_sync_at": sync_summary.get("synced_at"),
    }
    if export_format == "markdown":
        payload["markdown"] = _render_aibom_markdown(payload)
    return payload


def sync_aibom_snapshots(
    store: GuardStore,
    context: HarnessContext,
    *,
    generated_at: str,
    options: AibomCliOptions | None = None,
) -> dict[str, object]:
    from .runtime.runner import (
        GuardSyncNotConfiguredError,
        _guard_events_sync_url,
        _guard_sync_request,
        _resolve_guard_sync_auth_context,
        _urlopen_json_with_timeout_retry,
    )

    workspace_id = store.get_cloud_workspace_id()
    if workspace_id is None:
        raise GuardSyncNotConfiguredError("Guard Cloud workspace is not configured. Run `hol-guard connect` first.")

    snapshots = collect_aibom_snapshots(context, generated_at=generated_at, options=options)
    if not snapshots:
        synced_at = generated_at
        summary = {
            "synced": True,
            "synced_at": synced_at,
            "snapshots": 0,
            "accepted": 0,
            "message": "No installed harness snapshots were available to sync.",
        }
        store.set_sync_payload("aibom_sync_summary", summary, synced_at)
        return summary

    resolved_auth_context = _resolve_guard_sync_auth_context(store)
    sync_url = _guard_events_sync_url(str(resolved_auth_context["sync_url"]))
    events = [
        _inventory_snapshot_event(
            snapshot=snapshot,
            workspace_id=workspace_id,
            generated_at=generated_at,
        )
        for snapshot in snapshots
    ]
    body = json.dumps({"events": events}).encode("utf-8")
    request = _guard_sync_request(
        resolved_auth_context,
        request_url=sync_url,
        method="POST",
        data=body,
        extra_headers=None,
    )
    try:
        payload = _urlopen_json_with_timeout_retry(
            request=request,
            timeout_seconds=30,
            retry_timeout_seconds=60,
        )
    except OSError as error:
        raise RuntimeError("Guard Cloud AIBOM sync failed due to a network error.") from error
    accepted = payload.get("accepted")
    synced_at = _sync_timestamp_from_payload(payload) or generated_at
    summary = {
        "synced": True,
        "synced_at": synced_at,
        "snapshots": len(snapshots),
        "accepted": accepted if isinstance(accepted, int) else len(snapshots),
        "rejected": payload.get("rejected"),
        "statuses": payload.get("statuses"),
    }
    store.set_sync_payload("aibom_sync_summary", summary, synced_at)
    return summary


def summarize_aibom_layers(
    snapshots: tuple[GuardAgentInventorySnapshot, ...],
    *,
    generated_at: str,
) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    counts = {
        "instructions": 0,
        "skills": 0,
        "mcp": 0,
        "plugins": 0,
        "policies": 0,
        "findings": 0,
        "trust": 0,
        "sources": 0,
        "configSources": 0,
    }
    for snapshot in snapshots:
        counts["findings"] += len(snapshot.findings)
        counts["configSources"] += len(snapshot.sources)
        for item in snapshot.items:
            if item.item_kind in {"overlay", "prompt_pack"}:
                counts["instructions"] += 1
            elif item.item_kind == "skill":
                counts["skills"] += 1
            elif item.item_kind in {"mcp_server", "mcp_tool"}:
                counts["mcp"] += 1
            elif item.item_kind in {"plugin", "daemon_plugin"}:
                counts["plugins"] += 1
            elif item.item_kind == "policy":
                counts["policies"] += 1
            if isinstance(item.metadata.get("trustResolution"), dict):
                counts["trust"] += 1
            source_links = item.metadata.get("sourceLinks")
            source_of_truth = item.metadata.get("sourceOfTruth")
            if isinstance(source_links, list) and source_links:
                counts["sources"] += len(source_links)
            elif isinstance(source_of_truth, dict):
                counts["sources"] += 1
    drift = summarize_aibom_drift(snapshots)
    trust = summarize_aibom_trust(snapshots)
    layer_summary = {
        **counts,
        "driftCount": drift.get("total", 0),
        "highRiskCount": drift.get("high_risk", 0),
        "lowTrustCount": trust.get("low_trust", 0),
        "generatedAt": generated_at,
        "staleSnapshot": False,
    }
    return layer_summary, trust, drift


def summarize_aibom_trust(snapshots: tuple[GuardAgentInventorySnapshot, ...]) -> dict[str, object]:
    covered = 0
    eligible = 0
    low_trust = 0
    scores: list[int] = []
    for snapshot in snapshots:
        for item in snapshot.items:
            if item.item_kind not in {"skill", "plugin", "mcp_server"}:
                continue
            eligible += 1
            trust = item.metadata.get("trustResolution")
            if not isinstance(trust, dict):
                continue
            covered += 1
            score = trust.get("trustScore")
            if isinstance(score, int):
                scores.append(score)
                if score < 70:
                    low_trust += 1
    coverage_percent = round((covered / eligible) * 100) if eligible else 100
    average_score = round(sum(scores) / len(scores)) if scores else None
    return {
        "eligible": eligible,
        "covered": covered,
        "coverage_percent": coverage_percent,
        "low_trust": low_trust,
        "average_score": average_score,
    }


def summarize_aibom_drift(snapshots: tuple[GuardAgentInventorySnapshot, ...]) -> dict[str, object]:
    counts = {"new": 0, "changed": 0, "removed": 0, "unchanged": 0, "high_risk": 0}
    for snapshot in snapshots:
        for item in snapshot.items:
            state = item.drift_state
            if state in counts:
                counts[state] += 1
            if item.risk_level in {"critical", "high"}:
                counts["high_risk"] += 1
        for drift in snapshot.drift:
            state = drift.state
            if state in counts:
                counts[state] += 1
    total = counts["new"] + counts["changed"] + counts["removed"]
    return {
        "new": counts["new"],
        "changed": counts["changed"],
        "removed": counts["removed"],
        "unchanged": counts["unchanged"],
        "high_risk": counts["high_risk"],
        "total": total,
    }


def _metadata_lookup_from_snapshots(
    snapshots: tuple[GuardAgentInventorySnapshot, ...],
) -> dict[tuple[str, str], dict[str, object]]:
    lookup: dict[tuple[str, str], dict[str, object]] = {}
    for snapshot in snapshots:
        harness = snapshot.agent_type
        for item in snapshot.items:
            extensions = extract_aibom_metadata_extensions(item.metadata)
            if not extensions:
                continue
            lookup[(harness, item.item_id)] = extensions
    return lookup


def _artifact_rows_from_store(
    store: GuardStore,
    snapshots: tuple[GuardAgentInventorySnapshot, ...],
) -> list[dict[str, object]]:
    metadata_by_artifact = _metadata_lookup_from_snapshots(snapshots)
    artifacts: list[dict[str, object]] = []
    for item in store.list_inventory():
        trust_verdict = str(item.get("last_policy_action") or "unknown")
        harness = str(item.get("harness") or "")
        artifact_id = str(item.get("artifact_id") or "")
        row = {**item, "trust_verdict": trust_verdict}
        extensions = metadata_by_artifact.get((harness, artifact_id))
        if extensions:
            row.update(extensions)
        artifacts.append(row)
    return artifacts


def _aggregate_redaction_report(
    snapshots: tuple[GuardAgentInventorySnapshot, ...],
) -> dict[str, object]:
    redacted_fields: set[str] = set()
    raw_secrets = False
    symlink_items = 0
    for snapshot in snapshots:
        report = snapshot.redaction_report
        if report.get("rawSecretsIncluded") is True:
            raw_secrets = True
        fields = report.get("redactedFields")
        if isinstance(fields, (list, tuple)):
            redacted_fields.update(str(field) for field in fields)
        for item in snapshot.items:
            source_of_truth = item.metadata.get("sourceOfTruth")
            source_links = item.metadata.get("sourceLinks")
            if isinstance(source_of_truth, dict) or (isinstance(source_links, list) and source_links):
                symlink_items += 1
    return {
        "rawValuesIncluded": raw_secrets,
        "redactedFields": sorted(redacted_fields),
        "symlinkItems": symlink_items,
        "snapshots": len(snapshots),
    }


def _redact_inventory_store_item(
    item: dict[str, object],
    *,
    home_dir: Path,
) -> dict[str, object]:
    redacted = dict(item)
    config_path = item.get("config_path")
    if isinstance(config_path, str) and config_path:
        redacted["config_path"] = redact_local_path(Path(config_path), home_dir=home_dir)
    return redacted


def _aibom_connection_status(store: GuardStore) -> str:
    if store.get_cloud_sync_profile() is None:
        return "not_connected"
    if store.get_cloud_workspace_id() is None:
        return "workspace_required"
    sync_summary = _sync_summary(store)
    if sync_summary.get("synced_at"):
        return "synced"
    return "sync_required"


def _sync_summary(store: GuardStore) -> dict[str, object]:
    payload = store.get_sync_payload("aibom_sync_summary")
    return payload if isinstance(payload, dict) else {}


def _inventory_snapshot_event(
    *,
    snapshot: GuardAgentInventorySnapshot,
    workspace_id: str,
    generated_at: str,
) -> dict[str, object]:
    event_id = str(uuid.uuid4())
    return {
        "eventId": event_id,
        "eventType": "agent.inventory_snapshot",
        "idempotencyKey": snapshot.snapshot_id,
        "occurredAt": generated_at,
        "source": "edge",
        "workspaceId": workspace_id,
        "payload": {"snapshot": serialize_inventory_snapshot(snapshot)},
    }


def _sync_timestamp_from_payload(payload: dict[str, object]) -> str | None:
    for key in ("syncedAt", "synced_at", "acceptedAt"):
        value = payload.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _render_aibom_markdown(payload: dict[str, object]) -> str:
    layer_summary = payload.get("layer_summary")
    trust_summary = payload.get("trust_summary")
    lines = [
        "# HOL Guard AIBOM",
        "",
        "## Layer summary",
        "",
    ]
    if isinstance(layer_summary, dict):
        lines.extend(
            [
                f"- Instructions: {layer_summary.get('instructions', 0)}",
                f"- Skills: {layer_summary.get('skills', 0)}",
                f"- MCP: {layer_summary.get('mcp', 0)}",
                f"- Plugins: {layer_summary.get('plugins', 0)}",
                f"- Policies: {layer_summary.get('policies', 0)}",
                f"- Findings: {layer_summary.get('findings', 0)}",
                f"- Trust: {layer_summary.get('trust', 0)}",
                f"- Sources: {layer_summary.get('sources', 0)}",
                f"- Drift: {layer_summary.get('driftCount', 0)}",
                "",
            ]
        )
    lines.extend(
        [
            "## Artifacts",
            "",
            "| Artifact | Harness | Type | Scope | Verdict | Present |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
    )
    artifacts = payload.get("artifacts")
    if isinstance(artifacts, list):
        for item in artifacts:
            if not isinstance(item, dict):
                continue
            lines.append(
                "| "
                f"{item.get('artifact_name', '')} | {item.get('harness', '')} | {item.get('artifact_type', '')} | "
                f"{item.get('source_scope', '')} | {item.get('trust_verdict', '')} | "
                f"{'yes' if item.get('present') else 'no'} |"
            )
    if isinstance(trust_summary, dict):
        lines.extend(
            [
                "",
                "## Trust coverage",
                "",
                f"- Covered: {trust_summary.get('covered', 0)} / {trust_summary.get('eligible', 0)}",
                f"- Coverage: {trust_summary.get('coverage_percent', 0)}%",
                "",
            ]
        )
    return "\n".join(lines) + "\n"
