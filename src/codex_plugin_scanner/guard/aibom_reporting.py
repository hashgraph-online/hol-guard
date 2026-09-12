"""Aibom reporting helpers preserving the public CLI dependency seams."""

from __future__ import annotations

import html
import re
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from .adapters.base import HarnessContext
from .inventory_contract import (
    GuardAgentInventorySnapshot,
)


def summarize_aibom_layers(
    snapshots: tuple[GuardAgentInventorySnapshot, ...],
    *,
    generated_at: str,
) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    """Count evidence by layer without discarding artifacts from other providers."""
    from . import aibom_cli as api

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
    drift = api.summarize_aibom_drift(snapshots)
    trust = api.summarize_aibom_trust(snapshots)
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
    """Summarize recorded trust evidence without inventing unavailable assessments."""
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
    """Report changed artifacts from the current stored inventory view."""
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
    """Index snapshot metadata for joining local stored artifact rows."""
    from . import aibom_cli as api

    lookup: dict[tuple[str, str], dict[str, object]] = {}
    for snapshot in snapshots:
        harness = snapshot.agent_type
        for item in snapshot.items:
            extensions = api.extract_aibom_metadata_extensions(item.metadata)
            if not extensions:
                continue
            lookup[(harness, item.item_id)] = extensions
    return lookup


def _artifact_rows_from_store(
    store: Any,
    snapshots: tuple[GuardAgentInventorySnapshot, ...],
    *,
    context: HarnessContext,
    generated_at: str,
) -> list[dict[str, object]]:
    """Combine stored artifact rows with available snapshot metadata."""
    from . import aibom_cli as api

    metadata_by_artifact = api._metadata_lookup_from_snapshots(snapshots)
    artifacts: list[dict[str, object]] = []
    for item in store.list_inventory():
        trust_verdict = str(item.get("last_policy_action") or "unknown")
        harness = str(item.get("harness") or "")
        artifact_id = str(item.get("artifact_id") or "")
        row = api._redact_inventory_store_item(item, home_dir=context.home_dir)
        row["trust_verdict"] = trust_verdict
        extensions = metadata_by_artifact.get((harness, artifact_id))
        config_path = api._store_row_config_path(item) if str(item.get("artifact_type") or "") == "skill_file" else None
        config_path_exists = config_path.exists() if config_path is not None else None
        if not extensions:
            extensions = api._store_only_artifact_metadata_extensions(
                row,
                context=context,
                generated_at=generated_at,
                config_path=config_path,
                config_path_exists=config_path_exists,
            )
            if config_path_exists is False:
                row["present"] = False
        if extensions:
            row.update(extensions)
        artifacts.append(row)
    return artifacts


def _store_row_config_path(row: dict[str, object]) -> Path | None:
    """Read a stored configuration path only when it has the expected shape."""
    raw_config_path = row.get("config_path")
    if not isinstance(raw_config_path, str) or not raw_config_path.strip():
        return None
    return Path(raw_config_path).expanduser()


def _store_only_artifact_metadata_extensions(
    row: dict[str, object],
    *,
    context: HarnessContext,
    generated_at: str,
    config_path: Path | None,
    config_path_exists: bool | None,
) -> dict[str, object]:
    """Build metadata extensions for artifacts known only to the local store."""
    from . import aibom_cli as api

    artifact_type = str(row.get("artifact_type") or "")
    if artifact_type != "skill_file":
        return {}
    if config_path is None or config_path_exists is not True:
        return {}
    artifact = SimpleNamespace(
        artifact_id=str(row.get("artifact_id") or ""),
        artifact_type=artifact_type,
        config_path=str(config_path),
        name=str(row.get("artifact_name") or row.get("artifact_id") or "skill_file"),
    )
    metadata = api.apply_local_trust_metadata(
        artifact,
        captured_at=generated_at,
        item_kind="skill",
        metadata={"artifactType": artifact_type},
        workspace_dir=context.workspace_dir,
    )
    return api.extract_aibom_metadata_extensions(metadata)


def _aggregate_redaction_report(
    snapshots: tuple[GuardAgentInventorySnapshot, ...],
) -> dict[str, object]:
    """Combine per-snapshot redaction counts without exposing redacted values."""
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
    """Redact local paths before emitting a stored inventory row."""
    from . import aibom_cli as api

    redacted = dict(item)
    config_path = item.get("config_path")
    if isinstance(config_path, str) and config_path:
        redacted["config_path"] = api.redact_local_path(Path(config_path), home_dir=home_dir)
    launch_command = item.get("launch_command")
    if isinstance(launch_command, str):
        from .inventory_contract import _redact_command_value

        redacted["launch_command"] = _redact_command_value(launch_command, home_dir, None)
    return redacted


def _aibom_connection_status(store: Any) -> str:
    """Resolve the cloud connection summary through the existing runtime interface."""
    from . import aibom_cli as api

    if store.get_cloud_sync_profile() is None:
        return "not_connected"
    if store.get_cloud_workspace_id() is None:
        return "workspace_required"
    sync_summary = api._sync_summary(store)
    if sync_summary.get("synced") is True and sync_summary.get("synced_at"):
        return "synced"
    return "sync_required"


def _markdown_table_cell(value: object) -> str:
    """Keep untrusted text literal and confined to one Markdown table cell."""
    text = html.escape(" ".join(str(value).splitlines()), quote=False)
    return re.sub(r"([\\|`*_\[\]()!~])", r"\\\1", text)


def _render_aibom_markdown(payload: dict[str, object]) -> str:
    """Render the redacted inventory report as human-readable Markdown."""
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
            cells = [
                _markdown_table_cell(item.get(field, ""))
                for field in ("artifact_name", "harness", "artifact_type", "source_scope", "trust_verdict")
            ]
            cells.append("yes" if item.get("present") else "no")
            lines.append("| " + " | ".join(cells) + " |")
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
