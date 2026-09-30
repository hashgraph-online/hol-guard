"""Scanner results and symlink findings normalized into inventory evidence."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from .inventory_contract_fingerprints import fingerprint_mapping
from .inventory_contract_models import (
    GuardAgentInventoryFinding,
    GuardAgentInventoryItem,
    GuardInventorySource,
    InventoryFindingSource,
    InventorySeverity,
)
from .inventory_contract_redaction import _redact_known_path, _safe_finding_text, _safe_source_detail


def _cisco_inventory_findings(
    cisco_runs: tuple[object, ...],
    *,
    items: tuple[GuardAgentInventoryItem, ...],
    home_dir: Path,
    workspace_dir: Path | None,
) -> tuple[GuardAgentInventoryFinding, ...]:
    """Map optional scanner findings into the canonical inventory finding contract."""
    findings: list[GuardAgentInventoryFinding] = []
    seen: set[str] = set()
    for run in cisco_runs:
        source = _cisco_source(run)
        if source is None:
            continue
        run_status = str(getattr(run, "status", "unknown"))
        run_message = _safe_finding_text(
            str(getattr(run, "message", "")),
            home_dir=home_dir,
            workspace_dir=workspace_dir,
        )
        duration_ms = getattr(run, "duration_ms", None)
        for raw_finding in tuple(getattr(run, "findings", ()) or ()):
            rule_id = str(getattr(raw_finding, "rule_id", "cisco-finding") or "cisco-finding")
            title = _safe_finding_text(
                str(getattr(raw_finding, "title", "Cisco scanner finding") or "Cisco scanner finding"),
                home_dir=home_dir,
                workspace_dir=workspace_dir,
            )
            file_path = getattr(raw_finding, "file_path", None)
            safe_path = (
                _redact_known_path(str(file_path), home_dir, workspace_dir)
                if isinstance(file_path, str) and file_path
                else None
            )
            line_number = getattr(raw_finding, "line_number", None)
            finding_hash = fingerprint_mapping(
                {
                    "source": source,
                    "rule_id": rule_id,
                    "title": title,
                    "path": safe_path,
                    "line": line_number if isinstance(line_number, int) else None,
                }
            )
            finding_id = f"{source}:{rule_id}:{finding_hash[:16]}"
            if finding_id in seen:
                continue
            seen.add(finding_id)
            severity = _inventory_severity(getattr(raw_finding, "severity", "info"))
            findings.append(
                GuardAgentInventoryFinding(
                    finding_id=finding_id,
                    source=source,
                    severity=severity,
                    confidence="high" if run_status == "enabled" else "unknown",
                    title=title,
                    artifact_id=_artifact_id_for_cisco_finding(safe_path, items),
                    check_id=rule_id,
                    summary=_safe_finding_text(
                        str(getattr(raw_finding, "description", "") or ""),
                        home_dir=home_dir,
                        workspace_dir=workspace_dir,
                    ),
                    evidence={
                        "scannerStatus": run_status,
                        "scannerMessage": run_message,
                        "filePath": safe_path,
                        "lineNumber": line_number if isinstance(line_number, int) else None,
                        "durationMs": duration_ms if isinstance(duration_ms, int) else None,
                        "riskComponent": {
                            "source": source,
                            "severity": severity,
                            "confidence": "high" if run_status == "enabled" else "unknown",
                            "scoreDelta": _score_delta_for_severity(severity),
                        },
                    },
                )
            )
    return tuple(findings)


def _cisco_inventory_sources(cisco_runs: tuple[object, ...]) -> tuple[GuardInventorySource, ...]:
    """Record scanner sources and their availability alongside inventory evidence."""
    sources: list[GuardInventorySource] = []
    for run in cisco_runs:
        source = _cisco_source(run)
        if source is None:
            continue
        status = str(getattr(run, "status", "unknown"))
        detail = _safe_source_detail(run)
        sources.append(
            GuardInventorySource(
                source_id=f"{source}:{fingerprint_mapping({'status': status, 'detail': detail})[:12]}",
                source_type="scanner",
                status=_source_status_for_cisco_status(status),
                detail=detail,
            )
        )
    return tuple(sources)


def _cisco_source(run: object) -> InventoryFindingSource | None:
    """Build a source descriptor for one supported scanner."""
    source = str(getattr(run, "source", ""))
    if source == "cisco-mcp-scanner":
        return "cisco-mcp-scanner"
    if source == "cisco-skill-scanner":
        return "cisco-skill-scanner"
    return None


def _inventory_severity(value: object) -> InventorySeverity:
    """Normalize scanner severity without elevating unknown values."""
    severity_value = str(getattr(value, "value", value)).strip().lower()
    if severity_value == "critical":
        return "critical"
    if severity_value == "high":
        return "high"
    if severity_value == "medium":
        return "medium"
    if severity_value == "low":
        return "low"
    if severity_value == "info":
        return "info"
    return "info"


def _score_delta_for_severity(severity: InventorySeverity) -> int:
    """Map a finding severity to the established inventory score adjustment."""
    return {"critical": -40, "high": -25, "medium": -12, "low": -5, "info": 0}[severity]


def _artifact_id_for_cisco_finding(
    safe_path: str | None,
    items: tuple[GuardAgentInventoryItem, ...],
) -> str:
    """Associate a scanner finding with a known native artifact when possible."""
    if safe_path is None:
        return "unknown"
    for item in items:
        config_path = item.metadata.get("configPath")
        if isinstance(config_path, str) and (config_path == safe_path or config_path.endswith(safe_path)):
            return item.item_id
    return "unknown"


def _source_status_for_cisco_status(status: str) -> Literal["available", "missing", "failed"]:
    """Map scanner completion state to the public inventory source status."""
    if status == "enabled":
        return "available"
    if status in {"failed", "timed_out"}:
        return "failed"
    return "missing"


def _symlink_findings_from_items(
    harness: str,
    items: tuple[GuardAgentInventoryItem, ...],
) -> tuple[GuardAgentInventoryFinding, ...]:
    """Convert recorded symlink evidence into attributable inventory findings."""
    findings: list[GuardAgentInventoryFinding] = []
    for item in items:
        source_of_truth = item.metadata.get("sourceOfTruth")
        if not isinstance(source_of_truth, dict):
            continue
        validation_state = source_of_truth.get("validationState")
        if validation_state == "valid":
            continue
        if not isinstance(validation_state, str):
            continue
        severity: InventorySeverity = "high" if validation_state in {"loop", "escape_blocked"} else "medium"
        findings.append(
            GuardAgentInventoryFinding(
                finding_id=f"{harness}:symlink:{item.item_id}:{validation_state}",
                source="hol-detector",
                severity=severity,
                confidence="high",
                title=f"Symlink source {validation_state.replace('_', ' ')}",
                artifact_id=item.item_id,
                check_id=f"aibom.symlink.{validation_state}",
                summary=f"Inventory item references a symlink source in state {validation_state}.",
                evidence={
                    "validationState": validation_state,
                    "sourceFingerprint": source_of_truth.get("sourceFingerprint"),
                    "pathClass": source_of_truth.get("pathClass"),
                },
            )
        )
    return tuple(findings)
