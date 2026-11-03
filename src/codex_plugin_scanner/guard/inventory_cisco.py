"""Cisco scanner bridge for Guard inventory snapshots."""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from ..integrations.cisco_mcp_scanner import run_cisco_mcp_scan
from ..integrations.cisco_skill_scanner import run_cisco_skill_scan
from ..models import Finding
from .adapters.base import HarnessContext
from .native_inventory_scan_targets import (
    CiscoMcpScanTarget,
    CiscoScanTargets,
    InventoryScanTargetsUnavailableError,
    native_inventory_scan_targets,
)

CiscoInventorySource = Literal["cisco-mcp-scanner", "cisco-skill-scanner"]


@dataclass(frozen=True, slots=True)
class CiscoInventoryRun:
    source: CiscoInventorySource
    status: str
    message: str
    findings: tuple[Finding, ...]
    duration_ms: int
    metadata: dict[str, object]


def _local_scanner_metadata(metadata: dict[str, object]) -> dict[str, object]:
    return {
        **metadata,
        "evidenceProvenance": "client_unverified",
        "scannerResolutionSource": "local_reported",
        "scannerVerificationRequired": "guard_cloud",
    }


def run_cisco_inventory_scans(
    *,
    harness: str,
    context: HarnessContext,
    detection: object,
    mcp_mode: str = "off",
    skill_mode: str = "off",
    timeout_seconds: float | None = None,
) -> tuple[CiscoInventoryRun, ...]:
    if mcp_mode == "off" and skill_mode == "off":
        return ()
    # Choosing the targets is part of the pass the caller gave a budget to, so
    # it is charged against that budget rather than taking a deadline of its
    # own and still handing the scanners the whole of it.
    pass_started = time.perf_counter()
    try:
        targets = _scan_targets(
            harness=harness,
            context=context,
            detection=detection,
            timeout_seconds=timeout_seconds,
        )
    except InventoryScanTargetsUnavailableError:
        return _unavailable_runs(mcp_mode=mcp_mode, skill_mode=skill_mode)

    runs: list[CiscoInventoryRun] = []
    remaining_timeout_seconds = _consume_timeout_budget(timeout_seconds, started_at=pass_started)
    if mcp_mode != "off":
        mcp_started = time.perf_counter()
        runs.extend(
            _run_mcp_inventory_scans(
                targets=targets.mcp_targets,
                mode=mcp_mode,
                timeout_seconds=remaining_timeout_seconds,
            )
        )
        remaining_timeout_seconds = _consume_timeout_budget(
            remaining_timeout_seconds,
            started_at=mcp_started,
        )
    if skill_mode != "off":
        runs.extend(
            _run_skill_inventory_scans(
                roots=targets.skill_roots,
                mode=skill_mode,
                timeout_seconds=remaining_timeout_seconds,
            )
        )
    return tuple(runs)


def _scan_targets(
    *,
    harness: str,
    context: HarnessContext,
    detection: object,
    timeout_seconds: float | None = None,
) -> CiscoScanTargets:
    """Ask the resident what this pass is allowed to read."""

    return native_inventory_scan_targets(
        harness=harness,
        home_dir=context.home_dir,
        workspace_dir=context.workspace_dir,
        artifacts=tuple(getattr(detection, "artifacts", ())),
        guard_home=getattr(context, "guard_home", None),
        timeout_seconds=timeout_seconds,
    )


def _unavailable_runs(*, mcp_mode: str, skill_mode: str) -> tuple[CiscoInventoryRun, ...]:
    """Report that the scan did not happen, rather than that it found nothing.

    Choosing the targets here instead would be the second implementation the
    op exists to remove, and reporting a clean pass would describe
    configurations nothing opened.
    """

    runs: list[CiscoInventoryRun] = []
    if mcp_mode != "off":
        runs.append(
            CiscoInventoryRun(
                source="cisco-mcp-scanner",
                status="unavailable",
                message=(
                    "Guard's native runtime could not choose the MCP configurations to scan; "
                    "Cisco MCP inventory scan did not run."
                ),
                findings=(),
                duration_ms=0,
                metadata=_local_scanner_metadata({"target": "unavailable", "targetsScanned": 0, "mode": mcp_mode}),
            )
        )
    if skill_mode != "off":
        runs.append(
            CiscoInventoryRun(
                source="cisco-skill-scanner",
                status="unavailable",
                message=(
                    "Guard's native runtime could not choose the skill collections to scan; "
                    "Cisco skill inventory scan did not run."
                ),
                findings=(),
                duration_ms=0,
                metadata=_local_scanner_metadata({"target": "unavailable", "skillsScanned": 0, "mode": skill_mode}),
            )
        )
    return tuple(runs)


def _run_mcp_inventory_scans(
    *,
    targets: tuple[CiscoMcpScanTarget, ...],
    mode: str,
    timeout_seconds: float | None,
) -> tuple[CiscoInventoryRun, ...]:
    if not targets:
        return (
            CiscoInventoryRun(
                source="cisco-mcp-scanner",
                status="skipped",
                message="No MCP configuration found; Cisco MCP inventory scan skipped.",
                findings=(),
                duration_ms=0,
                metadata=_local_scanner_metadata({"target": "missing", "targetsScanned": 0, "mode": mode}),
            ),
        )
    remaining_timeout_seconds = timeout_seconds
    runs: list[CiscoInventoryRun] = []
    for target in targets:
        if remaining_timeout_seconds is not None and remaining_timeout_seconds <= 0:
            runs.append(_build_mcp_inventory_budget_exhausted_run(target=target, mode=mode))
            continue
        started = time.perf_counter()
        runs.append(
            _run_single_mcp_inventory_scan(
                target=target,
                mode=mode,
                timeout_seconds=remaining_timeout_seconds,
            )
        )
        remaining_timeout_seconds = _consume_timeout_budget(
            remaining_timeout_seconds,
            started_at=started,
        )
    return tuple(runs)


def _run_single_mcp_inventory_scan(
    *,
    target: CiscoMcpScanTarget,
    mode: str,
    timeout_seconds: float | None,
) -> CiscoInventoryRun:
    started = time.perf_counter()
    summary = run_cisco_mcp_scan(
        target.root,
        mode=mode,
        timeout_seconds=timeout_seconds,
        config_path=target.config_path,
    )
    duration_ms = int((time.perf_counter() - started) * 1000)
    return CiscoInventoryRun(
        source="cisco-mcp-scanner",
        status=str(summary.status.value),
        message=summary.message,
        findings=summary.findings,
        duration_ms=duration_ms,
        metadata=_local_scanner_metadata(
            {
                "target": target.label,
                "_targetPath": str(target.root),
                "_configPath": str(target.config_path),
                "targetsScanned": summary.targets_scanned,
                "totalFindings": summary.total_findings,
                "findingsBySeverity": summary.findings_by_severity,
                "analyzersUsed": summary.analyzers_used,
                "scanMode": summary.scan_mode,
                "mode": mode,
            }
        ),
    )


def _build_mcp_inventory_budget_exhausted_run(*, target: CiscoMcpScanTarget, mode: str) -> CiscoInventoryRun:
    return CiscoInventoryRun(
        source="cisco-mcp-scanner",
        status="timed_out",
        message="Cisco MCP inventory scan timed out before Guard could start this configuration.",
        findings=(),
        duration_ms=0,
        metadata=_local_scanner_metadata(
            {
                "target": target.label,
                "_targetPath": str(target.root),
                "_configPath": str(target.config_path),
                "targetsScanned": 0,
                "mode": mode,
            }
        ),
    )


def _run_skill_inventory_scans(
    *,
    roots: tuple[Path, ...],
    mode: str,
    timeout_seconds: float | None,
) -> tuple[CiscoInventoryRun, ...]:
    if not roots:
        return (
            CiscoInventoryRun(
                source="cisco-skill-scanner",
                status="skipped",
                message="No skill directory found; Cisco skill inventory scan skipped.",
                findings=(),
                duration_ms=0,
                metadata=_local_scanner_metadata({"target": "missing", "skillsScanned": 0, "mode": mode}),
            ),
        )
    remaining_timeout_seconds = timeout_seconds
    runs: list[CiscoInventoryRun] = []
    for root in roots:
        if remaining_timeout_seconds is not None and remaining_timeout_seconds <= 0:
            runs.append(_build_skill_inventory_budget_exhausted_run(root=root, mode=mode))
            continue
        started = time.perf_counter()
        runs.append(
            _run_single_skill_inventory_scan(
                root=root,
                mode=mode,
                timeout_seconds=remaining_timeout_seconds,
            )
        )
        remaining_timeout_seconds = _consume_timeout_budget(
            remaining_timeout_seconds,
            started_at=started,
        )
    return tuple(runs)


def _run_single_skill_inventory_scan(
    *,
    root: Path,
    mode: str,
    timeout_seconds: float | None,
) -> CiscoInventoryRun:
    started = time.perf_counter()
    summary = run_cisco_skill_scan(root, mode=mode, timeout_seconds=timeout_seconds)
    duration_ms = int((time.perf_counter() - started) * 1000)
    return CiscoInventoryRun(
        source="cisco-skill-scanner",
        status=str(summary.status.value),
        message=summary.message,
        findings=summary.findings,
        duration_ms=duration_ms,
        metadata=_local_scanner_metadata(
            {
                "target": str(root),
                "skillsScanned": summary.skills_scanned,
                "skillsSkipped": summary.skills_skipped,
                "totalFindings": summary.total_findings,
                "findingsBySeverity": summary.findings_by_severity,
                "analyzersUsed": summary.analyzers_used,
                "policyName": summary.policy_name,
                "mode": mode,
            }
        ),
    )


def _build_skill_inventory_budget_exhausted_run(*, root: Path, mode: str) -> CiscoInventoryRun:
    return CiscoInventoryRun(
        source="cisco-skill-scanner",
        status="timed_out",
        message="Cisco skill scanner timed out before Guard could start this skill collection.",
        findings=(),
        duration_ms=0,
        metadata=_local_scanner_metadata(
            {
                "target": str(root),
                "skillsScanned": 0,
                "skillsSkipped": (),
                "totalFindings": 0,
                "findingsBySeverity": {},
                "analyzersUsed": (),
                "policyName": "balanced",
                "mode": mode,
            }
        ),
    )


def _consume_timeout_budget(
    timeout_seconds: float | None,
    *,
    started_at: float,
) -> float | None:
    if timeout_seconds is None:
        return None
    elapsed_seconds = max(time.perf_counter() - started_at, 0.0)
    return max(timeout_seconds - elapsed_seconds, 0.0)
