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

CiscoInventorySource = Literal["cisco-mcp-scanner", "cisco-skill-scanner"]


@dataclass(frozen=True, slots=True)
class CiscoInventoryRun:
    source: CiscoInventorySource
    status: str
    message: str
    findings: tuple[Finding, ...]
    duration_ms: int
    metadata: dict[str, object]


def run_cisco_inventory_scans(
    *,
    harness: str,
    context: HarnessContext,
    detection: object,
    mcp_mode: str = "off",
    skill_mode: str = "off",
    timeout_seconds: float | None = None,
) -> tuple[CiscoInventoryRun, ...]:
    runs: list[CiscoInventoryRun] = []
    if mcp_mode != "off":
        runs.append(_run_mcp_inventory_scan(context=context, mode=mcp_mode, timeout_seconds=timeout_seconds))
    if skill_mode != "off":
        runs.extend(
            _run_skill_inventory_scans(
                harness=harness,
                context=context,
                detection=detection,
                mode=skill_mode,
                timeout_seconds=timeout_seconds,
            )
        )
    return tuple(runs)


def _run_mcp_inventory_scan(
    *,
    context: HarnessContext,
    mode: str,
    timeout_seconds: float | None,
) -> CiscoInventoryRun:
    root = _mcp_scan_root(context)
    if root is None:
        return CiscoInventoryRun(
            source="cisco-mcp-scanner",
            status="skipped",
            message="No .mcp.json found; Cisco MCP inventory scan skipped.",
            findings=(),
            duration_ms=0,
            metadata={"target": "missing", "targetsScanned": 0, "mode": mode},
        )
    started = time.perf_counter()
    summary = run_cisco_mcp_scan(root, mode=mode, timeout_seconds=timeout_seconds)
    duration_ms = int((time.perf_counter() - started) * 1000)
    return CiscoInventoryRun(
        source="cisco-mcp-scanner",
        status=str(summary.status.value),
        message=summary.message,
        findings=summary.findings,
        duration_ms=duration_ms,
        metadata={
            "target": root.name,
            "targetsScanned": summary.targets_scanned,
            "totalFindings": summary.total_findings,
            "findingsBySeverity": summary.findings_by_severity,
            "analyzersUsed": summary.analyzers_used,
            "scanMode": summary.scan_mode,
            "mode": mode,
        },
    )


def _run_skill_inventory_scans(
    *,
    harness: str,
    context: HarnessContext,
    detection: object,
    mode: str,
    timeout_seconds: float | None,
) -> tuple[CiscoInventoryRun, ...]:
    roots = _skill_scan_roots(harness=harness, context=context, detection=detection)
    if not roots:
        return (
            CiscoInventoryRun(
                source="cisco-skill-scanner",
                status="skipped",
                message="No skill directory found; Cisco skill inventory scan skipped.",
                findings=(),
                duration_ms=0,
                metadata={"target": "missing", "skillsScanned": 0, "mode": mode},
            ),
        )
    return tuple(
        _run_single_skill_inventory_scan(
            root=root,
            mode=mode,
            timeout_seconds=timeout_seconds,
        )
        for root in roots
    )


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
        metadata={
            "target": str(root),
            "skillsScanned": summary.skills_scanned,
            "skillsSkipped": summary.skills_skipped,
            "totalFindings": summary.total_findings,
            "findingsBySeverity": summary.findings_by_severity,
            "analyzersUsed": summary.analyzers_used,
            "policyName": summary.policy_name,
            "mode": mode,
        },
    )


def _mcp_scan_root(context: HarnessContext) -> Path | None:
    candidates = []
    if context.workspace_dir is not None:
        candidates.append(context.workspace_dir)
    candidates.append(context.home_dir)
    for candidate in candidates:
        if (candidate / ".mcp.json").is_file():
            return candidate
    return None


def _skill_scan_roots(*, harness: str, context: HarnessContext, detection: object) -> tuple[Path, ...]:
    roots: list[Path] = []
    seen: set[str] = set()

    if harness == "hermes":
        hermes_skills = context.home_dir / ".hermes" / "skills"
        _extend_unique_skill_roots(roots, seen, _skill_dirs_under(hermes_skills))
        if roots:
            return tuple(roots)

    artifacts = tuple(getattr(detection, "artifacts", ()))
    for artifact in artifacts:
        artifact_type = str(getattr(artifact, "artifact_type", ""))
        if artifact_type not in {"skill", "skill_file"}:
            continue
        root = _artifact_skill_root(artifact, context=context)
        if root is not None:
            resolved = str(root.resolve())
            if resolved not in seen:
                seen.add(resolved)
                roots.append(root)
    return tuple(roots)


def _artifact_skill_root(artifact: object, *, context: HarnessContext) -> Path | None:
    metadata = getattr(artifact, "metadata", {})
    if isinstance(metadata, dict):
        skill_root = metadata.get("skill_root")
        if isinstance(skill_root, str):
            for base_dir in (context.workspace_dir, context.home_dir):
                if base_dir is None:
                    continue
                candidate = (base_dir / skill_root).resolve()
                if candidate.is_dir():
                    nested_skill_dirs = _skill_dirs_under(candidate)
                    if len(nested_skill_dirs) == 1:
                        return nested_skill_dirs[0]
                    if (candidate / "SKILL.md").is_file():
                        return candidate
    config_path = getattr(artifact, "config_path", None)
    if not isinstance(config_path, str):
        return None
    skill_path = Path(config_path)
    root = _nearest_skill_dir(skill_path)
    if root is not None and root.is_dir():
        return root
    if skill_path.is_dir() and (skill_path / "SKILL.md").is_file():
        return skill_path
    return None


def _extend_unique_skill_roots(roots: list[Path], seen: set[str], candidates: tuple[Path, ...]) -> None:
    for candidate in candidates:
        resolved = str(candidate.resolve())
        if resolved in seen:
            continue
        seen.add(resolved)
        roots.append(candidate)


def _skill_dirs_under(root: Path) -> tuple[Path, ...]:
    if not root.is_dir():
        return ()
    skill_dirs = sorted({path.parent.resolve() for path in root.rglob("SKILL.md") if path.is_file()})
    return tuple(skill_dirs)


def _nearest_skill_dir(path: Path) -> Path | None:
    if path.name == "SKILL.md":
        return path.parent
    for parent in path.parents:
        if (parent / "SKILL.md").is_file():
            return parent
    return None
