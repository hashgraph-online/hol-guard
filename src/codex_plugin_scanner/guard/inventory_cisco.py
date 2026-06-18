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
    remaining_timeout_seconds = timeout_seconds
    if mcp_mode != "off":
        mcp_started = time.perf_counter()
        runs.append(
            _run_mcp_inventory_scan(
                context=context,
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
                harness=harness,
                context=context,
                detection=detection,
                mode=skill_mode,
                timeout_seconds=remaining_timeout_seconds,
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
    if timeout_seconds is not None and timeout_seconds <= 0:
        return CiscoInventoryRun(
            source="cisco-mcp-scanner",
            status="timed_out",
            message="Cisco MCP inventory scan timed out before Guard could start it.",
            findings=(),
            duration_ms=0,
            metadata={"target": root.name, "targetsScanned": 0, "mode": mode},
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


def _build_skill_inventory_budget_exhausted_run(*, root: Path, mode: str) -> CiscoInventoryRun:
    return CiscoInventoryRun(
        source="cisco-skill-scanner",
        status="timed_out",
        message="Cisco skill scanner timed out before Guard could start this skill collection.",
        findings=(),
        duration_ms=0,
        metadata={
            "target": str(root),
            "skillsScanned": 0,
            "skillsSkipped": (),
            "totalFindings": 0,
            "findingsBySeverity": {},
            "analyzersUsed": (),
            "policyName": "balanced",
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
                    if (candidate / "SKILL.md").is_file():
                        return candidate
                    if _skill_dirs_under(candidate):
                        return candidate
    config_path = getattr(artifact, "config_path", None)
    if not isinstance(config_path, str):
        return None
    skill_path = Path(config_path)
    collection_root = _nearest_skill_collection_dir(skill_path)
    if collection_root is not None and collection_root.is_dir():
        return collection_root
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


def _nearest_skill_collection_dir(path: Path) -> Path | None:
    for parent in path.parents:
        if parent.name != "skills":
            continue
        if _skill_dirs_under(parent):
            return parent
    return None


def _consume_timeout_budget(
    timeout_seconds: float | None,
    *,
    started_at: float,
) -> float | None:
    if timeout_seconds is None:
        return None
    elapsed_seconds = max(time.perf_counter() - started_at, 0.0)
    return max(timeout_seconds - elapsed_seconds, 0.0)
