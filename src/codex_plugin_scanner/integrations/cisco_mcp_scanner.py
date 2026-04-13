"""Cisco MCP scanner integration."""

from __future__ import annotations

import asyncio
import os
from collections.abc import Awaitable
from dataclasses import dataclass
from pathlib import Path
from threading import Thread
from typing import TypeVar

from ..models import Finding, Severity, severity_from_value
from .cisco_skill_scanner import CiscoIntegrationStatus

_EXCLUDED_DIRS = {
    ".codex-plugin",
    ".git",
    ".next",
    ".turbo",
    ".venv",
    "__pycache__",
    "coverage",
    "node_modules",
    "venv",
}
_SOURCE_SUFFIXES = {".cjs", ".js", ".json", ".jsx", ".mjs", ".py", ".ts", ".tsx"}
_MAX_TARGET_SIZE_BYTES = 1_000_000
T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class CiscoMcpScanSummary:
    """Normalized summary from a Cisco MCP scan run."""

    status: CiscoIntegrationStatus
    message: str
    findings: tuple[Finding, ...]
    targets_scanned: int
    analyzers_used: tuple[str, ...]
    total_findings: int
    findings_by_severity: dict[str, int]
    scan_mode: str = "static"


def _empty_counts() -> dict[str, int]:
    return {severity.value: 0 for severity in Severity}


def _build_summary(
    *,
    status: CiscoIntegrationStatus,
    message: str,
    findings: tuple[Finding, ...] = (),
    targets_scanned: int = 0,
    analyzers_used: tuple[str, ...] = (),
) -> CiscoMcpScanSummary:
    counts = _empty_counts()
    for finding in findings:
        counts[finding.severity.value] += 1
    return CiscoMcpScanSummary(
        status=status,
        message=message,
        findings=findings,
        targets_scanned=targets_scanned,
        analyzers_used=analyzers_used,
        total_findings=len(findings),
        findings_by_severity=counts,
    )


def _load_mcp_scanner_components() -> dict[str, object]:
    from mcpscanner import YaraAnalyzer

    return {"YaraAnalyzer": YaraAnalyzer}


def _relative_path(plugin_dir: Path, file_path: Path) -> str:
    try:
        return file_path.resolve().relative_to(plugin_dir.resolve()).as_posix()
    except ValueError:
        return file_path.as_posix()


def _normalize_rule_fragment(value: str) -> str:
    normalized = []
    for character in value.upper():
        normalized.append(character if character.isalnum() else "-")
    return "".join(normalized).strip("-") or "FINDING"


def _extract_rule_id(details: object, threat_category: str) -> str:
    if isinstance(details, dict):
        raw_response = details.get("raw_response")
        if isinstance(raw_response, dict):
            candidate = raw_response.get("rule")
            if isinstance(candidate, str) and candidate.strip():
                return f"CISCO-MCP-{_normalize_rule_fragment(candidate)}"
        candidate = details.get("threat_type")
        if isinstance(candidate, str) and candidate.strip():
            return f"CISCO-MCP-{_normalize_rule_fragment(candidate)}"
    return f"CISCO-MCP-{_normalize_rule_fragment(threat_category)}"


def _extract_description(summary: str, details: object) -> str:
    if isinstance(details, dict):
        evidence = details.get("evidence")
        if isinstance(evidence, str) and evidence.strip():
            return evidence.strip()
    return summary or "Cisco MCP scanner reported a potential issue."


def _extract_title(summary: str, threat_category: str) -> str:
    if summary:
        return summary
    return threat_category.replace("_", " ").title() or "Cisco MCP scanner finding"


def _normalize_finding(plugin_dir: Path, file_path: Path, finding: object) -> Finding:
    summary = str(getattr(finding, "summary", "") or "")
    details = getattr(finding, "details", {})
    threat_category = str(getattr(finding, "threat_category", "") or "mcp-security")
    return Finding(
        rule_id=_extract_rule_id(details, threat_category),
        severity=severity_from_value(str(getattr(finding, "severity", "info") or "info")),
        category="security",
        title=_extract_title(summary, threat_category),
        description=_extract_description(summary, details),
        file_path=_relative_path(plugin_dir, file_path),
        source="cisco-mcp-scanner",
    )


def _collect_static_targets(plugin_dir: Path) -> tuple[Path, ...]:
    config_path = plugin_dir / ".mcp.json"
    if not config_path.is_file():
        return ()

    targets: list[Path] = []
    try:
        if config_path.stat().st_size <= _MAX_TARGET_SIZE_BYTES:
            targets.append(config_path)
    except OSError:
        pass
    for root, dirs, files in os.walk(plugin_dir, topdown=True):
        dirs[:] = sorted(dir_name for dir_name in dirs if dir_name not in _EXCLUDED_DIRS)
        current_dir = Path(root)
        for file_name in sorted(files):
            file_path = current_dir / file_name
            if file_path == config_path or file_path.suffix.lower() not in _SOURCE_SUFFIXES:
                continue
            try:
                if file_path.stat().st_size > _MAX_TARGET_SIZE_BYTES:
                    continue
            except OSError:
                continue
            targets.append(file_path)
    return tuple(targets)


def _run_awaitable(awaitable: Awaitable[T]) -> T:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(awaitable)

    result: list[T] = []
    errors: list[BaseException] = []

    def _runner() -> None:
        try:
            result.append(asyncio.run(awaitable))
        except BaseException as exc:
            errors.append(exc)

    thread = Thread(target=_runner)
    thread.start()
    thread.join()
    if errors:
        raise errors[0]
    if result:
        return result[0]
    raise RuntimeError("Cisco MCP scanner completed without a result.")


async def _scan_targets(
    plugin_dir: Path, targets: tuple[Path, ...], analyzer: object
) -> tuple[tuple[Finding, ...], int]:
    findings: list[Finding] = []
    targets_scanned = 0
    for target in targets:
        try:
            content = target.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        content_type = "mcp-config" if target.name == ".mcp.json" else "mcp-source"
        external_findings = await analyzer.analyze(
            content,
            {
                "tool_name": target.name,
                "content_type": content_type,
                "file_path": str(target),
            },
        )
        targets_scanned += 1
        for finding in external_findings:
            findings.append(_normalize_finding(plugin_dir, target, finding))
    return tuple(findings), targets_scanned


def run_cisco_mcp_scan(plugin_dir: Path, mode: str = "auto") -> CiscoMcpScanSummary:
    """Run Cisco MCP scanner static analysis when available."""

    if mode == "off":
        return _build_summary(
            status=CiscoIntegrationStatus.SKIPPED,
            message="Cisco MCP scanning disabled by configuration.",
        )

    if not (plugin_dir / ".mcp.json").is_file():
        return _build_summary(
            status=CiscoIntegrationStatus.SKIPPED,
            message="No .mcp.json found; Cisco MCP scan skipped.",
        )

    try:
        components = _load_mcp_scanner_components()
    except ImportError:
        if mode == "on":
            return _build_summary(
                status=CiscoIntegrationStatus.UNAVAILABLE,
                message="Cisco MCP scanner is required but not installed. Ensure package dependencies are installed.",
            )
        return _build_summary(
            status=CiscoIntegrationStatus.UNAVAILABLE,
            message="Cisco MCP scanner not installed; deep MCP scan skipped.",
        )
    except Exception as exc:
        return _build_summary(
            status=CiscoIntegrationStatus.FAILED,
            message=f"Cisco MCP scanner failed to load: {exc}",
        )

    try:
        analyzer_class = components["YaraAnalyzer"]
        analyzer = analyzer_class()
        targets = _collect_static_targets(plugin_dir)
        findings, targets_scanned = _run_awaitable(_scan_targets(plugin_dir, targets, analyzer))
    except Exception as exc:
        return _build_summary(
            status=CiscoIntegrationStatus.FAILED,
            message=f"Cisco MCP scanner failed: {exc}",
        )

    if findings:
        message = (
            f"Cisco MCP scanner completed static analysis for {targets_scanned} target(s) "
            f"and reported {len(findings)} finding(s)."
        )
    else:
        message = f"Cisco MCP scanner completed static analysis for {targets_scanned} target(s) with no findings."
    return _build_summary(
        status=CiscoIntegrationStatus.ENABLED,
        message=message,
        findings=findings,
        targets_scanned=targets_scanned,
        analyzers_used=("yara",),
    )
