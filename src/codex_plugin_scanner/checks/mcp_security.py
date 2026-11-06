"""Cisco MCP security checks."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..integrations.cisco_mcp_scanner import CiscoMcpScanSummary, run_cisco_mcp_scan
from ..integrations.cisco_skill_scanner import CiscoIntegrationStatus
from ..models import SEVERITY_ORDER, CheckResult, Finding, ScanOptions, Severity, max_severity


@dataclass(frozen=True, slots=True)
class McpSecurityContext:
    """Resolved Cisco MCP scan context."""

    summary: CiscoMcpScanSummary | None
    skip_message: str | None = None
    target_present: bool = False


def _not_applicable_results(message: str) -> tuple[CheckResult, ...]:
    return (
        CheckResult(
            name="Cisco MCP scan completed",
            passed=True,
            points=0,
            max_points=0,
            message=message,
            applicable=False,
        ),
        CheckResult(
            name="No elevated Cisco MCP findings",
            passed=True,
            points=0,
            max_points=0,
            message=message,
            applicable=False,
        ),
        CheckResult(
            name="MCP sources analyzable",
            passed=True,
            points=0,
            max_points=0,
            message=message,
            applicable=False,
        ),
    )


def _elevated_findings(findings: tuple[Finding, ...]) -> tuple[Finding, ...]:
    threshold = SEVERITY_ORDER[Severity.MEDIUM]
    return tuple(finding for finding in findings if SEVERITY_ORDER[finding.severity] >= threshold)


def _availability_check(summary: CiscoMcpScanSummary, mode: str) -> CheckResult:
    if summary.status == CiscoIntegrationStatus.ENABLED:
        return CheckResult(
            name="Cisco MCP scan completed",
            passed=True,
            points=3,
            max_points=3,
            message=summary.message,
        )

    if summary.status == CiscoIntegrationStatus.SKIPPED:
        return CheckResult(
            name="Cisco MCP scan completed",
            passed=True,
            points=0,
            max_points=0,
            message=summary.message,
            applicable=False,
        )

    if mode == "on":
        rule_id = (
            "CISCO-MCP-SCANNER-FAILED"
            if summary.status == CiscoIntegrationStatus.FAILED
            else "CISCO-MCP-SCANNER-UNAVAILABLE"
        )
        findings = (
            Finding(
                rule_id=rule_id,
                severity=Severity.LOW,
                category="security",
                title="Cisco MCP scanner unavailable",
                description=summary.message,
                remediation="Install scanner dependencies or disable the Cisco MCP scan requirement for this run.",
                source="cisco-mcp-scanner",
            ),
        )
        return CheckResult(
            name="Cisco MCP scan completed",
            passed=False,
            points=0,
            max_points=3,
            message=summary.message,
            findings=findings,
        )

    return CheckResult(
        name="Cisco MCP scan completed",
        passed=True,
        points=0,
        max_points=0,
        message=summary.message,
        applicable=False,
    )


def _findings_check(summary: CiscoMcpScanSummary) -> CheckResult:
    if summary.status != CiscoIntegrationStatus.ENABLED:
        return CheckResult(
            name="No elevated Cisco MCP findings",
            passed=True,
            points=0,
            max_points=0,
            message="Cisco MCP scan not executed; elevated findings check not applicable.",
            applicable=False,
        )

    elevated = _elevated_findings(summary.findings)
    if not elevated:
        if summary.total_findings:
            return CheckResult(
                name="No elevated Cisco MCP findings",
                passed=True,
                points=6,
                max_points=6,
                message=f"Cisco MCP scan found only advisory-level findings ({summary.total_findings}).",
                findings=summary.findings,
            )
        return CheckResult(
            name="No elevated Cisco MCP findings",
            passed=True,
            points=6,
            max_points=6,
            message="Cisco MCP scan found no elevated findings.",
        )

    severity = max_severity(elevated)
    titles = ", ".join(finding.title for finding in elevated[:3])
    return CheckResult(
        name="No elevated Cisco MCP findings",
        passed=False,
        points=0,
        max_points=6,
        message=f"Elevated Cisco MCP findings detected ({severity.value if severity else 'unknown'}): {titles}",
        findings=summary.findings,
    )


def _analyzability_check(summary: CiscoMcpScanSummary) -> CheckResult:
    if summary.status != CiscoIntegrationStatus.ENABLED:
        return CheckResult(
            name="MCP sources analyzable",
            passed=True,
            points=0,
            max_points=0,
            message="Cisco MCP scan not executed; analyzability not applicable.",
            applicable=False,
        )

    if summary.targets_scanned > 0:
        return CheckResult(
            name="MCP sources analyzable",
            passed=True,
            points=3,
            max_points=3,
            message=f"Cisco MCP scanner analyzed {summary.targets_scanned} target(s).",
        )

    return CheckResult(
        name="MCP sources analyzable",
        passed=False,
        points=0,
        max_points=3,
        message="Cisco MCP scan ran but did not analyze any targets.",
    )


def resolve_mcp_security_context(plugin_dir: Path, options: ScanOptions | None = None) -> McpSecurityContext:
    """Resolve Cisco MCP security scan context for a plugin directory."""

    if not (plugin_dir / ".mcp.json").is_file():
        return McpSecurityContext(summary=None, skip_message="No .mcp.json found.", target_present=False)

    scan_options = options or ScanOptions()
    return McpSecurityContext(
        summary=run_cisco_mcp_scan(plugin_dir, scan_options.cisco_mcp_scan),
        target_present=True,
    )


def run_mcp_security_checks(
    plugin_dir: Path,
    options: ScanOptions | None = None,
    context: McpSecurityContext | None = None,
) -> tuple[CheckResult, ...]:
    """Run Cisco MCP checks for plugins that declare MCP configuration."""

    resolved_context = context or resolve_mcp_security_context(plugin_dir, options)
    if resolved_context.skip_message:
        return _not_applicable_results(resolved_context.skip_message)

    summary = resolved_context.summary
    if summary is None:
        return _not_applicable_results("Cisco MCP scan context unavailable.")

    scan_options = options or ScanOptions()
    return (
        _availability_check(summary, scan_options.cisco_mcp_scan),
        _findings_check(summary),
        _analyzability_check(summary),
    )
