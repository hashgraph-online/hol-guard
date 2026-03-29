"""Skill security checks powered by Cisco skill-scanner."""

from __future__ import annotations

from pathlib import Path

from ..integrations.cisco_skill_scanner import (
    CiscoIntegrationStatus,
    CiscoSkillScanSummary,
    run_cisco_skill_scan,
)
from ..models import SEVERITY_ORDER, CheckResult, Finding, ScanOptions, Severity, max_severity
from .manifest import load_manifest


def _not_applicable_results(message: str) -> tuple[CheckResult, ...]:
    return (
        CheckResult(
            name="Cisco skill scan completed",
            passed=True,
            points=0,
            max_points=0,
            message=message,
            applicable=False,
        ),
        CheckResult(
            name="No elevated Cisco skill findings",
            passed=True,
            points=0,
            max_points=0,
            message=message,
            applicable=False,
        ),
        CheckResult(
            name="Skills analyzable",
            passed=True,
            points=0,
            max_points=0,
            message=message,
            applicable=False,
        ),
    )


def _elevated_findings(findings: tuple[Finding, ...]) -> tuple[Finding, ...]:
    return tuple(
        finding
        for finding in findings
        if SEVERITY_ORDER[finding.severity] >= SEVERITY_ORDER[Severity.MEDIUM]
    )


def _availability_check(summary: CiscoSkillScanSummary, mode: str) -> CheckResult:
    if summary.status in {CiscoIntegrationStatus.ENABLED, CiscoIntegrationStatus.SKIPPED}:
        return CheckResult(
            name="Cisco skill scan completed",
            passed=True,
            points=3 if summary.status == CiscoIntegrationStatus.ENABLED else 0,
            max_points=3 if summary.status == CiscoIntegrationStatus.ENABLED else 0,
            message=summary.message,
            applicable=summary.status == CiscoIntegrationStatus.ENABLED,
        )

    findings = ()
    if mode == "on":
        findings = (
            Finding(
                rule_id="CISCO-SCANNER-UNAVAILABLE",
                severity=Severity.LOW,
                category="skill-security",
                title="Cisco skill scanner unavailable",
                description=summary.message,
                remediation="Install the cisco extra or disable the Cisco scan requirement for this run.",
                source="cisco-skill-scanner",
            ),
        )
        return CheckResult(
            name="Cisco skill scan completed",
            passed=False,
            points=0,
            max_points=3,
            message=summary.message,
            findings=findings,
        )

    return CheckResult(
        name="Cisco skill scan completed",
        passed=True,
        points=3,
        max_points=3,
        message=summary.message,
    )


def _findings_check(summary: CiscoSkillScanSummary) -> CheckResult:
    if summary.status != CiscoIntegrationStatus.ENABLED:
        return CheckResult(
            name="No elevated Cisco skill findings",
            passed=True,
            points=0,
            max_points=0,
            message="Cisco scan not executed; elevated findings check not applicable.",
            applicable=False,
        )

    elevated = _elevated_findings(summary.findings)
    if not elevated:
        advisory_count = summary.total_findings
        if advisory_count:
            return CheckResult(
                name="No elevated Cisco skill findings",
                passed=True,
                points=8,
                max_points=8,
                message=f"Cisco scan found only advisory-level findings ({advisory_count}).",
                findings=summary.findings,
            )
        return CheckResult(
            name="No elevated Cisco skill findings",
            passed=True,
            points=8,
            max_points=8,
            message="Cisco scan found no elevated skill findings.",
        )

    severity = max_severity(elevated)
    top_titles = ", ".join(finding.title for finding in elevated[:3])
    return CheckResult(
        name="No elevated Cisco skill findings",
        passed=False,
        points=0,
        max_points=8,
        message=f"Elevated Cisco findings detected ({severity.value if severity else 'unknown'}): {top_titles}",
        findings=elevated,
    )


def _analyzability_check(summary: CiscoSkillScanSummary) -> CheckResult:
    if summary.status != CiscoIntegrationStatus.ENABLED:
        return CheckResult(
            name="Skills analyzable",
            passed=True,
            points=0,
            max_points=0,
            message="Cisco scan not executed; analyzability not applicable.",
            applicable=False,
        )

    if summary.skills_skipped:
        skipped = ", ".join(summary.skills_skipped[:3])
        return CheckResult(
            name="Skills analyzable",
            passed=False,
            points=0,
            max_points=4,
            message=f"Cisco skipped skills: {skipped}",
        )

    if summary.skills_scanned > 0:
        return CheckResult(
            name="Skills analyzable",
            passed=True,
            points=4,
            max_points=4,
            message=f"Cisco analyzed {summary.skills_scanned} skill(s).",
        )

    return CheckResult(
        name="Skills analyzable",
        passed=False,
        points=0,
        max_points=4,
        message="Cisco scan ran but did not analyze any skills.",
    )


def run_skill_security_checks(plugin_dir: Path, options: ScanOptions | None = None) -> tuple[CheckResult, ...]:
    """Run Cisco-backed skill security checks when the plugin declares skills."""

    scan_options = options or ScanOptions()
    manifest = load_manifest(plugin_dir)
    if manifest is None:
        return _not_applicable_results("plugin.json is unavailable; skill security checks skipped.")

    skills_path_value = manifest.get("skills")
    if not isinstance(skills_path_value, str) or not skills_path_value.strip():
        return _not_applicable_results("No skills declared in plugin.json.")

    skills_dir = (plugin_dir / skills_path_value).resolve()
    if not skills_dir.is_dir():
        return _not_applicable_results(f'Skills directory "{skills_path_value}" is missing; see best-practice checks.')

    summary = run_cisco_skill_scan(
        skills_dir=skills_dir,
        mode=scan_options.cisco_skill_scan,
        policy_name=scan_options.cisco_policy,
    )

    return (
        _availability_check(summary, scan_options.cisco_skill_scan),
        _findings_check(summary),
        _analyzability_check(summary),
    )
