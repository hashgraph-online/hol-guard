"""Skill security checks powered by Cisco skill-scanner."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

from ..integrations.cisco_skill_scanner import (
    CiscoIntegrationStatus,
    CiscoSkillScanSummary,
    run_cisco_skill_scan,
)
from ..models import SEVERITY_ORDER, CheckResult, Finding, ScanOptions, Severity, max_severity
from .manifest import load_manifest


@dataclass(frozen=True, slots=True)
class SkillSecurityContext:
    summary: CiscoSkillScanSummary | None
    skills_dir: Path | None = None
    skip_message: str | None = None


_RISKY_SKILL_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"cat\s+\.env", re.IGNORECASE), "reads the local .env file"),
    (re.compile(r"curl\s+.*?https?://[^\s`\"']+", re.IGNORECASE), "sends workspace data to a remote endpoint"),
    (re.compile(r"wget\s+.*?https?://[^\s`\"']+", re.IGNORECASE), "downloads or sends data over the network"),
    (re.compile(r"\b(?:bash|sh)\s+-lc\b", re.IGNORECASE), "runs through a shell wrapper"),
    (re.compile(r"(?:~\/\.ssh|id_rsa|authorized_keys)", re.IGNORECASE), "references sensitive SSH material"),
)


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
    return tuple(finding for finding in findings if SEVERITY_ORDER[finding.severity] >= SEVERITY_ORDER[Severity.MEDIUM])


def _availability_check(summary: CiscoSkillScanSummary, mode: str) -> CheckResult:
    if summary.status == CiscoIntegrationStatus.ENABLED:
        return CheckResult(
            name="Cisco skill scan completed",
            passed=True,
            points=3,
            max_points=3,
            message=summary.message,
        )

    if summary.status == CiscoIntegrationStatus.SKIPPED:
        return CheckResult(
            name="Cisco skill scan completed",
            passed=True,
            points=0,
            max_points=0,
            message=summary.message,
            applicable=False,
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
                remediation="Install scanner dependencies or disable the Cisco scan requirement for this run.",
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
        points=0,
        max_points=0,
        message=summary.message,
        applicable=False,
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


def _relative_skill_path(plugin_dir: Path, skill_path: Path) -> str:
    try:
        return Path(os.path.relpath(skill_path, plugin_dir)).as_posix()
    except ValueError:
        return skill_path.as_posix()


def _local_skill_instruction_findings(plugin_dir: Path, skills_dir: Path) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    for skill_path in sorted(skills_dir.rglob("SKILL.md")):
        try:
            content = skill_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        relative_path = _relative_skill_path(plugin_dir, skill_path)
        for pattern, behavior in _RISKY_SKILL_PATTERNS:
            match = pattern.search(content)
            if match is None:
                continue
            findings.append(
                Finding(
                    rule_id="RISKY_SKILL_INSTRUCTION",
                    severity=Severity.HIGH,
                    category="skill-security",
                    title="Risky local skill instruction detected",
                    description=f'The skill includes "{match.group(0)}" and {behavior}.',
                    remediation=(
                        "Remove instructions that read sensitive local files, launch shell wrappers, "
                        "or send workspace data to remote endpoints."
                    ),
                    file_path=relative_path,
                )
            )
    return tuple(findings)


def _local_skill_instruction_check(plugin_dir: Path, skills_dir: Path | None) -> CheckResult:
    if skills_dir is None:
        return CheckResult(
            name="No risky local skill instructions",
            passed=True,
            points=0,
            max_points=0,
            message="No skills directory available for local skill review.",
            applicable=False,
        )

    findings = _local_skill_instruction_findings(plugin_dir, skills_dir)
    if not findings:
        return CheckResult(
            name="No risky local skill instructions",
            passed=True,
            points=5,
            max_points=5,
            message="No risky local skill instructions detected.",
        )

    return CheckResult(
        name="No risky local skill instructions",
        passed=False,
        points=0,
        max_points=5,
        message="Guard found risky local skill instructions that can expose secrets or contact remote endpoints.",
        findings=findings,
    )


def resolve_skill_security_context(plugin_dir: Path, options: ScanOptions | None = None) -> SkillSecurityContext:
    """Resolve Cisco skill scanning context for a plugin directory."""

    scan_options = options or ScanOptions()
    manifest = load_manifest(plugin_dir)
    if manifest is None:
        return SkillSecurityContext(
            summary=None,
            skills_dir=None,
            skip_message="plugin.json is unavailable; skill security checks skipped.",
        )

    skills_path_value = manifest.get("skills")
    if not isinstance(skills_path_value, str) or not skills_path_value.strip():
        return SkillSecurityContext(summary=None, skills_dir=None, skip_message="No skills declared in plugin.json.")

    skills_dir = (plugin_dir / skills_path_value).resolve()
    if not skills_dir.is_dir():
        return SkillSecurityContext(
            summary=None,
            skills_dir=skills_dir,
            skip_message=f'Skills directory "{skills_path_value}" is missing; see best-practice checks.',
        )

    return SkillSecurityContext(
        skills_dir=skills_dir,
        summary=run_cisco_skill_scan(
            skills_dir=skills_dir,
            mode=scan_options.cisco_skill_scan,
            policy_name=scan_options.cisco_policy,
        ),
    )


def run_skill_security_checks(
    plugin_dir: Path,
    options: ScanOptions | None = None,
    context: SkillSecurityContext | None = None,
) -> tuple[CheckResult, ...]:
    """Run Cisco-backed skill security checks when the plugin declares skills."""

    resolved_context = context or resolve_skill_security_context(plugin_dir, options)
    if resolved_context.skip_message:
        return _not_applicable_results(resolved_context.skip_message)

    summary = resolved_context.summary
    if summary is None:
        return _not_applicable_results("Cisco scan context unavailable.")

    scan_options = options or ScanOptions()
    return (
        _availability_check(summary, scan_options.cisco_skill_scan),
        _findings_check(summary),
        _analyzability_check(summary),
        _local_skill_instruction_check(plugin_dir, resolved_context.skills_dir),
    )
