"""Cisco skill-scanner integration."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from ..models import Finding, Severity, severity_from_value


class CiscoIntegrationStatus(StrEnum):
    """State of the Cisco skill-scanner integration."""

    ENABLED = "enabled"
    SKIPPED = "skipped"
    UNAVAILABLE = "unavailable"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class CiscoSkillScanSummary:
    """Normalized summary from a Cisco skill-scanner run."""

    status: CiscoIntegrationStatus
    message: str
    findings: tuple[Finding, ...]
    skills_scanned: int
    skills_skipped: tuple[str, ...]
    analyzers_used: tuple[str, ...]
    policy_name: str
    total_findings: int
    findings_by_severity: dict[str, int]


def _empty_counts() -> dict[str, int]:
    return {severity.value: 0 for severity in Severity}


def _build_unavailable_summary(message: str, *, status: CiscoIntegrationStatus) -> CiscoSkillScanSummary:
    return CiscoSkillScanSummary(
        status=status,
        message=message,
        findings=(),
        skills_scanned=0,
        skills_skipped=(),
        analyzers_used=(),
        policy_name="balanced",
        total_findings=0,
        findings_by_severity=_empty_counts(),
    )


def _to_local_finding(plugin_dir: Path, skill_result: dict[str, object], finding: dict[str, object]) -> Finding:
    skill_path = Path(str(skill_result.get("skill_path", "")))
    relative_skill_path = skill_path
    if skill_path.is_absolute():
        try:
            relative_skill_path = skill_path.relative_to(plugin_dir)
        except ValueError:
            relative_skill_path = Path(skill_path.name)

    finding_path = str(finding.get("file_path") or "").strip()
    full_path = relative_skill_path / finding_path if finding_path else relative_skill_path
    line_number = finding.get("line_number")

    return Finding(
        rule_id=str(finding.get("rule_id") or finding.get("id") or "CISCO-SKILL-SCANNER"),
        severity=severity_from_value(str(finding.get("severity") or "info")),
        category="skill-security",
        title=str(finding.get("title") or "Cisco skill-scanner finding"),
        description=str(finding.get("description") or "Cisco skill-scanner reported a potential issue."),
        remediation=str(finding.get("remediation")) if finding.get("remediation") else None,
        file_path=str(full_path),
        line_number=int(line_number) if isinstance(line_number, int) else None,
        source="cisco-skill-scanner",
    )


def run_cisco_skill_scan(skills_dir: Path, mode: str = "auto", policy_name: str = "balanced") -> CiscoSkillScanSummary:
    """Run Cisco skill-scanner against a skills directory when available."""

    if mode == "off":
        return _build_unavailable_summary(
            "Cisco skill scanning disabled by configuration.",
            status=CiscoIntegrationStatus.SKIPPED,
        )

    try:
        from skill_scanner import SkillScanner
        from skill_scanner.core.scan_policy import ScanPolicy
    except ImportError:
        if mode == "on":
            return _build_unavailable_summary(
                "Cisco skill scanner is required but not installed. Install with the cisco extra.",
                status=CiscoIntegrationStatus.UNAVAILABLE,
            )
        return _build_unavailable_summary(
            "Cisco skill scanner not installed; deep skill scan skipped.",
            status=CiscoIntegrationStatus.UNAVAILABLE,
        )

    try:
        scanner = SkillScanner(policy=ScanPolicy(preset_base=policy_name))
        report = scanner.scan_directory(skills_dir.resolve())
        payload = report.to_dict()
    except Exception as exc:  # pragma: no cover - defensive around third-party code
        return _build_unavailable_summary(
            f"Cisco skill scanner failed: {exc}",
            status=CiscoIntegrationStatus.FAILED,
        )

    findings: list[Finding] = []
    results = payload.get("results", [])
    for result in results:
        if not isinstance(result, dict):
            continue
        skill_findings = result.get("findings", [])
        if not isinstance(skill_findings, list):
            continue
        for finding in skill_findings:
            if isinstance(finding, dict):
                findings.append(_to_local_finding(skills_dir.parent, result, finding))

    summary = payload.get("summary", {})
    counts = _empty_counts()
    findings_by_severity = summary.get("findings_by_severity", {})
    if isinstance(findings_by_severity, dict):
        for key, value in findings_by_severity.items():
            if key in counts and isinstance(value, int):
                counts[key] = value

    analyzers_used = []
    skills_skipped: tuple[str, ...] = ()
    if results and isinstance(results[0], dict):
        analyzers = results[0].get("analyzers_used", [])
        if isinstance(analyzers, list):
            analyzers_used = [str(analyzer) for analyzer in analyzers]

    return CiscoSkillScanSummary(
        status=CiscoIntegrationStatus.ENABLED,
        message=f"Cisco skill scanner completed using the {policy_name} policy preset.",
        findings=tuple(findings),
        skills_scanned=int(summary.get("total_skills_scanned", 0)),
        skills_skipped=skills_skipped,
        analyzers_used=tuple(analyzers_used),
        policy_name=policy_name,
        total_findings=int(summary.get("total_findings", len(findings))),
        findings_by_severity=counts,
    )
