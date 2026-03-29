"""Tests for Cisco-backed skill security checks."""

from pathlib import Path

from codex_plugin_scanner.checks.skill_security import run_skill_security_checks
from codex_plugin_scanner.integrations.cisco_skill_scanner import (
    CiscoIntegrationStatus,
    CiscoSkillScanSummary,
)
from codex_plugin_scanner.models import Finding, ScanOptions, Severity
from codex_plugin_scanner.scanner import scan_plugin

FIXTURES = Path(__file__).parent / "fixtures"


def _high_risk_summary() -> CiscoSkillScanSummary:
    return CiscoSkillScanSummary(
        status=CiscoIntegrationStatus.ENABLED,
        message="Cisco scan completed",
        findings=(
            Finding(
                rule_id="CISCO-BEHAVIOR-1",
                severity=Severity.HIGH,
                category="skill-security",
                title="Dangerous command execution in skill",
                description="The skill exposes a command execution path that can be abused.",
                remediation="Restrict tool execution and validate arguments.",
                file_path="skills/example/SKILL.md",
                source="cisco-skill-scanner",
            ),
        ),
        skills_scanned=1,
        skills_skipped=(),
        analyzers_used=("static_analyzer", "pipeline"),
        policy_name="strict",
        total_findings=1,
        findings_by_severity={"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
    )


def test_skill_security_uses_cisco_summary(monkeypatch):
    monkeypatch.setattr(
        "codex_plugin_scanner.checks.skill_security.run_cisco_skill_scan",
        lambda *args, **kwargs: _high_risk_summary(),
    )

    checks = run_skill_security_checks(
        FIXTURES / "good-plugin",
        ScanOptions(cisco_skill_scan="on", cisco_policy="strict"),
    )

    names = {check.name: check for check in checks}
    assert names["Cisco skill scan completed"].passed is True
    assert names["No elevated Cisco skill findings"].passed is False
    assert "Dangerous command execution in skill" in names["No elevated Cisco skill findings"].message


def test_scan_plugin_includes_cisco_findings(monkeypatch):
    monkeypatch.setattr(
        "codex_plugin_scanner.checks.skill_security.run_cisco_skill_scan",
        lambda *args, **kwargs: _high_risk_summary(),
    )

    result = scan_plugin(FIXTURES / "good-plugin", ScanOptions(cisco_skill_scan="on", cisco_policy="strict"))

    assert any(category.name == "Skill Security" for category in result.categories)
    assert result.severity_counts["high"] == 1
    assert any(finding.source == "cisco-skill-scanner" for finding in result.findings)
    assert result.integrations[0].status == CiscoIntegrationStatus.ENABLED
