"""Tests for Cisco-backed skill security checks."""

import sys
from pathlib import Path
from types import ModuleType

from codex_plugin_scanner.checks.skill_security import run_skill_security_checks
from codex_plugin_scanner.integrations.cisco_skill_scanner import (
    CiscoIntegrationStatus,
    CiscoSkillScanSummary,
    run_cisco_skill_scan,
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


def _summary_with_status(status: CiscoIntegrationStatus, message: str) -> CiscoSkillScanSummary:
    return CiscoSkillScanSummary(
        status=status,
        message=message,
        findings=(),
        skills_scanned=0,
        skills_skipped=(),
        analyzers_used=(),
        policy_name="balanced",
        total_findings=0,
        findings_by_severity={"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
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


def test_skill_security_auto_mode_unavailable_is_not_applicable(monkeypatch):
    monkeypatch.setattr(
        "codex_plugin_scanner.checks.skill_security.run_cisco_skill_scan",
        lambda *args, **kwargs: _summary_with_status(
            CiscoIntegrationStatus.UNAVAILABLE,
            "Cisco skill scanner not installed; deep skill scan skipped.",
        ),
    )

    checks = run_skill_security_checks(FIXTURES / "good-plugin", ScanOptions(cisco_skill_scan="auto"))

    availability = next(check for check in checks if check.name == "Cisco skill scan completed")
    assert availability.passed is True
    assert availability.points == 0
    assert availability.max_points == 0
    assert availability.applicable is False


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


def test_scan_plugin_runs_cisco_scan_once(monkeypatch):
    calls: list[tuple[tuple[object, ...], dict[str, object]]] = []

    def fake_scan(*args, **kwargs):
        calls.append((args, kwargs))
        return _high_risk_summary()

    monkeypatch.setattr("codex_plugin_scanner.checks.skill_security.run_cisco_skill_scan", fake_scan)
    monkeypatch.setattr("codex_plugin_scanner.scanner.run_cisco_skill_scan", fake_scan, raising=False)

    scan_plugin(FIXTURES / "good-plugin", ScanOptions(cisco_skill_scan="on", cisco_policy="strict"))

    assert len(calls) == 1


def test_run_cisco_skill_scan_populates_skipped_skills(monkeypatch):
    skill_scanner_module = ModuleType("skill_scanner")
    skill_scanner_core_module = ModuleType("skill_scanner.core")
    scan_policy_module = ModuleType("skill_scanner.core.scan_policy")

    class FakeScanPolicy:
        def __init__(self, preset_base: str):
            self.preset_base = preset_base

    class FakeReport:
        def to_dict(self) -> dict[str, object]:
            return {
                "summary": {
                    "total_skills_scanned": 1,
                    "total_findings": 0,
                    "findings_by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
                    "skills_skipped": ["skills/skipped/SKILL.md"],
                },
                "results": [{"findings": [], "analyzers_used": ["pipeline"]}],
            }

    class FakeSkillScanner:
        def __init__(self, policy: FakeScanPolicy):
            self.policy = policy

        def scan_directory(self, _skills_dir: Path) -> FakeReport:
            return FakeReport()

    skill_scanner_module.SkillScanner = FakeSkillScanner
    scan_policy_module.ScanPolicy = FakeScanPolicy

    monkeypatch.setitem(sys.modules, "skill_scanner", skill_scanner_module)
    monkeypatch.setitem(sys.modules, "skill_scanner.core", skill_scanner_core_module)
    monkeypatch.setitem(sys.modules, "skill_scanner.core.scan_policy", scan_policy_module)

    summary = run_cisco_skill_scan(FIXTURES / "good-plugin" / "skills", mode="on", policy_name="strict")

    assert summary.status == CiscoIntegrationStatus.ENABLED
    assert summary.skills_skipped == ("skills/skipped/SKILL.md",)
