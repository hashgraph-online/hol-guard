"""Regression coverage for complete GitHub Actions finding summaries."""

from __future__ import annotations

from types import SimpleNamespace

import codex_plugin_scanner.action_runner as action_runner
from codex_plugin_scanner.models import Finding, ScanResult, Severity, build_severity_counts


def test_scan_step_summary_includes_complete_finding_details(monkeypatch, tmp_path) -> None:
    finding = Finding(
        rule_id="TEST-INFO-001",
        severity=Severity.INFO,
        category="Security",
        title="Informational scanner finding",
        description="The scanner found a concrete issue that should be visible in the job summary.",
        remediation="Apply the documented remediation and rerun the scanner.",
        file_path="plugin/example.py",
        line_number=42,
        source="native",
    )
    findings = (finding,)
    result = ScanResult(
        score=97,
        grade="A",
        categories=(),
        timestamp="2026-08-10T00:00:00Z",
        plugin_dir=str(tmp_path),
        findings=findings,
        severity_counts=build_severity_counts(findings),
    )
    policy_eval = SimpleNamespace(policy_pass=True)

    def _fake_scan(*_args, **_kwargs):
        return result, result, "default", policy_eval, 97, None, None

    report_path = tmp_path / "ai-plugin-scanner.sarif"
    summary_path = tmp_path / "step-summary.md"
    output_path = tmp_path / "github-output.txt"

    monkeypatch.setattr(action_runner, "_scan_with_policy", _fake_scan)
    monkeypatch.setenv("MODE", "scan")
    monkeypatch.setenv("PLUGIN_DIR", str(tmp_path))
    monkeypatch.setenv("FORMAT", "sarif")
    monkeypatch.setenv("OUTPUT", str(report_path))
    monkeypatch.setenv("UPLOAD_SARIF", "true")
    monkeypatch.setenv("WRITE_STEP_SUMMARY", "true")
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_path))
    monkeypatch.setenv("GITHUB_OUTPUT", str(output_path))
    monkeypatch.setenv("PR_COMMENT", "off")
    monkeypatch.setenv("MIN_SCORE", "0")
    monkeypatch.setenv("FAIL_ON", "none")
    monkeypatch.setenv("CISCO_SCAN", "off")
    monkeypatch.setenv("CISCO_POLICY", "balanced")
    monkeypatch.setenv("SUBMISSION_ENABLED", "false")
    monkeypatch.setenv("REGISTRY_PAYLOAD_OUTPUT", "")

    exit_code = action_runner.main()

    assert exit_code == 0
    assert report_path.exists()
    summary = summary_path.read_text(encoding="utf-8")
    assert "- Score: 97/100" in summary
    assert "- Grade: A - Excellent" in summary
    assert "- Max severity: info" in summary
    assert "- Findings: 1" in summary
    assert "### Finding details" in summary
    assert "### Contributor review pathway" in summary
    assert "Review does not grant approval or change the scan result." in summary
    assert "#### 1. INFO - Informational scanner finding" in summary
    assert "- Rule ID: TEST-INFO-001" in summary
    assert "- Category: Security" in summary
    assert "- Source: native" in summary
    assert "- Location: plugin/example.py:42" in summary
    assert "- Description: The scanner found a concrete issue that should be visible in the job summary." in summary
    assert "- Remediation: Apply the documented remediation and rerun the scanner." in summary


def test_finding_summary_orders_severity_and_escapes_markdown() -> None:
    findings = (
        Finding(
            rule_id="INFO-1",
            severity=Severity.INFO,
            category="General",
            title="Info finding",
            description="Plain detail",
        ),
        Finding(
            rule_id="CRIT-1",
            severity=Severity.CRITICAL,
            category="Security",
            title="Unsafe <script> *title*",
            description="Potential `code` injection",
            file_path="plugin/[unsafe].py",
            source="external",
        ),
    )

    summary = "\n".join(action_runner._build_findings_summary_lines(findings))

    assert summary.index("CRITICAL") < summary.index("INFO")
    assert "Unsafe \\<script\\> \\*title\\*" in summary
    assert "Potential \\`code\\` injection" in summary
    assert "plugin/\\[unsafe\\].py" in summary
    assert "- Remediation: Not provided." in summary
