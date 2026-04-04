"""Behavior checks for the GitHub Action runner output contract."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.action_runner import main

FIXTURES = Path(__file__).parent / "fixtures"


def test_action_runner_writes_all_outputs(monkeypatch, tmp_path, capsys) -> None:
    output_path = tmp_path / "github-output.txt"

    monkeypatch.setenv("PLUGIN_DIR", str(FIXTURES / "good-plugin"))
    monkeypatch.setenv("FORMAT", "json")
    monkeypatch.setenv("OUTPUT", "")
    monkeypatch.setenv("MIN_SCORE", "0")
    monkeypatch.setenv("FAIL_ON", "none")
    monkeypatch.setenv("CISCO_SCAN", "off")
    monkeypatch.setenv("CISCO_POLICY", "balanced")
    monkeypatch.setenv("SUBMISSION_ENABLED", "false")
    monkeypatch.setenv("SUBMISSION_SCORE_THRESHOLD", "80")
    monkeypatch.setenv("SUBMISSION_REPOS", "hashgraph-online/awesome-codex-plugins")
    monkeypatch.setenv("SUBMISSION_TOKEN", "")
    monkeypatch.setenv("SUBMISSION_LABELS", "plugin-submission")
    monkeypatch.setenv("SUBMISSION_CATEGORY", "Community Plugins")
    monkeypatch.setenv("SUBMISSION_PLUGIN_NAME", "")
    monkeypatch.setenv("SUBMISSION_PLUGIN_URL", "")
    monkeypatch.setenv("SUBMISSION_PLUGIN_DESCRIPTION", "")
    monkeypatch.setenv("SUBMISSION_AUTHOR", "")
    monkeypatch.setenv("WRITE_STEP_SUMMARY", "false")
    monkeypatch.setenv("REGISTRY_PAYLOAD_OUTPUT", "")
    monkeypatch.setenv("GITHUB_OUTPUT", str(output_path))

    exit_code = main()

    assert exit_code == 0
    output_lines = output_path.read_text(encoding="utf-8").splitlines()
    assert "score=100" in output_lines
    assert "grade=A" in output_lines
    assert "grade_label=Excellent" in output_lines
    assert "max_severity=none" in output_lines
    assert "findings_total=0" in output_lines
    assert "report_path=" in output_lines
    assert "registry_payload_path=" in output_lines
    assert "policy_pass=true" in output_lines
    assert "verify_pass=" in output_lines
    assert "submission_eligible=false" in output_lines
    assert "submission_performed=false" in output_lines
    assert "submission_issue_urls=" in output_lines
    assert "submission_issue_numbers=" in output_lines

    stdout = capsys.readouterr().out
    assert '"score": 100' in stdout


def test_action_runner_writes_step_summary_and_registry_payload(monkeypatch, tmp_path) -> None:
    output_path = tmp_path / "github-output.txt"
    report_path = tmp_path / "scan-report.json"
    summary_path = tmp_path / "step-summary.md"
    registry_payload_path = tmp_path / "registry-payload.json"

    monkeypatch.setenv("PLUGIN_DIR", str(FIXTURES / "good-plugin"))
    monkeypatch.setenv("FORMAT", "json")
    monkeypatch.setenv("OUTPUT", str(report_path))
    monkeypatch.setenv("MIN_SCORE", "0")
    monkeypatch.setenv("FAIL_ON", "none")
    monkeypatch.setenv("CISCO_SCAN", "off")
    monkeypatch.setenv("CISCO_POLICY", "balanced")
    monkeypatch.setenv("SUBMISSION_ENABLED", "false")
    monkeypatch.setenv("SUBMISSION_SCORE_THRESHOLD", "80")
    monkeypatch.setenv("SUBMISSION_REPOS", "hashgraph-online/awesome-codex-plugins")
    monkeypatch.setenv("SUBMISSION_TOKEN", "")
    monkeypatch.setenv("SUBMISSION_LABELS", "plugin-submission")
    monkeypatch.setenv("SUBMISSION_CATEGORY", "Community Plugins")
    monkeypatch.setenv("SUBMISSION_PLUGIN_NAME", "")
    monkeypatch.setenv("SUBMISSION_PLUGIN_URL", "")
    monkeypatch.setenv("SUBMISSION_PLUGIN_DESCRIPTION", "")
    monkeypatch.setenv("SUBMISSION_AUTHOR", "")
    monkeypatch.setenv("WRITE_STEP_SUMMARY", "true")
    monkeypatch.setenv("REGISTRY_PAYLOAD_OUTPUT", str(registry_payload_path))
    monkeypatch.setenv("GITHUB_OUTPUT", str(output_path))
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_path))
    monkeypatch.setenv("GITHUB_REPOSITORY", "hashgraph-online/example-good-plugin")
    monkeypatch.setenv("GITHUB_SERVER_URL", "https://github.com")
    monkeypatch.setenv("GITHUB_SHA", "abc123")
    monkeypatch.setenv("GITHUB_RUN_ID", "77")

    exit_code = main()

    assert exit_code == 0
    output_lines = output_path.read_text(encoding="utf-8").splitlines()
    assert f"report_path={report_path}" in output_lines
    assert f"registry_payload_path={registry_payload_path}" in output_lines

    payload_text = registry_payload_path.read_text(encoding="utf-8")
    assert '"pluginName": "Example Good Plugin"' in payload_text
    assert '"sourceRepository": "hashgraph-online/example-good-plugin"' in payload_text

    summary_text = summary_path.read_text(encoding="utf-8")
    assert "## HOL Codex Plugin Scanner" in summary_text
    assert "- Score: 100/100" in summary_text
    assert "- Grade: A - Excellent" in summary_text
    assert f"- Registry payload: `{registry_payload_path}`" in summary_text


def test_action_runner_verify_mode_writes_human_report(monkeypatch, tmp_path, capsys) -> None:
    output_path = tmp_path / "verify-report.txt"
    github_output = tmp_path / "github-output.txt"

    monkeypatch.setenv("MODE", "verify")
    monkeypatch.setenv("PLUGIN_DIR", str(FIXTURES / "good-plugin"))
    monkeypatch.setenv("FORMAT", "text")
    monkeypatch.setenv("OUTPUT", str(output_path))
    monkeypatch.setenv("PROFILE", "default")
    monkeypatch.setenv("CONFIG", "")
    monkeypatch.setenv("BASELINE", "")
    monkeypatch.setenv("ONLINE", "false")
    monkeypatch.setenv("MIN_SCORE", "0")
    monkeypatch.setenv("FAIL_ON", "none")
    monkeypatch.setenv("CISCO_SCAN", "off")
    monkeypatch.setenv("CISCO_POLICY", "balanced")
    monkeypatch.setenv("SUBMISSION_ENABLED", "false")
    monkeypatch.setenv("SUBMISSION_SCORE_THRESHOLD", "80")
    monkeypatch.setenv("SUBMISSION_REPOS", "hashgraph-online/awesome-codex-plugins")
    monkeypatch.setenv("SUBMISSION_TOKEN", "")
    monkeypatch.setenv("SUBMISSION_LABELS", "plugin-submission")
    monkeypatch.setenv("SUBMISSION_CATEGORY", "Community Plugins")
    monkeypatch.setenv("SUBMISSION_PLUGIN_NAME", "")
    monkeypatch.setenv("SUBMISSION_PLUGIN_URL", "")
    monkeypatch.setenv("SUBMISSION_PLUGIN_DESCRIPTION", "")
    monkeypatch.setenv("SUBMISSION_AUTHOR", "")
    monkeypatch.setenv("WRITE_STEP_SUMMARY", "false")
    monkeypatch.setenv("REGISTRY_PAYLOAD_OUTPUT", "")
    monkeypatch.setenv("GITHUB_OUTPUT", str(github_output))

    exit_code = main()

    assert exit_code == 0
    assert "Verification: PASS" in output_path.read_text(encoding="utf-8")
    assert "mode=verify" in github_output.read_text(encoding="utf-8")
    assert "verify_pass=true" in github_output.read_text(encoding="utf-8")
    assert "Report written to" in capsys.readouterr().out


def test_action_runner_repository_scan_defaults_to_marketplace_root(monkeypatch, tmp_path) -> None:
    output_path = tmp_path / "github-output.txt"
    summary_path = tmp_path / "step-summary.md"

    monkeypatch.setenv("PLUGIN_DIR", str(FIXTURES / "multi-plugin-repo"))
    monkeypatch.setenv("FORMAT", "json")
    monkeypatch.setenv("OUTPUT", "")
    monkeypatch.setenv("MIN_SCORE", "0")
    monkeypatch.setenv("FAIL_ON", "none")
    monkeypatch.setenv("CISCO_SCAN", "off")
    monkeypatch.setenv("CISCO_POLICY", "balanced")
    monkeypatch.setenv("SUBMISSION_ENABLED", "false")
    monkeypatch.setenv("SUBMISSION_SCORE_THRESHOLD", "80")
    monkeypatch.setenv("SUBMISSION_REPOS", "hashgraph-online/awesome-codex-plugins")
    monkeypatch.setenv("SUBMISSION_TOKEN", "")
    monkeypatch.setenv("SUBMISSION_LABELS", "plugin-submission")
    monkeypatch.setenv("SUBMISSION_CATEGORY", "Community Plugins")
    monkeypatch.setenv("SUBMISSION_PLUGIN_NAME", "")
    monkeypatch.setenv("SUBMISSION_PLUGIN_URL", "")
    monkeypatch.setenv("SUBMISSION_PLUGIN_DESCRIPTION", "")
    monkeypatch.setenv("SUBMISSION_AUTHOR", "")
    monkeypatch.setenv("WRITE_STEP_SUMMARY", "true")
    monkeypatch.setenv("REGISTRY_PAYLOAD_OUTPUT", "")
    monkeypatch.setenv("GITHUB_OUTPUT", str(output_path))
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_path))

    exit_code = main()

    assert exit_code == 0
    summary_text = summary_path.read_text(encoding="utf-8")
    assert "- Scope: repository" in summary_text
    assert "- Local plugins scanned: 2" in summary_text
    assert "- Skipped marketplace entries: 1" in summary_text
    output_lines = output_path.read_text(encoding="utf-8").splitlines()
    assert any(line.startswith("score=") for line in output_lines)
