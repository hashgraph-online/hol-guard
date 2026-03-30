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
    monkeypatch.setenv("GITHUB_OUTPUT", str(output_path))

    exit_code = main()

    assert exit_code == 0
    output_lines = output_path.read_text(encoding="utf-8").splitlines()
    assert "score=100" in output_lines
    assert "grade=A" in output_lines
    assert "submission_eligible=false" in output_lines
    assert "submission_performed=false" in output_lines
    assert "submission_issue_urls=" in output_lines
    assert "submission_issue_numbers=" in output_lines

    stdout = capsys.readouterr().out
    assert '"score": 100' in stdout
