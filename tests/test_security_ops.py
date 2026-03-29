"""Tests for security-ops oriented outputs and gates."""

import json
from pathlib import Path

from codex_plugin_scanner.cli import format_json, main
from codex_plugin_scanner.reporting import format_markdown, format_sarif
from codex_plugin_scanner.scanner import scan_plugin

FIXTURES = Path(__file__).parent / "fixtures"


def test_json_output_contains_findings_summary():
    result = scan_plugin(FIXTURES / "bad-plugin")
    payload = json.loads(format_json(result))

    assert "summary" in payload
    assert "findings" in payload["summary"]
    assert payload["summary"]["findings"]["high"] >= 1
    assert payload["findings"]


def test_markdown_output_contains_top_findings():
    result = scan_plugin(FIXTURES / "bad-plugin")
    output = format_markdown(result)

    assert "# Codex Plugin Scanner Report" in output
    assert "## Top Findings" in output
    assert "Hardcoded secret detected" in output or "Dangerous MCP command pattern detected" in output


def test_sarif_output_contains_results():
    result = scan_plugin(FIXTURES / "bad-plugin")
    sarif = json.loads(format_sarif(result))

    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "codex-plugin-scanner"
    assert sarif["runs"][0]["results"]


def test_fail_on_severity_trips_exit_code():
    exit_code = main([str(FIXTURES / "bad-plugin"), "--fail-on-severity", "high"])
    assert exit_code == 1


def test_sarif_cli_format_is_parseable(capsys):
    exit_code = main([str(FIXTURES / "bad-plugin"), "--format", "sarif"])
    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["version"] == "2.1.0"
