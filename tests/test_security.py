"""Tests for security checks."""

from pathlib import Path

from codex_plugin_scanner.checks.security import run_security_checks

FIXTURES = Path(__file__).parent / "fixtures"


def test_good_plugin_security_30():
    results = run_security_checks(FIXTURES / "good-plugin")
    total = sum(c.points for c in results)
    assert total == 30


def test_bad_plugin_security():
    results = run_security_checks(FIXTURES / "bad-plugin")
    names = {c.name: c.passed for c in results}
    assert names["No hardcoded secrets"] is False
    assert names["No dangerous MCP commands"] is False


def test_minimal_plugin_partial_security():
    results = run_security_checks(FIXTURES / "minimal-plugin")
    total = sum(c.points for c in results)
    assert 0 < total < 30
