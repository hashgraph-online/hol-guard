"""Tests for manifest checks."""

from pathlib import Path

from codex_plugin_scanner.checks.manifest import run_manifest_checks

FIXTURES = Path(__file__).parent / "fixtures"


def test_good_plugin_manifest_25():
    results = run_manifest_checks(FIXTURES / "good-plugin")
    total = sum(c.points for c in results)
    assert total == 25
    assert all(c.passed for c in results)


def test_bad_plugin_manifest():
    results = run_manifest_checks(FIXTURES / "bad-plugin")
    names = {c.name: c.passed for c in results}
    assert names["Version follows semver"] is False
    assert names["Name is kebab-case"] is False


def test_minimal_plugin_manifest_25():
    results = run_manifest_checks(FIXTURES / "minimal-plugin")
    total = sum(c.points for c in results)
    assert total == 25
