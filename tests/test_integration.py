"""Integration tests - full end-to-end scanner runs."""

import json
from pathlib import Path

from codex_plugin_scanner.cli import format_json, format_text
from codex_plugin_scanner.models import ScanOptions
from codex_plugin_scanner.scanner import scan_plugin

FIXTURES = Path(__file__).parent / "fixtures"


def test_good_plugin_full_score():
    result = scan_plugin(FIXTURES / "good-plugin")
    assert result.score == 100
    assert result.grade == "A"
    for cat in result.categories:
        assert sum(c.points for c in cat.checks) == sum(c.max_points for c in cat.checks)


def test_bad_plugin_catches_all_issues():
    result = scan_plugin(FIXTURES / "bad-plugin")
    assert result.score == 38
    assert result.grade == "F"

    cats = {c.name: c for c in result.categories}
    sec = cats["Security"]
    sec_names = {c.name: c.passed for c in sec.checks}
    assert sec_names["SECURITY.md found"] is False
    assert sec_names["LICENSE found"] is False
    assert sec_names["No hardcoded secrets"] is False
    assert sec_names["No dangerous MCP commands"] is False

    bp = cats["Best Practices"]
    bp_names = {c.name: c.passed for c in bp.checks}
    assert bp_names["No .env files committed"] is False


def test_json_output_is_parseable():
    result = scan_plugin(FIXTURES / "good-plugin")
    output = format_json(result)
    parsed = json.loads(output)
    assert parsed["score"] == 100
    assert len(parsed["categories"]) == 7
    total_checks = sum(len(c["checks"]) for c in parsed["categories"])
    assert total_checks == 33


def test_text_output_is_readable():
    result = scan_plugin(FIXTURES / "good-plugin")
    output = format_text(result)
    # Should have all category headers
    assert "Manifest Validation" in output
    assert "Security" in output
    assert "Operational Security" in output
    assert "Best Practices" in output
    assert "Marketplace" in output
    assert "Skill Security" in output
    assert "Code Quality" in output
    # Should have score
    assert "100/100" in output


def test_all_check_names_unique():
    result = scan_plugin(FIXTURES / "good-plugin")
    all_names = []
    for cat in result.categories:
        for check in cat.checks:
            all_names.append(check.name)
    assert len(all_names) == len(set(all_names)), f"Duplicate check names: {all_names}"


def test_max_points_total_100():
    result = scan_plugin(FIXTURES / "good-plugin", ScanOptions(cisco_skill_scan="off"))
    total_max = sum(c.max_points for cat in result.categories for c in cat.checks)
    assert total_max == 72


def test_mit_license_plugin():
    result = scan_plugin(FIXTURES / "mit-license")
    sec_cat = next(c for c in result.categories if c.name == "Security")
    license_check = next(c for c in sec_cat.checks if c.name == "LICENSE found")
    assert license_check.passed
    assert "MIT" in license_check.message


def test_with_marketplace_plugin():
    result = scan_plugin(FIXTURES / "with-marketplace")
    mp_cat = next(c for c in result.categories if c.name == "Marketplace")
    assert sum(c.points for c in mp_cat.checks) == 15
    mp_names = {c.name: c.passed for c in mp_cat.checks}
    assert mp_names["marketplace.json valid"] is True
    assert mp_names["Policy fields present"] is True
    assert mp_names["Marketplace sources are safe"] is True


def test_malformed_json_manifest():
    result = scan_plugin(FIXTURES / "malformed-json")
    assert result.score < 100
    manifest_cat = next(c for c in result.categories if c.name == "Manifest Validation")
    assert sum(c.points for c in manifest_cat.checks) < 31


def test_public_api_import():
    """Test that the public API is importable."""
    import codex_plugin_scanner
    from codex_plugin_scanner import scan_plugin

    assert hasattr(codex_plugin_scanner, "__version__")
    assert scan_plugin is not None
