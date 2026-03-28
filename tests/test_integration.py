"""Integration tests for CLI output formatting."""

import json
from pathlib import Path

from codex_plugin_scanner.scanner import scan_plugin
from codex_plugin_scanner.cli import format_json

FIXTURES = Path(__file__).parent / "fixtures"


def test_text_output_sections():
    # Just verify the scanner produces correct data for text formatting
    result = scan_plugin(FIXTURES / "good-plugin")
    assert result.score == 100
    assert result.grade == "A"
    assert len(result.categories) == 5
    cat_names = [c.name for c in result.categories]
    assert "Manifest Validation" in cat_names
    assert "Security" in cat_names


def test_json_output_valid():
    result = scan_plugin(FIXTURES / "good-plugin")
    output = format_json(result)
    parsed = json.loads(output)
    assert parsed["score"] == 100
    assert parsed["grade"] == "A"
    assert len(parsed["categories"]) == 5
    assert "timestamp" in parsed


def test_bad_plugin_json_shows_failures():
    result = scan_plugin(FIXTURES / "bad-plugin")
    output = format_json(result)
    parsed = json.loads(output)
    assert parsed["score"] < 60
    security = next(c for c in parsed["categories"] if c["name"] == "Security")
    assert security["score"] < security["max"]
