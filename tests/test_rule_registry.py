"""Tests for stable rule registry metadata."""

from codex_plugin_scanner.rules import get_rule_spec, has_rule_spec, list_rule_specs


def test_registry_contains_current_rule_ids():
    specs = list_rule_specs()
    assert len(specs) >= 28
    assert has_rule_spec("HARDCODED_SECRET")
    assert has_rule_spec("MARKETPLACE_JSON_INVALID")


def test_get_rule_spec_returns_expected_metadata():
    spec = get_rule_spec("CODEXIGNORE_MISSING")
    assert spec is not None
    assert spec.fixable is True
    assert spec.category == "best-practices"
