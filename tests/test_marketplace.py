"""Tests for marketplace checks."""

import tempfile
from pathlib import Path

from codex_plugin_scanner.checks.marketplace import (
    check_marketplace_json,
    check_policy_fields,
    run_marketplace_checks,
)

FIXTURES = Path(__file__).parent / "fixtures"


class TestCheckMarketplaceJson:
    def test_passes_when_no_file(self):
        r = check_marketplace_json(FIXTURES / "good-plugin")
        assert r.passed and r.points == 0
        assert not r.applicable

    def test_passes_for_valid_marketplace(self):
        r = check_marketplace_json(FIXTURES / "with-marketplace")
        assert r.passed and r.points == 5

    def test_fails_for_invalid_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mp = Path(tmpdir) / "marketplace.json"
            mp.write_text("not json")
            r = check_marketplace_json(Path(tmpdir))
            assert not r.passed and r.points == 0

    def test_fails_for_missing_name(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mp = Path(tmpdir) / "marketplace.json"
            mp.write_text('{"plugins": []}')
            r = check_marketplace_json(Path(tmpdir))
            assert not r.passed and r.points == 0

    def test_fails_for_missing_plugins(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mp = Path(tmpdir) / "marketplace.json"
            mp.write_text('{"name": "test"}')
            r = check_marketplace_json(Path(tmpdir))
            assert not r.passed and r.points == 0

    def test_fails_for_missing_plugin_source(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mp = Path(tmpdir) / "marketplace.json"
            mp.write_text('{"name": "test", "plugins": [{"policy": {}}]}')
            r = check_marketplace_json(Path(tmpdir))
            assert not r.passed and r.points == 0

    def test_fails_for_missing_plugin_policy(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mp = Path(tmpdir) / "marketplace.json"
            mp.write_text('{"name": "test", "plugins": [{"source": "https://example.com"}]}')
            r = check_marketplace_json(Path(tmpdir))
            assert not r.passed and r.points == 0


class TestCheckPolicyFields:
    def test_passes_when_no_file(self):
        r = check_policy_fields(FIXTURES / "good-plugin")
        assert r.passed and r.points == 0
        assert not r.applicable

    def test_passes_when_all_fields_present(self):
        r = check_policy_fields(FIXTURES / "with-marketplace")
        assert r.passed and r.points == 5

    def test_passes_when_empty_plugins(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mp = Path(tmpdir) / "marketplace.json"
            mp.write_text('{"name": "test", "plugins": []}')
            r = check_policy_fields(Path(tmpdir))
            assert r.passed and r.points == 5

    def test_fails_for_missing_installation(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mp = Path(tmpdir) / "marketplace.json"
            mp.write_text('{"name": "test", "plugins": [{"source": "x", "policy": {"authentication": "none"}}]}')
            r = check_policy_fields(Path(tmpdir))
            assert not r.passed and r.points == 0

    def test_fails_for_missing_authentication(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mp = Path(tmpdir) / "marketplace.json"
            mp.write_text('{"name": "test", "plugins": [{"source": "x", "policy": {"installation": "auto"}}]}')
            r = check_policy_fields(Path(tmpdir))
            assert not r.passed and r.points == 0

    def test_skips_invalid_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mp = Path(tmpdir) / "marketplace.json"
            mp.write_text("broken")
            r = check_policy_fields(Path(tmpdir))
            assert r.passed and r.points == 5


class TestRunMarketplaceChecks:
    def test_good_plugin_gets_0(self):
        results = run_marketplace_checks(FIXTURES / "good-plugin")
        assert sum(c.points for c in results) == 0
        assert sum(c.max_points for c in results) == 0

    def test_with_marketplace_gets_15(self):
        results = run_marketplace_checks(FIXTURES / "with-marketplace")
        assert sum(c.points for c in results) == 15

    def test_returns_tuple_of_correct_length(self):
        results = run_marketplace_checks(FIXTURES / "good-plugin")
        assert isinstance(results, tuple)
        assert len(results) == 3

    def test_http_marketplace_source_is_unsafe(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mp = Path(tmpdir) / "marketplace.json"
            mp.write_text(
                '{"name": "test", "plugins": [{"source": "http://example.com/plugin", '
                '"policy": {"installation": "manual", "authentication": "none"}}]}'
            )
            results = run_marketplace_checks(Path(tmpdir))
            source_check = next(check for check in results if check.name == "Marketplace sources are safe")
            assert source_check.passed is False
            assert "http://example.com/plugin" in source_check.message
