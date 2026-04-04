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

    def test_fails_for_non_object_plugin_entry(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mp = Path(tmpdir) / "marketplace.json"
            mp.write_text('{"name": "test", "plugins": ["invalid"]}')
            r = check_marketplace_json(Path(tmpdir))
            assert not r.passed and r.points == 0
            assert r.message == "marketplace.json plugin[0] must be an object"

    def test_fails_for_invalid_source_shape(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mp = Path(tmpdir) / "marketplace.json"
            mp.write_text(
                '{"name": "test", "plugins": [{"source": {"source": "git", '
                '"path": "./plugins/example"}, "policy": {}}]}'
            )
            r = check_marketplace_json(Path(tmpdir))
            assert not r.passed and r.points == 0

    def test_fails_for_missing_plugin_policy(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mp = Path(tmpdir) / "marketplace.json"
            mp.write_text('{"name": "test", "plugins": [{"source": {"source": "local", "path": "./plugins/example"}}]}')
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
            mp.write_text(
                '{"name": "test", "plugins": [{"source": {"source": "local", '
                '"path": "./plugins/example"}, "policy": {"authentication": '
                '"ON_INSTALL"}, "category": "Productivity"}]}'
            )
            r = check_policy_fields(Path(tmpdir))
            assert not r.passed and r.points == 0

    def test_fails_for_missing_authentication(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mp = Path(tmpdir) / "marketplace.json"
            mp.write_text(
                '{"name": "test", "plugins": [{"source": {"source": "local", '
                '"path": "./plugins/example"}, "policy": {"installation": '
                '"AVAILABLE"}, "category": "Productivity"}]}'
            )
            r = check_policy_fields(Path(tmpdir))
            assert not r.passed and r.points == 0

    def test_fails_for_missing_category(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mp = Path(tmpdir) / "marketplace.json"
            mp.write_text(
                '{"name": "test", "plugins": [{"source": {"source": "local", '
                '"path": "./plugins/example"}, "policy": {"installation": '
                '"AVAILABLE", "authentication": "ON_INSTALL"}}]}'
            )
            r = check_policy_fields(Path(tmpdir))
            assert not r.passed and r.points == 0

    def test_fails_for_non_object_plugin_entry(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mp = Path(tmpdir) / "marketplace.json"
            mp.write_text('{"name": "test", "plugins": ["invalid"]}')
            r = check_policy_fields(Path(tmpdir))
            assert not r.passed and r.points == 0
            assert "plugin[0]: not an object" in r.message
            assert all(
                finding.remediation
                == "Add policy.installation, policy.authentication, and category for each marketplace entry."
                for finding in r.findings
            )

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
                '{"name": "test", "plugins": [{"source": {"source": "local", "path": "../outside"}, '
                '"policy": {"installation": "AVAILABLE", "authentication": "ON_INSTALL"}, "category": "Productivity"}]}'
            )
            results = run_marketplace_checks(Path(tmpdir))
            source_check = next(check for check in results if check.name == "Marketplace sources are safe")
            assert source_check.passed is False
            assert "../outside" in source_check.message

    def test_invalid_marketplace_entry_is_unsafe(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            mp = Path(tmpdir) / "marketplace.json"
            mp.write_text('{"name": "test", "plugins": ["invalid"]}')
            results = run_marketplace_checks(Path(tmpdir))
            source_check = next(check for check in results if check.name == "Marketplace sources are safe")
            assert source_check.passed is False
            assert source_check.message == "Unsafe marketplace sources detected: plugin[0]=invalid-entry"
