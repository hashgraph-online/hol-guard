"""Tests for marketplace checks."""

import json
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

    def test_passes_for_codex_marketplace_layout(self, tmp_path: Path):
        marketplace_dir = tmp_path / ".agents" / "plugins"
        marketplace_dir.mkdir(parents=True)
        (marketplace_dir / "plugins" / "demo").mkdir(parents=True)
        (marketplace_dir / "marketplace.json").write_text(
            json.dumps(
                {
                    "name": "demo-marketplace",
                    "interface": {"displayName": "Demo Marketplace"},
                    "plugins": [
                        {
                            "source": {
                                "source": "https://github.com/hashgraph-online/example-plugin",
                                "path": "./plugins/demo",
                            },
                            "policy": {"installation": "manual", "authentication": "none"},
                            "category": "Developer Tools",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

        result = check_marketplace_json(tmp_path)

        assert result.passed is True
        assert result.points == 5

    def test_legacy_root_marketplace_runs_in_compatibility_mode(self, tmp_path: Path):
        (tmp_path / "marketplace.json").write_text(
            json.dumps(
                {
                    "name": "legacy-marketplace",
                    "plugins": [
                        {
                            "source": "https://github.com/hashgraph-online/example-plugin",
                            "policy": {"installation": "manual", "authentication": "none"},
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

        result = check_marketplace_json(tmp_path)

        assert result.passed is True
        assert "compatibility" in result.message.lower()

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

    def test_fails_for_missing_category_in_codex_layout(self, tmp_path: Path):
        marketplace_dir = tmp_path / ".agents" / "plugins"
        marketplace_dir.mkdir(parents=True)
        (marketplace_dir / "plugins" / "demo").mkdir(parents=True)
        (marketplace_dir / "marketplace.json").write_text(
            json.dumps(
                {
                    "name": "demo-marketplace",
                    "plugins": [
                        {
                            "source": {
                                "source": "https://github.com/hashgraph-online/example-plugin",
                                "path": "./plugins/demo",
                            },
                            "policy": {"installation": "manual", "authentication": "none"},
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

        result = check_policy_fields(tmp_path)

        assert result.passed is False
        assert "category" in result.message

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

    def test_codex_marketplace_path_must_start_with_dot_slash(self, tmp_path: Path):
        marketplace_dir = tmp_path / ".agents" / "plugins"
        marketplace_dir.mkdir(parents=True)
        (marketplace_dir / "plugins" / "demo").mkdir(parents=True)
        (marketplace_dir / "marketplace.json").write_text(
            json.dumps(
                {
                    "name": "demo-marketplace",
                    "plugins": [
                        {
                            "source": {
                                "source": "https://github.com/hashgraph-online/example-plugin",
                                "path": "plugins/demo",
                            },
                            "policy": {"installation": "manual", "authentication": "none"},
                            "category": "Developer Tools",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

        results = run_marketplace_checks(tmp_path)
        source_check = next(check for check in results if check.name == "Marketplace sources are safe")

        assert source_check.passed is False
        assert "./" in source_check.message
