"""Tests for manifest checks."""

import tempfile
from pathlib import Path

from codex_plugin_scanner.checks.manifest import (
    check_interface_assets,
    check_interface_metadata,
    check_kebab_case,
    check_plugin_json_exists,
    check_required_fields,
    check_semver,
    check_valid_json,
    load_manifest,
    run_manifest_checks,
)

FIXTURES = Path(__file__).parent / "fixtures"


class TestLoadManifest:
    def test_returns_dict_for_valid_json(self):
        result = load_manifest(FIXTURES / "good-plugin")
        assert isinstance(result, dict)
        assert result["name"] == "example-good-plugin"

    def test_returns_none_for_missing_dir(self):
        result = load_manifest(FIXTURES / "empty-dir")
        assert result is None

    def test_returns_none_for_malformed_json(self):
        result = load_manifest(FIXTURES / "malformed-json")
        assert result is None

    def test_returns_none_for_nonexistent_path(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            result = load_manifest(Path(tmpdir) / "nonexistent")
            assert result is None


class TestCheckPluginJsonExists:
    def test_passes_when_exists(self):
        r = check_plugin_json_exists(FIXTURES / "good-plugin")
        assert r.passed and r.points == 4

    def test_fails_when_missing(self):
        r = check_plugin_json_exists(FIXTURES / "empty-dir")
        assert not r.passed and r.points == 0


class TestCheckValidJson:
    def test_passes_for_valid_json(self):
        r = check_valid_json(FIXTURES / "good-plugin")
        assert r.passed and r.points == 4

    def test_fails_for_malformed(self):
        r = check_valid_json(FIXTURES / "malformed-json")
        assert not r.passed and r.points == 0

    def test_fails_for_missing(self):
        r = check_valid_json(FIXTURES / "empty-dir")
        assert not r.passed and r.points == 0


class TestCheckRequiredFields:
    def test_passes_when_all_present(self):
        r = check_required_fields(FIXTURES / "good-plugin")
        assert r.passed and r.points == 5

    def test_fails_for_missing_description(self):
        r = check_required_fields(FIXTURES / "missing-fields")
        assert not r.passed and r.points == 0
        assert "description" in r.message

    def test_fails_for_malformed(self):
        r = check_required_fields(FIXTURES / "malformed-json")
        assert not r.passed and r.points == 0


class TestCheckSemver:
    def test_passes_for_valid_semver(self):
        r = check_semver(FIXTURES / "good-plugin")
        assert r.passed and r.points == 3

    def test_fails_for_non_semver(self):
        r = check_semver(FIXTURES / "bad-plugin")
        assert not r.passed and r.points == 0

    def test_fails_for_empty_version(self):
        r = check_semver(FIXTURES / "no-version")
        assert not r.passed and r.points == 0


class TestCheckKebabCase:
    def test_passes_for_kebab_case(self):
        r = check_kebab_case(FIXTURES / "good-plugin")
        assert r.passed and r.points == 2

    def test_fails_for_bad_name(self):
        r = check_kebab_case(FIXTURES / "bad-plugin")
        assert not r.passed and r.points == 0


class TestInterfaceChecks:
    def test_interface_metadata_passes_for_good_plugin(self):
        r = check_interface_metadata(FIXTURES / "good-plugin")
        assert r.passed and r.points == 3

    def test_interface_metadata_not_applicable_when_missing(self):
        r = check_interface_metadata(FIXTURES / "minimal-plugin")
        assert r.passed and r.points == 0
        assert not r.applicable

    def test_interface_assets_pass_for_good_plugin(self):
        r = check_interface_assets(FIXTURES / "good-plugin")
        assert r.passed and r.points == 3

    def test_interface_assets_fail_for_unsafe_values(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            plugin_dir = Path(tmpdir)
            manifest_dir = plugin_dir / ".codex-plugin"
            manifest_dir.mkdir(parents=True)
            (manifest_dir / "plugin.json").write_text(
                """
                {
                  "name": "interface-bad",
                  "version": "1.0.0",
                  "description": "bad interface metadata",
                  "interface": {
                    "type": "cli",
                    "displayName": "Bad",
                    "shortDescription": "Bad",
                    "longDescription": "Bad",
                    "developerName": "Bad",
                    "category": "Security",
                    "capabilities": ["Read"],
                    "websiteURL": "http://example.com",
                    "privacyPolicyURL": "https://example.com/privacy",
                    "termsOfServiceURL": "https://example.com/terms",
                    "composerIcon": "../icon.svg"
                  }
                }
                """,
                encoding="utf-8",
            )
            r = check_interface_assets(plugin_dir)
            assert not r.passed and r.points == 0


class TestRunManifestChecks:
    def test_good_plugin_gets_31(self):
        results = run_manifest_checks(FIXTURES / "good-plugin")
        assert sum(c.points for c in results) == 31
        assert all(c.passed for c in results)

    def test_bad_plugin_fails_version_and_name(self):
        results = run_manifest_checks(FIXTURES / "bad-plugin")
        names = {c.name: c.passed for c in results}
        assert names["Version follows semver"] is False
        assert names["Name is kebab-case"] is False

    def test_minimal_plugin_gets_21(self):
        results = run_manifest_checks(FIXTURES / "minimal-plugin")
        assert sum(c.points for c in results) == 21

    def test_malformed_json_gets_4(self):
        results = run_manifest_checks(FIXTURES / "malformed-json")
        assert sum(c.points for c in results) == 4

    def test_empty_dir_gets_0(self):
        results = run_manifest_checks(FIXTURES / "empty-dir")
        assert sum(c.points for c in results) == 0

    def test_returns_tuple_of_correct_length(self):
        results = run_manifest_checks(FIXTURES / "good-plugin")
        assert isinstance(results, tuple)
        assert len(results) == 9
