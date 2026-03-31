"""Tests for scanner config and baseline loading."""

from pathlib import Path

from codex_plugin_scanner.config import ConfigError, load_baseline_rule_ids, load_scanner_config


def test_load_scanner_config_defaults(tmp_path: Path):
    config = load_scanner_config(tmp_path)
    assert config.profile is None
    assert not config.enabled_rules


def test_load_scanner_config_from_toml(tmp_path: Path):
    (tmp_path / ".codex-plugin-scanner.toml").write_text(
        """
[scanner]
profile = "strict-security"
baseline_file = "baseline.txt"
ignore_paths = ["tests/*"]
[rules]
enabled = ["README_MISSING"]
disabled = ["HARDCODED_SECRET"]
severity_overrides = { README_MISSING = "low" }
""",
        encoding="utf-8",
    )
    config = load_scanner_config(tmp_path)
    assert config.profile == "strict-security"
    assert "README_MISSING" in config.enabled_rules
    assert "HARDCODED_SECRET" in config.disabled_rules
    assert config.ignore_paths == ("tests/*",)


def test_load_baseline_rule_ids_text(tmp_path: Path):
    (tmp_path / "baseline.txt").write_text("README_MISSING\nHARDCODED_SECRET\n", encoding="utf-8")
    baseline = load_baseline_rule_ids(tmp_path, "baseline.txt")
    assert baseline == frozenset({"README_MISSING", "HARDCODED_SECRET"})


def test_load_scanner_config_bad_toml(tmp_path: Path):
    (tmp_path / ".codex-plugin-scanner.toml").write_text("[scanner\nprofile='x'", encoding="utf-8")
    try:
        load_scanner_config(tmp_path)
        assert False, "expected ConfigError"
    except ConfigError:
        assert True


def test_load_baseline_bad_json(tmp_path: Path):
    (tmp_path / "baseline.json").write_text("[not-valid-json", encoding="utf-8")
    try:
        load_baseline_rule_ids(tmp_path, "baseline.json")
        assert False, "expected ConfigError"
    except ConfigError:
        assert True
