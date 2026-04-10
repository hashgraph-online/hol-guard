"""Tests for scanner config and baseline loading."""

from pathlib import Path

from codex_plugin_scanner.config import ConfigError, load_baseline_rule_ids, load_scanner_config


def test_load_scanner_config_defaults(tmp_path: Path):
    config = load_scanner_config(tmp_path)
    assert config.profile is None
    assert not config.enabled_rules


def test_load_scanner_config_from_toml(tmp_path: Path):
    (tmp_path / ".plugin-scanner.toml").write_text(
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


def test_load_scanner_config_supports_legacy_filename(tmp_path: Path):
    (tmp_path / ".codex-plugin-scanner.toml").write_text(
        """
[scanner]
profile = "default"
""",
        encoding="utf-8",
    )
    config = load_scanner_config(tmp_path)
    assert config.profile == "default"


def test_load_scanner_config_prefers_generic_filename(tmp_path: Path):
    (tmp_path / ".plugin-scanner.toml").write_text("[scanner]\nprofile = 'strict-security'\n", encoding="utf-8")
    (tmp_path / ".codex-plugin-scanner.toml").write_text("[scanner]\nprofile = 'default'\n", encoding="utf-8")
    config = load_scanner_config(tmp_path)
    assert config.profile == "strict-security"


def test_load_baseline_rule_ids_text(tmp_path: Path):
    (tmp_path / "baseline.txt").write_text("README_MISSING\nHARDCODED_SECRET\n", encoding="utf-8")
    baseline = load_baseline_rule_ids(tmp_path, "baseline.txt")
    assert baseline == frozenset({"README_MISSING", "HARDCODED_SECRET"})


def test_load_scanner_config_bad_toml(tmp_path: Path):
    (tmp_path / ".plugin-scanner.toml").write_text("[scanner\nprofile='x'", encoding="utf-8")
    try:
        load_scanner_config(tmp_path)
        raise AssertionError("expected ConfigError")
    except ConfigError:
        assert True


def test_load_scanner_config_explicit_missing_file_raises(tmp_path: Path):
    try:
        load_scanner_config(tmp_path, config_path=str(tmp_path / "missing.toml"))
        raise AssertionError("expected ConfigError")
    except ConfigError:
        assert True


def test_load_scanner_config_resolves_relative_explicit_path_from_plugin_dir(tmp_path: Path):
    plugin_dir = tmp_path / "plugins" / "example"
    plugin_dir.mkdir(parents=True)
    (plugin_dir / ".plugin-scanner.toml").write_text("[scanner]\nprofile = 'strict-security'\n", encoding="utf-8")

    config = load_scanner_config(plugin_dir, config_path=".plugin-scanner.toml")

    assert config.profile == "strict-security"


def test_load_baseline_bad_json(tmp_path: Path):
    (tmp_path / "baseline.json").write_text("[not-valid-json", encoding="utf-8")
    try:
        load_baseline_rule_ids(tmp_path, "baseline.json")
        raise AssertionError("expected ConfigError")
    except ConfigError:
        assert True
