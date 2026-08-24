"""Tests for scanner config and baseline loading."""

from pathlib import Path

import pytest

from codex_plugin_scanner.config import ConfigError, load_baseline_rule_ids, load_scanner_config


def test_load_scanner_config_discovery(tmp_path: Path) -> None:
    config = load_scanner_config(tmp_path)
    assert config.profile is None
    assert not config.enabled_rules
    (tmp_path / ".codex-plugin-scanner.toml").write_text(
        '[scanner]\nprofile = "default"\n',
        encoding="utf-8",
    )
    config = load_scanner_config(tmp_path)
    assert config.profile == "default"
    (tmp_path / ".plugin-scanner.toml").write_text("[scanner]\nprofile = 'strict-security'\n", encoding="utf-8")
    assert load_scanner_config(tmp_path).profile == "strict-security"
    plugin_dir = tmp_path / "plugins" / "example"
    plugin_dir.mkdir(parents=True)
    (plugin_dir / ".plugin-scanner.toml").write_text("[scanner]\nprofile = 'strict-security'\n", encoding="utf-8")
    assert load_scanner_config(plugin_dir, config_path=".plugin-scanner.toml").profile == "strict-security"


def test_load_scanner_config_toml_and_github_validation(tmp_path: Path) -> None:
    config_dir = tmp_path / "full"
    config_dir.mkdir()
    (config_dir / ".plugin-scanner.toml").write_text(
        """
[scanner]
profile = "strict-security"
baseline_file = "baseline.txt"
ignore_paths = ["tests/*"]
[rules]
enabled = ["README_MISSING"]
disabled = ["HARDCODED_SECRET"]
severity_overrides = { README_MISSING = "low" }
[github]
pr_comment = "always"
pr_comment_style = "detailed"
pr_comment_max_findings = 7
""",
        encoding="utf-8",
    )
    config = load_scanner_config(config_dir)
    assert config.profile == "strict-security"
    assert "README_MISSING" in config.enabled_rules and "HARDCODED_SECRET" in config.disabled_rules
    assert config.ignore_paths == ("tests/*",)
    assert (config.github_pr_comment, config.github_pr_comment_style, config.github_pr_comment_max_findings) == (
        "always",
        "detailed",
        7,
    )
    github_dir = tmp_path / "github-non-table"
    github_dir.mkdir()
    (github_dir / ".plugin-scanner.toml").write_text(
        """
github = "off"
[scanner]
profile = "default"
""",
        encoding="utf-8",
    )

    config = load_scanner_config(github_dir)
    assert config.profile == "default"
    assert (config.github_pr_comment, config.github_pr_comment_style, config.github_pr_comment_max_findings) == (
        None,
        None,
        None,
    )


def test_load_baseline_rule_ids_text_and_bad_json(tmp_path: Path) -> None:
    (tmp_path / "baseline.txt").write_text("README_MISSING\nHARDCODED_SECRET\n", encoding="utf-8")
    assert load_baseline_rule_ids(tmp_path, "baseline.txt") == frozenset({"README_MISSING", "HARDCODED_SECRET"})
    (tmp_path / "baseline.json").write_text("[not-valid-json", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_baseline_rule_ids(tmp_path, "baseline.json")


def test_load_scanner_config_errors(tmp_path: Path) -> None:
    (tmp_path / ".plugin-scanner.toml").write_text("[scanner\nprofile='x'", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_scanner_config(tmp_path)
    with pytest.raises(ConfigError):
        load_scanner_config(tmp_path, config_path=str(tmp_path / "missing.toml"))
