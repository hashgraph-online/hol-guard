"""Behavior tests for Guard settings presets (L288-L291)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.config import (
    SECURITY_LEVEL_RISK_ACTIONS,
    VALID_RISK_ACTION_KEYS,
    load_guard_config,
    resolve_risk_action,
)


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


_PRESET_SENTINEL: dict[str, dict[str, str]] = {
    "gentle": {
        "local_secret_read": "warn",
        "credential_exfiltration": "warn",
        "network_egress": "allow",
        "guard_bypass": "warn",
        "prompt_injection": "warn",
    },
    "balanced": {
        "local_secret_read": "require-reapproval",
        "credential_exfiltration": "require-reapproval",
        "network_egress": "warn",
        "guard_bypass": "block",
        "prompt_injection": "require-reapproval",
    },
    "strict": {
        "local_secret_read": "require-reapproval",
        "data_flow_exfiltration": "block",
        "network_egress": "require-reapproval",
        "guard_bypass": "block",
        "prompt_injection": "block",
    },
    "paranoid": {
        "local_secret_read": "block",
        "credential_exfiltration": "block",
        "network_egress": "block",
        "guard_bypass": "block",
        "prompt_injection": "block",
    },
}


class TestPresetRiskActionMaps:
    """L288 — each named preset maps every risk key to the expected action."""

    @pytest.mark.parametrize("preset", ["relaxed", "gentle", "balanced", "strict", "paranoid"])
    def test_preset_covers_all_risk_keys(self, preset: str) -> None:
        assert set(SECURITY_LEVEL_RISK_ACTIONS[preset].keys()) == VALID_RISK_ACTION_KEYS

    @pytest.mark.parametrize("preset,sentinel", list(_PRESET_SENTINEL.items()))
    def test_preset_sentinel_actions_match_spec(self, tmp_path: Path, preset: str, sentinel: dict[str, str]) -> None:
        home_dir = tmp_path / "home"
        _write_text(home_dir / "config.toml", f'security_level = "{preset}"\n')
        config = load_guard_config(home_dir)
        for risk_key, expected_action in sentinel.items():
            actual = resolve_risk_action(config, risk_key, harness="codex")
            assert actual == expected_action, (
                f"preset={preset} risk={risk_key}: expected {expected_action!r} got {actual!r}"
            )

    def test_gentle_is_least_restrictive(self, tmp_path: Path) -> None:
        home_dir = tmp_path / "home"
        _write_text(home_dir / "config.toml", 'security_level = "gentle"\n')
        config = load_guard_config(home_dir)
        for risk_key in VALID_RISK_ACTION_KEYS:
            action = resolve_risk_action(config, risk_key, harness="codex")
            assert action in ("allow", "warn"), f"gentle preset should not block {risk_key}, got {action!r}"

    def test_paranoid_blocks_all(self, tmp_path: Path) -> None:
        home_dir = tmp_path / "home"
        _write_text(home_dir / "config.toml", 'security_level = "paranoid"\n')
        config = load_guard_config(home_dir)
        for risk_key in VALID_RISK_ACTION_KEYS:
            action = resolve_risk_action(config, risk_key, harness="codex")
            assert action == "block", f"paranoid preset should block {risk_key}, got {action!r}"


class TestPresetCliCommands:
    """L289 — CLI preset commands write correct config that resolve_risk_action honors."""

    @pytest.mark.parametrize("preset", ["relaxed", "gentle", "balanced", "strict", "paranoid"])
    def test_settings_preset_command_sets_level(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str], preset: str
    ) -> None:
        home_dir = tmp_path / "home"
        _write_text(home_dir / "config.toml", 'security_level = "custom"\n')
        rc = main(["guard", "settings", "set", "preset", preset, "--home", str(home_dir), "--json"])
        assert rc == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["settings"]["security_level"] == preset
        loaded = load_guard_config(home_dir)
        assert loaded.security_level == preset

    @pytest.mark.parametrize("preset", ["gentle", "balanced", "strict", "paranoid"])
    def test_settings_preset_clears_override_risk_actions(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str], preset: str
    ) -> None:
        home_dir = tmp_path / "home"
        config_toml = (
            'security_level = "custom"\n'
            "[risk_actions]\n"
            'local_secret_read = "allow"\n'
            "[harness_risk_actions.codex]\n"
            'local_secret_read = "allow"\n'
        )
        _write_text(home_dir / "config.toml", config_toml)
        rc = main(["guard", "settings", "set", "preset", preset, "--home", str(home_dir), "--json"])
        assert rc == 0
        capsys.readouterr()
        loaded = load_guard_config(home_dir)
        expected = SECURITY_LEVEL_RISK_ACTIONS[preset]["local_secret_read"]
        actual = resolve_risk_action(loaded, "local_secret_read", harness="codex")
        assert actual == expected
        assert loaded.risk_actions == {}
        assert loaded.harness_risk_actions == {}


class TestCustomModeActivation:
    """L290 — granular risk action overrides take effect without losing preset context."""

    def test_set_risk_action_override_applied_on_balanced(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        home_dir = tmp_path / "home"
        _write_text(home_dir / "config.toml", 'security_level = "balanced"\n')
        rc = main(
            [
                "guard",
                "settings",
                "set",
                "risk",
                "network_egress",
                "block",
                "--home",
                str(home_dir),
                "--json",
            ]
        )
        assert rc == 0
        capsys.readouterr()
        loaded = load_guard_config(home_dir)
        assert resolve_risk_action(loaded, "network_egress", harness="codex") == "block"
        assert loaded.risk_actions.get("network_egress") == "block"
        assert loaded.security_level == "balanced"

    def test_set_risk_action_override_applied_on_strict(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        home_dir = tmp_path / "home"
        _write_text(home_dir / "config.toml", 'security_level = "strict"\n')
        rc = main(
            [
                "guard",
                "settings",
                "set",
                "risk",
                "local_secret_read",
                "warn",
                "--home",
                str(home_dir),
                "--json",
            ]
        )
        assert rc == 0
        capsys.readouterr()
        loaded = load_guard_config(home_dir)
        assert resolve_risk_action(loaded, "local_secret_read", harness="codex") == "warn"
        assert loaded.risk_actions.get("local_secret_read") == "warn"
        assert loaded.security_level == "strict"

    def test_explicit_custom_mode_preserves_effective_risks(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        home_dir = tmp_path / "home"
        _write_text(home_dir / "config.toml", 'security_level = "strict"\n')
        rc = main(["guard", "settings", "set", "security-level", "custom", "--home", str(home_dir), "--json"])
        assert rc == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["settings"]["security_level"] == "custom"
        loaded = load_guard_config(home_dir)
        assert loaded.security_level == "custom"
        for key in VALID_RISK_ACTION_KEYS:
            action = resolve_risk_action(loaded, key, harness="codex")
            assert action in ("allow", "warn", "block", "require-reapproval")

    def test_applying_preset_after_override_restores_named_preset(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        home_dir = tmp_path / "home"
        _write_text(
            home_dir / "config.toml",
            'security_level = "custom"\n[risk_actions]\nnetwork_egress = "block"\n',
        )
        rc = main(["guard", "settings", "set", "preset", "balanced", "--home", str(home_dir), "--json"])
        assert rc == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["settings"]["security_level"] == "balanced"
        loaded = load_guard_config(home_dir)
        assert loaded.security_level == "balanced"
        assert resolve_risk_action(loaded, "network_egress", harness="codex") == "warn"


class TestSettingsExplainCommand:
    """L287 — settings explain returns preset description and current level."""

    @pytest.mark.parametrize("preset", ["gentle", "balanced", "strict", "paranoid"])
    def test_settings_explain_json_fields(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str], preset: str
    ) -> None:
        home_dir = tmp_path / "home"
        _write_text(home_dir / "config.toml", f'security_level = "{preset}"\n')
        rc = main(["guard", "settings", "explain", "--home", str(home_dir), "--json"])
        assert rc == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload["preset"] == preset
        assert isinstance(payload["description"], str)
        assert len(payload["description"]) > 0


class TestConfigMigration:
    """L282 — users on balanced/strict/custom retain their level after migration."""

    @pytest.mark.parametrize("level", ["balanced", "strict", "custom"])
    def test_existing_level_preserved_after_load(self, tmp_path: Path, level: str) -> None:
        home_dir = tmp_path / "home"
        _write_text(home_dir / "config.toml", f'security_level = "{level}"\n')
        loaded = load_guard_config(home_dir)
        assert loaded.security_level == level

    def test_unknown_level_falls_back_to_balanced(self, tmp_path: Path) -> None:
        home_dir = tmp_path / "home"
        _write_text(home_dir / "config.toml", 'security_level = "ultra-strict"\n')
        loaded = load_guard_config(home_dir)
        assert loaded.security_level == "balanced"
