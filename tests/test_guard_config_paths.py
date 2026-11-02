"""Regression tests for Guard branding on local state paths."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.config import (
    load_guard_config,
    resolve_guard_home,
    resolve_risk_action,
    update_guard_settings,
)
from codex_plugin_scanner.guard.mdm import runtime_request as runtime_request_module

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    import tomli as tomllib  # type: ignore[no-redef]


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_resolve_guard_home_defaults_to_hol_guard_directory(tmp_path, monkeypatch):
    home_dir = tmp_path / "home"
    monkeypatch.setattr(Path, "home", lambda: home_dir)

    assert resolve_guard_home() == home_dir / ".hol-guard"


def test_dashboard_settings_update_persists_to_cli_config_loader(tmp_path):
    guard_home = tmp_path / ".hol-guard"
    _write_text(
        guard_home / "config.toml",
        'mode = "prompt"\ndefault_action = "warn"\n\n[harnesses]\ncodex = "review"\n',
    )

    updated = update_guard_settings(
        guard_home,
        {
            "mode": "enforce",
            "default_action": "review",
            "changed_hash_action": "block",
            "approval_wait_timeout_seconds": 45,
            "approval_surface_policy": "approval-center",
            "telemetry": True,
            "ignored_key": "ignored",
        },
    )
    loaded = load_guard_config(guard_home)
    config_text = (guard_home / "config.toml").read_text(encoding="utf-8")

    assert updated.mode == "enforce"
    assert loaded.mode == "enforce"
    assert loaded.default_action == "review"
    assert loaded.changed_hash_action == "block"
    assert loaded.approval_wait_timeout_seconds == 45
    assert loaded.approval_surface_policy == "attention-aware"
    assert loaded.telemetry is True
    assert loaded.harness_actions == {"codex": "review"}
    assert "ignored_key" not in config_text


def test_guard_config_loads_security_level_and_risk_action_overrides(tmp_path):
    guard_home = tmp_path / ".hol-guard"
    _write_text(
        guard_home / "config.toml",
        "\n".join(
            [
                'security_level = "custom"',
                "",
                "[risk_actions]",
                'local_secret_read = "allow"',
                'credential_exfiltration = "block"',
                'data_flow_exfiltration = "block"',
                "",
                "[harness_risk_actions.codex]",
                'local_secret_read = "allow"',
                'data_flow_exfiltration = "block"',
                'destructive_shell = "require-reapproval"',
            ]
        )
        + "\n",
    )

    config = load_guard_config(guard_home)

    assert config.security_level == "custom"
    assert config.risk_actions == {
        "local_secret_read": "allow",
        "credential_exfiltration": "block",
        "data_flow_exfiltration": "block",
    }
    assert config.harness_risk_actions == {
        "codex": {
            "local_secret_read": "allow",
            "data_flow_exfiltration": "block",
            "destructive_shell": "require-reapproval",
        }
    }
    assert resolve_risk_action(config, "local_secret_read", harness="codex") == "allow"
    assert resolve_risk_action(config, "credential_exfiltration", harness="codex") == "block"
    assert resolve_risk_action(config, "data_flow_exfiltration", harness="codex") == "block"


def test_load_guard_config_reads_the_workspace_assessment_switch(tmp_path):
    guard_home = tmp_path / ".hol-guard"

    assert load_guard_config(guard_home).workspace_assessment_enabled is True

    _write_text(guard_home / "config.toml", "workspace_assessment_enabled = false\n")

    assert load_guard_config(guard_home).workspace_assessment_enabled is False


def test_load_guard_config_parses_hidden_runtime_detector_registry(tmp_path):
    guard_home = tmp_path / ".hol-guard"
    _write_text(
        guard_home / "config.toml",
        "\n".join(
            [
                "runtime_detector_registry = true",
                "runtime_detector_timeout_ms = 75",
                "runtime_detector_debug_trace = true",
                'runtime_detector_disabled_ids = ["secret.local"]',
            ]
        )
        + "\n",
    )

    config = load_guard_config(guard_home)

    assert config.runtime_detector_registry is True
    assert config.runtime_detector_timeout_ms == 75
    assert config.runtime_detector_debug_trace is True
    assert config.runtime_detector_disabled_ids == ("secret.local",)


def test_guard_config_strict_profile_defaults_review_sensitive_risks(tmp_path):
    guard_home = tmp_path / ".hol-guard"
    _write_text(guard_home / "config.toml", 'security_level = "strict"\n')

    config = load_guard_config(guard_home)

    assert config.security_level == "strict"
    assert resolve_risk_action(config, "local_secret_read", harness="codex") == "require-reapproval"
    assert resolve_risk_action(config, "data_flow_exfiltration", harness="codex") == "block"
    assert resolve_risk_action(config, "encoded_execution", harness="codex") == "require-reapproval"
    assert resolve_risk_action(config, "network_egress", harness="codex") == "require-reapproval"


def test_guard_config_balanced_profile_defaults_data_flow_exfil_to_review(tmp_path):
    guard_home = tmp_path / ".hol-guard"
    _write_text(guard_home / "config.toml", 'security_level = "balanced"\n')

    config = load_guard_config(guard_home)

    assert resolve_risk_action(config, "data_flow_exfiltration", harness="codex") == "require-reapproval"


def test_guard_config_invalid_security_level_falls_back_to_balanced(tmp_path):
    guard_home = tmp_path / ".hol-guard"
    _write_text(guard_home / "config.toml", 'security_level = "surprise-me"\n')

    config = load_guard_config(guard_home)

    assert config.security_level == "balanced"
    assert resolve_risk_action(config, "network_egress", harness="codex") == "warn"


def test_dashboard_settings_update_persists_security_level_and_risk_actions(tmp_path):
    guard_home = tmp_path / ".hol-guard"
    _write_text(guard_home / "config.toml", 'mode = "prompt"\n')

    updated = update_guard_settings(
        guard_home,
        {
            "security_level": "custom",
            "risk_actions": {"local_secret_read": "allow"},
            "harness_risk_actions": {"codex": {"credential_exfiltration": "require-reapproval"}},
        },
    )
    loaded = load_guard_config(guard_home)

    assert updated.security_level == "custom"
    assert loaded.security_level == "custom"
    assert resolve_risk_action(loaded, "local_secret_read", harness="claude-code") == "allow"
    assert resolve_risk_action(loaded, "credential_exfiltration", harness="codex") == "require-reapproval"


def test_dashboard_settings_switch_to_custom_carries_forward_effective_risk_map(tmp_path):
    guard_home = tmp_path / ".hol-guard"
    _write_text(guard_home / "config.toml", 'security_level = "strict"\n')

    updated = update_guard_settings(
        guard_home,
        {
            "security_level": "custom",
        },
    )
    loaded = load_guard_config(guard_home)

    assert updated.security_level == "custom"
    assert loaded.security_level == "custom"
    assert loaded.risk_actions == {
        "local_secret_read": "require-reapproval",
        "credential_exfiltration": "require-reapproval",
        "data_flow_exfiltration": "block",
        "destructive_shell": "require-reapproval",
        "encoded_execution": "require-reapproval",
        "network_egress": "require-reapproval",
        "prompt_injection": "block",
        "mcp_dangerous_tool": "block",
        "malicious_skill": "block",
        "package_script": "require-reapproval",
        "persistence": "block",
        "guard_bypass": "block",
        "cloud_advisory": "require-reapproval",
        "encoded_exfiltration": "block",
        "package_unknown": "block",
        "package_lockfile_drift": "require-reapproval",
        "package_direct_source": "require-reapproval",
        "package_custom_registry": "allow",
        "package_install": "allow",
        "low_trust_artifact": "require-reapproval",
        "runtime_known_vulnerable": "block",
    }
    assert resolve_risk_action(loaded, "network_egress", harness="codex") == "require-reapproval"


def test_dashboard_settings_update_preserves_nested_cli_policy_tables(tmp_path):
    guard_home = tmp_path / ".hol-guard"
    _write_text(
        guard_home / "config.toml",
        "\n".join(
            [
                'mode = "prompt"',
                "",
                "[harnesses.codex]",
                'default_action = "review"',
                "",
                '[publishers."@scope/pkg"]',
                'action = "block"',
                "",
                '[artifacts."codex:project:workspace-tools"]',
                'action = "allow"',
            ]
        )
        + "\n",
    )

    updated = update_guard_settings(
        guard_home,
        {
            "mode": "enforce",
            "approval_wait_timeout_seconds": 30,
        },
    )
    loaded = load_guard_config(guard_home)
    config_text = (guard_home / "config.toml").read_text(encoding="utf-8")

    assert updated.mode == "enforce"
    assert loaded.mode == "enforce"
    assert loaded.approval_wait_timeout_seconds == 30
    assert loaded.harness_actions == {"codex": "review"}
    assert loaded.publisher_actions == {"@scope/pkg": "block"}
    assert loaded.artifact_actions == {"codex:project:workspace-tools": "allow"}
    assert "[harnesses.codex]" in config_text
    assert '[publishers."@scope/pkg"]' in config_text
    assert '[artifacts."codex:project:workspace-tools"]' in config_text


def test_dashboard_settings_update_rejects_boolean_approval_timeout(tmp_path):
    guard_home = tmp_path / ".hol-guard"
    _write_text(
        guard_home / "config.toml",
        'mode = "prompt"\napproval_wait_timeout_seconds = 45\n',
    )

    with pytest.raises(ValueError, match="Approval wait timeout"):
        update_guard_settings(
            guard_home,
            {
                "approval_wait_timeout_seconds": True,
            },
        )

    loaded = load_guard_config(guard_home)
    assert loaded.approval_wait_timeout_seconds == 45


def test_dashboard_settings_update_preserves_existing_float_config_values(tmp_path):
    guard_home = tmp_path / ".hol-guard"
    _write_text(
        guard_home / "config.toml",
        'mode = "prompt"\nscore_threshold = 0.75\n',
    )

    updated = update_guard_settings(
        guard_home,
        {
            "mode": "enforce",
        },
    )
    config_payload = tomllib.loads((guard_home / "config.toml").read_text(encoding="utf-8"))

    assert updated.mode == "enforce"
    assert config_payload["score_threshold"] == 0.75
    assert isinstance(config_payload["score_threshold"], float)


def test_dashboard_settings_update_preserves_existing_array_config_values(tmp_path):
    guard_home = tmp_path / ".hol-guard"
    _write_text(
        guard_home / "config.toml",
        'mode = "prompt"\ntrusted_harnesses = ["codex", "claude-code"]\n',
    )

    updated = update_guard_settings(
        guard_home,
        {
            "mode": "enforce",
        },
    )
    config_payload = tomllib.loads((guard_home / "config.toml").read_text(encoding="utf-8"))

    assert updated.mode == "enforce"
    assert config_payload["trusted_harnesses"] == ["codex", "claude-code"]


def test_dashboard_settings_update_preserves_existing_inline_table_array_config_values(tmp_path):
    guard_home = tmp_path / ".hol-guard"
    _write_text(
        guard_home / "config.toml",
        'mode = "prompt"\nrules = [{ name = "canary", action = "review", weight = 0.5 }]\n',
    )

    updated = update_guard_settings(
        guard_home,
        {
            "mode": "enforce",
        },
    )
    config_payload = tomllib.loads((guard_home / "config.toml").read_text(encoding="utf-8"))

    assert updated.mode == "enforce"
    assert config_payload["rules"] == [{"name": "canary", "action": "review", "weight": 0.5}]


def _answer_guard_home(monkeypatch, answer):
    requests: list[dict[str, object]] = []

    def _runtime_answer(feature, command, request, **_kwargs):
        assert (feature, command) == ("native-guard-home-resolve-v1", "guard-home-resolve")
        requests.append(request)
        return answer

    monkeypatch.setattr(runtime_request_module, "runtime_answer", _runtime_answer)
    return requests


def test_resolve_guard_home_skips_the_runtime_without_a_legacy_home(tmp_path, monkeypatch):
    home_dir = tmp_path / "home"
    monkeypatch.setattr(Path, "home", lambda: home_dir)
    requests = _answer_guard_home(monkeypatch, {"guard_home": "/elsewhere"})

    assert resolve_guard_home() == home_dir / ".hol-guard"
    assert requests == []


def test_resolve_guard_home_uses_the_home_the_runtime_answers(tmp_path, monkeypatch):
    home_dir = tmp_path / "home"
    legacy_home = home_dir / ".ai-plugin-scanner-guard"
    legacy_home.mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: home_dir)
    requests = _answer_guard_home(monkeypatch, {"guard_home": str(legacy_home)})

    assert resolve_guard_home() == legacy_home
    assert requests == [{"schema": "guard-home-resolve.v1", "user_home": str(home_dir.absolute())}]


def test_resolve_guard_home_asks_the_runtime_once_after_it_picks_the_canonical_home(tmp_path, monkeypatch):
    home_dir = tmp_path / "home"
    canonical_home = home_dir / ".hol-guard"
    (home_dir / ".ai-plugin-scanner-guard").mkdir(parents=True)
    canonical_home.mkdir()
    monkeypatch.setattr(Path, "home", lambda: home_dir)
    requests = _answer_guard_home(monkeypatch, {"guard_home": str(canonical_home)})

    assert resolve_guard_home() == canonical_home
    assert resolve_guard_home() == canonical_home
    assert len(requests) == 1


def test_resolve_guard_home_without_the_runtime_keeps_the_legacy_home_until_canonical_exists(tmp_path, monkeypatch):
    home_dir = tmp_path / "home"
    legacy_home = home_dir / ".ai-plugin-scanner-guard"
    legacy_home.mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: home_dir)
    _answer_guard_home(monkeypatch, None)

    assert resolve_guard_home() == legacy_home
    (home_dir / ".hol-guard").mkdir()
    assert resolve_guard_home() == home_dir / ".hol-guard"


def test_load_guard_config_ignores_workspace_default_action_overrides(tmp_path):
    guard_home = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    guard_home.mkdir(parents=True, exist_ok=True)
    _write_text(guard_home / "config.toml", 'default_action = "warn"\n')
    _write_text(workspace_dir / ".ai-plugin-scanner-guard.toml", 'default_action = "allow"\n')
    _write_text(workspace_dir / ".hol-guard.toml", 'default_action = "block"\n')

    config = load_guard_config(guard_home, workspace_dir)

    assert config.default_action == "warn"


def test_load_guard_config_ignores_workspace_action_tables_across_legacy_and_hol_guard_files(tmp_path):
    guard_home = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    guard_home.mkdir(parents=True, exist_ok=True)
    _write_text(
        workspace_dir / ".ai-plugin-scanner-guard.toml",
        "\n".join(
            [
                "[harnesses.codex]",
                'default_action = "allow"',
            ]
        )
        + "\n",
    )
    _write_text(
        workspace_dir / ".hol-guard.toml",
        "\n".join(
            [
                "[harnesses.claude-code]",
                'default_action = "block"',
            ]
        )
        + "\n",
    )

    config = load_guard_config(guard_home, workspace_dir)

    assert config.harness_actions == {}


def test_load_guard_config_preserves_home_action_aliases_when_workspace_tries_to_override(tmp_path):
    guard_home = tmp_path / "guard-home"
    workspace_dir = tmp_path / "workspace"
    guard_home.mkdir(parents=True, exist_ok=True)
    _write_text(
        guard_home / "config.toml",
        "\n".join(
            [
                "[harnesses.codex]",
                'action = "review"',
            ]
        )
        + "\n",
    )
    _write_text(
        workspace_dir / ".ai-plugin-scanner-guard.toml",
        "\n".join(
            [
                "[harnesses.codex]",
                'action = "block"',
            ]
        )
        + "\n",
    )
    _write_text(
        workspace_dir / ".hol-guard.toml",
        "\n".join(
            [
                "[harnesses.codex]",
                'default_action = "allow"',
            ]
        )
        + "\n",
    )

    config = load_guard_config(guard_home, workspace_dir)

    assert config.harness_actions == {"codex": "review"}


def test_sandbox_analysis_default_is_off(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    config = load_guard_config(guard_home)
    assert config.sandbox_analysis == "off"


def test_sandbox_analysis_suspicious_loaded(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    (guard_home / "config.toml").write_text('sandbox_analysis = "suspicious"\n', encoding="utf-8")
    config = load_guard_config(guard_home)
    assert config.sandbox_analysis == "suspicious"


def test_sandbox_analysis_strict_loaded(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    (guard_home / "config.toml").write_text('sandbox_analysis = "strict"\n', encoding="utf-8")
    config = load_guard_config(guard_home)
    assert config.sandbox_analysis == "strict"


def test_sandbox_analysis_invalid_falls_back_to_off(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    (guard_home / "config.toml").write_text('sandbox_analysis = "dangerous_unknown_value"\n', encoding="utf-8")
    config = load_guard_config(guard_home)
    assert config.sandbox_analysis == "off"
