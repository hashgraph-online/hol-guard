"""Blocked request behavior is global, persisted, and opt-in for prompting."""

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.blocked_request_mode import safe_alternative_reason
from codex_plugin_scanner.guard.cli.commands_support_prompts import _runtime_artifact_native_reason
from codex_plugin_scanner.guard.config import GuardConfig, load_guard_config, update_guard_settings
from codex_plugin_scanner.guard.models import GuardArtifact
from codex_plugin_scanner.guard.secrets.public_rule_catalog import public_output_family_label


def test_prompt_mode_defaults_and_round_trip(tmp_path: Path) -> None:
    assert GuardConfig(guard_home=tmp_path, workspace=None).blocked_request_mode == "safe-alternative"
    assert load_guard_config(tmp_path).blocked_request_mode == "safe-alternative"
    update_guard_settings(tmp_path, {"blocked_request_mode": "ask"})
    assert load_guard_config(tmp_path).blocked_request_mode == "ask"
    update_guard_settings(tmp_path, {"blocked_request_mode": "safe-alternative"})
    assert load_guard_config(tmp_path).blocked_request_mode == "safe-alternative"


@pytest.mark.parametrize("value", ["always-allow", None, True, {}])
def test_prompt_mode_rejects_invalid_settings(tmp_path: Path, value: object) -> None:
    with pytest.raises(ValueError):
        update_guard_settings(tmp_path, {"blocked_request_mode": value})


def test_workspace_cannot_enable_prompts(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / ".hol-guard.toml").write_text('blocked_request_mode = "ask"\n')
    assert load_guard_config(tmp_path / "guard-home", workspace=workspace).blocked_request_mode == "safe-alternative"


def test_terminal_cli_response_preserves_safe_alternative_guidance() -> None:
    guidance = safe_alternative_reason("HOL Guard blocked this action.")
    artifact = GuardArtifact(
        artifact_id="guarded-tool",
        harness="zcode",
        artifact_type="prompt_request",
        name="Guarded tool",
        source_scope="project",
        config_path="config.json",
        command=None,
        args=(),
        transport="stdio",
    )
    reason = _runtime_artifact_native_reason(
        artifact,
        {
            "policy_action": "block",
            "blocked_request_guidance": guidance,
            "decision_v2_json": {"harness_message": "Wait for approval."},
        },
    )
    assert reason == guidance
    assert "Wait for approval" not in reason


def _tool_output_artifact(secret_source_family: str) -> GuardArtifact:
    return GuardArtifact(
        artifact_id="tool-output",
        name="Tool output",
        harness="codex",
        artifact_type="tool_action_request",
        source_scope="project",
        config_path="config.json",
        metadata={
            "runtime_request_signals": ["tool output contains credential-looking material"],
            "secret_source_family": secret_source_family,
        },
    )


def test_public_output_family_label_keeps_catalogued_text_only() -> None:
    assert public_output_family_label("local .env file and other local secret files") == (
        "local .env file and other local secret files"
    )
    leaked = "sk-" + "testtoken12345678"
    assert public_output_family_label(leaked) is None
    assert public_output_family_label(f"{leaked} and other local secret files") is None


def test_native_reason_names_a_catalogued_source_family() -> None:
    reason = _runtime_artifact_native_reason(
        _tool_output_artifact("Kubernetes pod environment"),
        {"policy_action": "block"},
    )
    assert "Kubernetes pod environment" in reason
    assert reason.startswith("HOL Guard blocked this tool output because it contains sensitive content from ")


def test_native_reason_does_not_echo_an_uncatalogued_source_family() -> None:
    leaked = "sk-" + "testtoken12345678"
    reason = _runtime_artifact_native_reason(
        _tool_output_artifact(leaked),
        {"policy_action": "block"},
    )
    assert leaked not in reason
    assert "sensitive content" in reason
