"""Blocked request behavior is global, persisted, and opt-in for prompting."""

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.blocked_request_mode import safe_alternative_reason
from codex_plugin_scanner.guard.cli.commands_support_prompts import _runtime_artifact_native_reason
from codex_plugin_scanner.guard.config import GuardConfig, load_guard_config, update_guard_settings
from codex_plugin_scanner.guard.models import GuardArtifact


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
