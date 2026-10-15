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


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        ("native_destructive_command", "git worktree remove"),
        ("native_package_review", "--ignore-scripts"),
        ("native_command_review_required", "read-only"),
        ("native_network_review", "network request"),
        ("native_pre_tool_unknown_review", "cannot check what this tool call"),
    ],
)
def test_specific_deny_text_names_reason_and_inbox_when_approval_queued(code: str, expected: str) -> None:
    text = safe_alternative_reason("HOL Guard blocked this action.", reason_code=code, approval_queued=True)
    assert expected in text
    assert "HOL Guard inbox" in text
    assert "hol-guard approvals" in text
    assert "Do not retry the same action until it is approved" in text
    assert "safe, permitted alternative" not in text


def test_package_hint_names_the_frozen_install_without_promising_it() -> None:
    # Only a frozen, script-free lockfile restore can be proven, and only when
    # the project checks out, so the hint names that exact form and tells an
    # agent that already used it to stop rather than loop.
    text = safe_alternative_reason("Blocked.", reason_code="native_package_review", approval_queued=True)
    assert "`bun install --frozen-lockfile --ignore-scripts`" in text
    assert "`npm ci --ignore-scripts`" in text
    assert "If this was already that form" in text
    assert "Use `--ignore-scripts`" not in text


def test_package_hint_leaves_the_approval_step_to_the_queue_state() -> None:
    # Without an inbox row, the hint must not send the agent to ask for an approval that cannot be given.
    text = safe_alternative_reason("Blocked.", reason_code="native_package_review", approval_queued=False)
    assert "If this was already that form" in text
    assert "approve this install" not in text
    assert "No approval is waiting in HOL Guard" in text


def test_specific_deny_text_without_queued_approval_points_to_no_approval() -> None:
    text = safe_alternative_reason("Blocked.", reason_code="native_policy_reapproval_required", approval_queued=False)
    assert text.startswith("Blocked. No approval is waiting in HOL Guard")
    assert "Ask the user to approve" not in text
    assert "hol-guard approvals" not in text


def test_extension_failure_keeps_the_native_reason_without_a_generic_hint() -> None:
    reason = "HOL Guard blocked this command because it leaves a quote open."
    text = safe_alternative_reason(
        reason, reason_code="native_command_extension_evaluation_failed", approval_queued=True
    )
    assert text.startswith(reason)
    assert "command substitution" not in text


def test_default_deny_text_is_unchanged_without_native_context() -> None:
    assert "safe, permitted alternative" in safe_alternative_reason("Blocked.")


def test_unbound_review_does_not_tell_the_agent_to_wait_for_approval() -> None:
    # No retry binding: a one-time approval cannot match the retry, so waiting sends the agent into a second block.
    text = safe_alternative_reason(
        "Blocked.", reason_code="native_command_review_required", approval_queued=True, retry_reuses_approval=False
    )
    assert "approving it there will not let you run it" in text
    assert "Do not retry it." in text
    assert "Do not retry the same action until it is approved" not in text


def test_unbound_review_with_exact_action_names_always_allow_as_the_only_way_through() -> None:
    text = safe_alternative_reason(
        "Blocked.",
        reason_code="native_command_review_required",
        approval_queued=True,
        retry_reuses_approval=False,
        exact_action_allowable=True,
    )
    assert "approving it just once will not let you run it" in text
    assert '"Always allow exact action"' in text
    assert "Do not retry the same action until it is approved" not in text


def test_bound_review_keeps_the_wait_for_approval_text() -> None:
    text = safe_alternative_reason(
        "Blocked.", reason_code="native_pre_tool_unknown_review", approval_queued=True, exact_action_allowable=True
    )
    assert "Do not retry the same action until it is approved" in text
    assert "will not let you run it" not in text
