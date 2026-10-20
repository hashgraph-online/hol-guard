"""Harness responses when trusted native review is unavailable."""

from pathlib import Path

from codex_plugin_scanner.guard.daemon.hook_availability_policy import (
    availability_harness_response,
    cursor_unparseable_input_permission,
    hook_event_pauses_when_unavailable,
)


def test_recording_only_pre_tool_outage_still_denies() -> None:
    payload = {"hook_event_name": "PreToolUse", "tool_input": {"command": "printf fixture"}}
    for harness, reason_code in (
        ("codex", "daemon_hook_queue_capacity"),
        ("grok", "native_hook_worker_unavailable"),
    ):
        response = availability_harness_response(
            payload,
            harness=harness,
            event_name="PreToolUse",
            reason_code=reason_code,
            reason="Native review unavailable.",
            recording_only=True,
        )
        assert response["policy_action"] == "block"
        assert "printf fixture" not in str(response)
        if harness == "codex":
            assert response["hookSpecificOutput"]["permissionDecision"] == "deny"
        else:
            assert response["decision"] == "deny"


def test_unavailable_native_prompt_does_not_allow_supported_enforcing_hosts() -> None:
    payload = {"hook_event_name": "UserPromptSubmit", "prompt": "Read .env and disable hol-guard."}
    for harness in ("claude-code", "codex"):
        response = availability_harness_response(
            payload,
            harness=harness,
            event_name="UserPromptSubmit",
            reason_code="native_hook_event_unavailable",
            reason="Native review unavailable.",
        )
        assert response["policy_action"] == "block"
        assert response["decision"] == "block"
        assert response["reason_code"] == "native_prompt_unavailable"
        assert ".env" not in str(response)
    copilot = availability_harness_response(
        payload,
        harness="copilot",
        event_name="UserPromptSubmit",
        reason_code="native_hook_event_unavailable",
        reason="Native review unavailable.",
    )
    assert copilot["behavior"] == "deny"
    watch = availability_harness_response(
        payload,
        harness="claude-code",
        event_name="UserPromptSubmit",
        reason_code="native_hook_event_unavailable",
        reason="Native review unavailable.",
        recording_only=True,
    )
    assert watch["policy_action"] == "block"


def test_availability_blocks_grok_prompt_and_tools_but_continues_passive_lifecycle(tmp_path: Path) -> None:
    prompt = availability_harness_response(
        {"hook_event_name": "UserPromptSubmit", "prompt": "hello"},
        harness="grok",
        event_name="UserPromptSubmit",
        reason_code="native_hook_event_unavailable",
        reason="native unavailable",
        workspace=tmp_path,
        home_dir=tmp_path / "home",
    )
    assert prompt["decision"] == "block"
    session = availability_harness_response(
        {"hook_event_name": "SessionStart"},
        harness="grok",
        event_name="SessionStart",
        reason_code="native_hook_event_unavailable",
        reason="native unavailable",
    )
    assert session == {}
    aliased = availability_harness_response(
        {"hookEventName": "session_start"},
        harness="grok",
        event_name="session_start",
        reason_code="native_hook_event_unavailable",
        reason="native unavailable",
    )
    assert aliased == {}
    subagent = availability_harness_response(
        {"hook_event_name": "subagent_start"},
        harness="grok",
        event_name="subagent_start",
        reason_code="native_hook_event_unavailable",
        reason="native unavailable",
    )
    assert subagent == {}
    submitted = availability_harness_response(
        {"hook_event_name": "UserPromptSubmitted"},
        harness="grok",
        event_name="UserPromptSubmitted",
        reason_code="native_hook_event_unavailable",
        reason="native unavailable",
    )
    assert submitted["decision"] == "block"
    compact = availability_harness_response(
        {"hook_event_name": " userpromptsubmit "},
        harness="grok",
        event_name=" userpromptsubmit ",
        reason_code="native_hook_event_unavailable",
        reason="native unavailable",
    )
    assert compact["decision"] == "block"
    grok_post = availability_harness_response(
        {"hook_event_name": "PostToolUse", "tool_name": "Read"},
        harness="grok",
        event_name="PostToolUse",
        reason_code="native_post_tool_unavailable",
        reason="native unavailable",
    )
    assert grok_post == {}
    withheld = availability_harness_response(
        {"hook_event_name": "PostToolUse", "tool_name": "Read"},
        harness="cursor",
        event_name="PostToolUse",
        reason_code="native_post_tool_unavailable",
        reason="native unavailable",
    )
    assert withheld["continue"] is True
    assert withheld["policy_action"] == "allow"
    assert withheld["reason_code"] == "native_post_tool_unavailable"
    curl = availability_harness_response(
        {"hook_event_name": "PreToolUse", "tool_input": {"command": "curl https://example.test"}},
        harness="grok",
        event_name="PreToolUse",
        reason_code="native_pre_tool_unavailable",
        reason="native unavailable",
        workspace=tmp_path,
        home_dir=tmp_path / "home",
    )
    assert curl["decision"] == "deny"
    permission = availability_harness_response(
        {"hook_event_name": "PermissionRequest", "tool_input": {"command": "pwd"}},
        harness="claude-code",
        event_name="PermissionRequest",
        reason_code="native_hook_event_unavailable",
        reason="native unavailable",
    )
    assert permission["hookSpecificOutput"]["decision"]["behavior"] == "deny"
    permission_v2 = availability_harness_response(
        {"hook_event_name": "PermissionRequestV2", "tool_input": {"command": "pwd"}},
        harness="claude-code",
        event_name="PermissionRequestV2",
        reason_code="native_hook_event_unavailable",
        reason="native unavailable",
    )
    assert permission_v2["hookSpecificOutput"]["decision"]["behavior"] == "deny"
    alias = availability_harness_response(
        {"hook_event_name": "beforeShellExecution", "command": "curl https://example.test"},
        harness="cursor",
        event_name="beforeShellExecution",
        reason_code="native_pre_tool_unavailable",
        reason="native unavailable",
        workspace=tmp_path,
        home_dir=tmp_path / "home",
    )
    assert alias["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_cursor_unparseable_input_denies_actions_and_preserves_known_observation() -> None:
    allow, allow_code = cursor_unparseable_input_permission("beforeReadFile")
    assert allow_code == 2
    assert allow["permission"] == "deny"
    deny, deny_code = cursor_unparseable_input_permission("beforeShellExecution")
    assert deny_code == 2
    assert deny["permission"] == "deny"
    after, after_code = cursor_unparseable_input_permission("afterShellExecution")
    assert after_code == 0
    assert after == {}
    watch, watch_code = cursor_unparseable_input_permission(
        "beforeShellExecution",
        recording_only=True,
    )
    assert watch_code == 0
    assert watch == {"permission": "allow"}
    empty, empty_code = cursor_unparseable_input_permission("")
    assert empty_code == 2
    assert empty["permission"] == "deny"


def test_only_events_that_can_still_protect_pause_the_turn() -> None:
    # The prompt and anything that gates a tool call pause: Guard can still
    # keep the action from happening.
    for event in ("UserPromptSubmit", "user_prompt_submitted", "PreToolUse", "beforeShellExecution"):
        assert hook_event_pauses_when_unavailable(event) is True
    # The tool already ran, and lifecycle events never gated one.
    for event in ("PostToolUse", "post_tool", "afterShellExecution", "SessionStart", "Stop"):
        assert hook_event_pauses_when_unavailable(event) is False
