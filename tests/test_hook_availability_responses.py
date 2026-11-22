"""Harness responses when trusted native review is unavailable."""

from pathlib import Path

from codex_plugin_scanner.guard.hook_review.hook_availability_policy import (
    availability_harness_response,
    canonical_hook_event_name,
    hook_event_pauses_when_unavailable,
)


def test_recording_only_pre_tool_outage_still_denies() -> None:
    for harness, reason_code in (
        ("codex", "daemon_hook_queue_capacity"),
        ("grok", "native_hook_worker_unavailable"),
    ):
        response = availability_harness_response(
            harness=harness,
            event_name="PreToolUse",
            reason_code=reason_code,
            reason="Native review unavailable.",
        )
        assert response["policy_action"] == "block"
        if harness == "codex":
            assert response["hookSpecificOutput"]["permissionDecision"] == "deny"
        else:
            assert response["decision"] == "deny"


def test_unavailable_native_prompt_does_not_allow_supported_enforcing_hosts() -> None:
    for harness in ("claude-code", "codex"):
        response = availability_harness_response(
            harness=harness,
            event_name="UserPromptSubmit",
            reason_code="native_hook_event_unavailable",
            reason="Native review unavailable.",
        )
        assert response["policy_action"] == "block"
        assert response["decision"] == "block"
        assert response["reason_code"] == "native_prompt_unavailable"
    copilot = availability_harness_response(
        harness="copilot",
        event_name="UserPromptSubmit",
        reason_code="native_hook_event_unavailable",
        reason="Native review unavailable.",
    )
    assert copilot["behavior"] == "deny"
    watch = availability_harness_response(
        harness="claude-code",
        event_name="UserPromptSubmit",
        reason_code="native_hook_event_unavailable",
        reason="Native review unavailable.",
    )
    assert watch["policy_action"] == "block"


def test_availability_blocks_grok_prompt_and_tools_but_continues_passive_lifecycle(tmp_path: Path) -> None:
    prompt = availability_harness_response(
        harness="grok",
        event_name="UserPromptSubmit",
        reason_code="native_hook_event_unavailable",
        reason="native unavailable",
    )
    assert prompt["decision"] == "block"
    session = availability_harness_response(
        harness="grok",
        event_name="SessionStart",
        reason_code="native_hook_event_unavailable",
        reason="native unavailable",
    )
    assert session == {}
    aliased = availability_harness_response(
        harness="grok",
        event_name="session_start",
        reason_code="native_hook_event_unavailable",
        reason="native unavailable",
    )
    assert aliased == {}
    subagent = availability_harness_response(
        harness="grok",
        event_name="subagent_start",
        reason_code="native_hook_event_unavailable",
        reason="native unavailable",
    )
    assert subagent == {}
    submitted = availability_harness_response(
        harness="grok",
        event_name="UserPromptSubmitted",
        reason_code="native_hook_event_unavailable",
        reason="native unavailable",
    )
    assert submitted["decision"] == "block"
    compact = availability_harness_response(
        harness="grok",
        event_name=" userpromptsubmit ",
        reason_code="native_hook_event_unavailable",
        reason="native unavailable",
    )
    assert compact["decision"] == "block"
    grok_post = availability_harness_response(
        harness="grok",
        event_name="PostToolUse",
        reason_code="native_post_tool_unavailable",
        reason="native unavailable",
    )
    assert grok_post == {}
    withheld = availability_harness_response(
        harness="cursor",
        event_name="PostToolUse",
        reason_code="native_post_tool_unavailable",
        reason="native unavailable",
    )
    assert withheld["continue"] is True
    assert withheld["policy_action"] == "allow"
    assert withheld["reason_code"] == "native_post_tool_unavailable"
    curl = availability_harness_response(
        harness="grok",
        event_name="PreToolUse",
        reason_code="native_pre_tool_unavailable",
        reason="native unavailable",
    )
    assert curl["decision"] == "deny"
    permission = availability_harness_response(
        harness="claude-code",
        event_name="PermissionRequest",
        reason_code="native_hook_event_unavailable",
        reason="native unavailable",
    )
    assert permission["hookSpecificOutput"]["decision"]["behavior"] == "deny"
    permission_v2 = availability_harness_response(
        harness="claude-code",
        event_name="PermissionRequestV2",
        reason_code="native_hook_event_unavailable",
        reason="native unavailable",
    )
    assert permission_v2["hookSpecificOutput"]["decision"]["behavior"] == "deny"
    alias = availability_harness_response(
        harness="cursor",
        event_name="beforeShellExecution",
        reason_code="native_pre_tool_unavailable",
        reason="native unavailable",
    )
    assert alias["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_availability_wrapper_uses_the_native_posture(monkeypatch) -> None:
    from codex_plugin_scanner.guard.hook_review import hook_availability_policy as policy

    monkeypatch.setattr(
        policy,
        "_runtime_availability",
        lambda _payload, **_kwargs: {"pauses": False},
    )
    assert hook_event_pauses_when_unavailable("PreToolUse") is False


def test_complete_native_outage_preserves_wire_event_and_safe_fallback(monkeypatch) -> None:
    from codex_plugin_scanner.guard.hook_review import hook_availability_policy as policy

    monkeypatch.setattr(policy, "_runtime_availability", lambda *_args, **_kwargs: None)
    assert canonical_hook_event_name({"hook_event_name": "PostToolUse"}) == "PostToolUse"
    assert hook_event_pauses_when_unavailable("PostToolUse") is False
    assert hook_event_pauses_when_unavailable("Stop") is False
    assert hook_event_pauses_when_unavailable("PreToolUse") is True
    assert canonical_hook_event_name({"hook_event_name": "post_toolcall"}) == "PostToolUse"
