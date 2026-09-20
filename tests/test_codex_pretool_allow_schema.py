from __future__ import annotations

from codex_plugin_scanner.guard.adapters import codex_daemon_hook_bridge as bridge


def test_codex_pre_tool_response_omits_unsupported_allow() -> None:
    allowed = bridge._codex_hook_response(
        {
            "continue": True,
            "policy_action": "allow",
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
                "permissionDecisionReason": "HOL Guard allowed this action",
            },
        },
        event_name="PreToolUse",
    )
    denied = bridge._codex_hook_response(
        {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": "blocked",
            }
        },
        event_name="PreToolUse",
    )

    assert allowed == {"continue": True, "hookSpecificOutput": {"hookEventName": "PreToolUse"}}
    assert denied == {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": "blocked",
        }
    }


def test_codex_pre_tool_warn_preserves_reason_as_system_message() -> None:
    warned = bridge._codex_hook_response(
        {
            "continue": True,
            "policy_action": "warn",
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
                "permissionDecisionReason": "Proceed, but this pattern is risky.",
            },
        },
        event_name="PreToolUse",
    )

    assert warned == {
        "continue": True,
        "systemMessage": "Proceed, but this pattern is risky.",
        "hookSpecificOutput": {"hookEventName": "PreToolUse"},
    }
    assert "permissionDecision" not in warned["hookSpecificOutput"]


def test_codex_pre_tool_response_drops_invalid_permission_fields() -> None:
    payload = bridge._codex_hook_response(
        {
            "hookSpecificOutput": {
                "hookEventName": "SessionStart",
                "permissionDecision": "block",
                "permissionDecisionReason": 12,
            }
        },
        event_name="PreToolUse",
    )

    assert payload == {"hookSpecificOutput": {"hookEventName": "PreToolUse"}}
