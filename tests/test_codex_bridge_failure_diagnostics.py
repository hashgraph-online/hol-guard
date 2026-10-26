"""A hook the bridge cannot route to a runtime fails closed on every blocking event."""

from __future__ import annotations

from codex_plugin_scanner.guard.adapters import codex_daemon_hook_bridge as bridge


def test_unavailable_prompt_warns_but_all_actions_require_review() -> None:
    assert bridge._fail_closed("UserPromptSubmit", "review failed") == {
        "continue": True,
        "systemMessage": "review failed",
    }
    assert bridge._fail_closed("PreToolUse", "review failed") == {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": "review failed",
        },
    }
