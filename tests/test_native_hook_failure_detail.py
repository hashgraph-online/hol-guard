"""Native proof failures report a category without leaking response content."""

from ci.native_runtime.installed_hook_client import hook_failure_detail


def test_failure_detail_includes_bounded_native_reason():
    detail = hook_failure_detail(
        "claude-code",
        "PreToolUse",
        {
            "reason_code": "native_hook_worker_unavailable",
            "hookSpecificOutput": {"permissionDecision": "deny"},
        },
    )
    assert detail["reason_code"] == "native_hook_worker_unavailable"
    assert detail["permission_decision"] == "deny"


def test_failure_detail_rejects_untrusted_text_and_structured_decisions():
    detail = hook_failure_detail(
        "claude-code",
        "PreToolUse",
        {
            "reason_code": "unsafe response text\nprivate payload",
            "decision": {"behavior": "deny", "message": "private payload"},
            "hookSpecificOutput": {"permissionDecision": "private payload"},
        },
    )
    assert detail["reason_code"] is None
    assert detail["decision"] is None
    assert detail["permission_decision"] is None
    assert "private payload" not in str(detail)


def test_outage_refuses_every_deciding_event_spelling():
    """A hook outage cannot answer, so no deciding spelling may exit silently."""

    from codex_plugin_scanner.guard.hook_failure_bridge import RUNTIME_MISSING, outage_stderr_failure

    for event in (
        "PreToolUse",
        "PreToolCall",
        "pre_tool",
        "BeforeToolUse",
        "PermissionRequest",
        "PermissionRequestV2",
        "copilot-permission-request",
        "user_prompt-submit",
        "UserPromptSubmitted",
    ):
        assert outage_stderr_failure(event) == ("", RUNTIME_MISSING, 2), event
    for event in ("PostToolUse", "SessionStart", "Stop", "SubagentStop"):
        assert outage_stderr_failure(event) == ("", "", 0), event
    # The runtime trims the event name before classifying it, so a padded
    # spelling has to be refused here too rather than exiting silently.
    for event in (" PreToolUse", "PreToolUse\n", "\tPermissionRequest "):
        assert outage_stderr_failure(event) == ("", RUNTIME_MISSING, 2), event


def test_outage_table_matches_the_fail_closed_envelope_contract():
    """The outage table is the contract's deciding events, not a shorter list."""

    import json

    from codex_plugin_scanner.guard.hook_failure_bridge import (
        _DECIDING_EVENT_PREFIXES,
        _DECIDING_EVENTS,
    )
    from codex_plugin_scanner.guard.hook_review.hook_fail_closed import ENVELOPES_CONTRACT_PATH

    contract = json.loads(ENVELOPES_CONTRACT_PATH.read_text(encoding="utf-8"))
    deciding = {"pre_tool", "permission", "prompt"}
    assert _DECIDING_EVENTS == {
        event for event, kind in contract["events"].items() if kind in deciding
    }
    assert set(_DECIDING_EVENT_PREFIXES) == {
        prefix for prefix, kind in contract["event_prefixes"].items() if kind in deciding
    }
