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
