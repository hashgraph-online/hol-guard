from __future__ import annotations

import copy
import json

import pytest

from codex_plugin_scanner.guard.adapters.bounded_cli_hook_daemon import _daemon_response_to_native


def _translate(payload: dict[str, object], *, harness: str = "grok", event: str = "PreToolUse"):
    stdout, stderr, code = _daemon_response_to_native(payload, harness=harness, event_name=event)
    return json.loads(stdout), stderr, code


@pytest.mark.parametrize(
    ("harness", "expected_code"),
    [("grok", 2), ("openclaw", 0), ("kimi", 2), ("pi", 2), ("zcode", 2)],
)
def test_policy_block_cannot_be_weakened_by_native_allow(harness: str, expected_code: int) -> None:
    payload, _stderr, code = _translate(
        {
            "decision": "allow",
            "policy_action": "block",
            "reason": "Blocked by policy.",
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "ask",
                "additionalContext": "retain context",
            },
        },
        harness=harness,
    )

    assert code == expected_code
    assert payload["decision"] == "deny"
    assert payload["policy_action"] == "block"
    assert payload["reason"] == "Blocked by policy."
    assert payload["hookSpecificOutput"] == {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "additionalContext": "retain context",
    }


def test_native_deny_promotes_allow_policy_to_block() -> None:
    payload, _stderr, code = _translate(
        {
            "decision": "allow",
            "policy_action": "allow",
            "approval_url": "http://127.0.0.1:7777/approval",
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": "Native denial.",
            },
        }
    )

    assert code == 2
    assert payload["decision"] == "deny"
    assert payload["policy_action"] == "block"
    assert payload["approval_url"] == "http://127.0.0.1:7777/approval"
    assert payload["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_review_denial_is_byte_semantically_preserved_and_waitable() -> None:
    original = {
        "decision": "deny",
        "policy_action": "review",
        "reason": "Approval required.",
        "approval_requests": [{"request_id": "req-1"}],
        "primary_approval_url": "http://127.0.0.1:7777/approval/req-1",
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "ask",
            "permissionDecisionReason": "Approval required.",
        },
    }

    payload, _stderr, code = _translate(original)

    assert payload == original
    assert code == 2


def test_review_policy_repairs_native_allow_without_losing_metadata() -> None:
    payload, _stderr, code = _translate(
        {
            "decision": "allow",
            "policy_action": "review",
            "approval_requests": [{"request_id": "req-2"}],
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
                "additionalContext": "retain review context",
            },
        }
    )

    assert code == 2
    assert payload["decision"] == "deny"
    assert payload["policy_action"] == "review"
    assert payload["approval_requests"] == [{"request_id": "req-2"}]
    assert payload["hookSpecificOutput"] == {
        "hookEventName": "PreToolUse",
        "permissionDecision": "ask",
        "additionalContext": "retain review context",
    }


@pytest.mark.parametrize("policy_action", ["allow", "warn"])
def test_watch_and_recording_native_allow_are_preserved(policy_action: str) -> None:
    original = {
        "decision": "allow",
        "policy_action": policy_action,
        "reason_code": "recording_only_pre_tool",
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
        },
    }

    payload, stderr, code = _translate(original)

    assert payload == original
    assert (stderr, code) == ("", 0)


def test_recording_only_allow_without_policy_metadata_is_preserved() -> None:
    payload, stderr, code = _translate({"decision": "allow"})

    assert payload == {"decision": "allow"}
    assert (stderr, code) == ("", 0)


def test_top_level_deny_cannot_be_masked_by_nested_allow() -> None:
    payload, _stderr, code = _translate(
        {
            "decision": "deny",
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "allow",
            },
        }
    )

    assert code == 2
    assert payload["decision"] == "deny"
    assert payload["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_lifecycle_envelope_without_decision_is_unchanged() -> None:
    original = {
        "policy_action": "block",
        "reason": "inventory unavailable",
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": "retain lifecycle context",
        },
    }

    payload, stderr, code = _translate(original, event="SessionStart")

    assert payload == original
    assert (stderr, code) == ("", 0)


@pytest.mark.parametrize(
    "original",
    [
        {"decision": "allow", "policy_action": "invalid"},
        {"decision": "bogus"},
        {"decision": 7},
        {
            "decision": "allow",
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "bogus",
            },
        },
        {
            "decision": "allow",
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": None,
            },
        },
    ],
)
def test_present_invalid_authority_fails_closed_without_mutating_input(original: dict[str, object]) -> None:
    before = copy.deepcopy(original)

    payload, _stderr, code = _translate(original)

    assert code == 2
    assert payload["decision"] == "deny"
    assert original == before
    hook_specific = payload.get("hookSpecificOutput")
    if isinstance(hook_specific, dict):
        assert hook_specific["permissionDecision"] == "deny"


def test_lifecycle_present_invalid_authority_is_not_promoted_to_a_gate() -> None:
    original = {
        "policy_action": "inventory-unavailable",
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": "retain lifecycle context",
        },
    }

    payload, stderr, code = _translate(original, event="SessionStart")

    assert payload == original
    assert (stderr, code) == ("", 0)


@pytest.mark.parametrize(
    ("harness", "policy_action", "expected_permission", "expected_top"),
    [
        ("grok", "block", "deny", "deny"),
        ("openclaw", "review", "ask", "deny"),
        ("codex", "block", "deny", None),
        ("claude-code", "review", "ask", None),
    ],
)
def test_restrictive_tool_policy_materializes_missing_native_authority(
    harness: str,
    policy_action: str,
    expected_permission: str,
    expected_top: str | None,
) -> None:
    original = {
        "policy_action": policy_action,
        "reason": "Retain policy reason.",
        "approval_requests": [{"request_id": "req-missing"}],
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "additionalContext": "retain envelope context",
        },
    }
    before = copy.deepcopy(original)

    payload, _stderr, code = _translate(original, harness=harness)

    assert payload["policy_action"] == policy_action
    assert payload["reason"] == "Retain policy reason."
    assert payload["approval_requests"] == [{"request_id": "req-missing"}]
    assert payload["hookSpecificOutput"] == {
        "hookEventName": "PreToolUse",
        "additionalContext": "retain envelope context",
        "permissionDecision": expected_permission,
    }
    assert payload.get("decision") == expected_top
    assert code == (2 if harness == "grok" else 0)
    assert original == before


def test_restrictive_policy_reconstructs_malformed_tool_envelope() -> None:
    original: dict[str, object] = {
        "decision": "allow",
        "policy_action": "block",
        "reason": "Malformed envelope blocked.",
        "hookSpecificOutput": "invalid",
    }
    before = copy.deepcopy(original)

    payload, _stderr, code = _translate(original, harness="openclaw")

    assert payload == {
        "decision": "deny",
        "policy_action": "block",
        "reason": "Malformed envelope blocked.",
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
        },
    }
    assert code == 0
    assert original == before


@pytest.mark.parametrize("harness", ["openclaw", "codex"])
def test_invalid_present_policy_materializes_stdout_denial_for_tool_envelope(harness: str) -> None:
    original = {
        "policy_action": "bogus",
        "reason": "Retain malformed-policy reason.",
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "additionalContext": "retain malformed-policy context",
        },
    }
    before = copy.deepcopy(original)

    payload, _stderr, code = _translate(original, harness=harness)

    assert payload["policy_action"] == "block"
    assert payload["reason"] == "Retain malformed-policy reason."
    assert payload["hookSpecificOutput"] == {
        "hookEventName": "PreToolUse",
        "additionalContext": "retain malformed-policy context",
        "permissionDecision": "deny",
    }
    assert payload.get("decision") == ("deny" if harness == "openclaw" else None)
    assert code == 0
    assert original == before


@pytest.mark.parametrize("policy_action", ["block", "review"])
def test_restrictive_prompt_policy_materializes_top_level_block(policy_action: str) -> None:
    original = {
        "policy_action": policy_action,
        "reason": "Prompt policy reason.",
        "hookSpecificOutput": {"hookEventName": "UserPromptSubmit"},
    }

    payload, _stderr, code = _translate(original, event="UserPromptSubmit")

    assert payload == {
        **original,
        "decision": "block",
    }
    assert code == 2
