"""Fail-safe payloads for bounded CLI harness hooks when review cannot finish."""

from __future__ import annotations

from ..daemon.hook_availability_policy import (
    EMERGENCY_SAFE_REASON,
    hook_action_is_emergency_safe,
    hook_event_pauses_when_unavailable,
)

_DECISION_HOOK_HARNESSES = frozenset({"grok", "hermes", "openclaw"})


def _is_permission_event(event_name: str) -> bool:
    compact = event_name.strip().lower().replace("_", "").replace("-", "")
    return compact in {"permissionrequest", "permissionrequestv2", "copilotpermissionrequest"}


def watch_continue_payload(harness: str, event_name: str) -> dict[str, object]:
    if harness == "copilot":
        return {"permissionDecision": "allow"}
    if harness in _DECISION_HOOK_HARNESSES:
        return {"decision": "allow"}
    return {
        "hookSpecificOutput": {
            "hookEventName": event_name,
            "permissionDecision": "allow",
        }
    }


def _emergency_safe_payload(harness: str, event_name: str) -> dict[str, object]:
    if harness == "copilot":
        return {
            "permissionDecision": "allow",
            "permissionDecisionReason": EMERGENCY_SAFE_REASON,
        }
    if harness in _DECISION_HOOK_HARNESSES:
        return {"decision": "allow", "reason": EMERGENCY_SAFE_REASON}
    return {
        "hookSpecificOutput": {
            "hookEventName": event_name,
            "permissionDecision": "allow",
            "permissionDecisionReason": EMERGENCY_SAFE_REASON,
        }
    }


def _observe_payload(harness: str, event_name: str, reason: str) -> dict[str, object]:
    if harness == "copilot":
        return {"permissionDecision": "allow"}
    if harness in _DECISION_HOOK_HARNESSES:
        return {"decision": "allow", "reason": reason}
    return {
        "continue": True,
        "systemMessage": reason,
        "hookSpecificOutput": {"hookEventName": event_name},
    }


def _pause_payload(harness: str, event_name: str, reason: str) -> tuple[dict[str, object], int]:
    if harness == "copilot":
        if _is_permission_event(event_name):
            return {
                "behavior": "deny",
                "message": reason,
                "interrupt": True,
            }, 0
        return {
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }, 0
    if harness in _DECISION_HOOK_HARNESSES:
        decision = "block" if harness == "hermes" else "deny"
        return {"decision": decision, "reason": reason}, (2 if harness == "hermes" else 0)
    if _is_permission_event(event_name):
        return {
            "continue": False,
            "stopReason": reason,
            "systemMessage": reason,
        }, 0
    return {
        "hookSpecificOutput": {
            "hookEventName": event_name,
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }, 2


def failure_payload(
    *,
    harness: str,
    event_name: str,
    reason: str,
    payload: dict[str, object] | None,
    recording_only: bool,
) -> tuple[dict[str, object], int]:
    if recording_only:
        return watch_continue_payload(harness, event_name), 0
    pauses = hook_event_pauses_when_unavailable(event_name)
    if (
        pauses
        and not _is_permission_event(event_name)
        and isinstance(payload, dict)
        and hook_action_is_emergency_safe(payload)
    ):
        return _emergency_safe_payload(harness, event_name), 0
    if not pauses:
        return _observe_payload(harness, event_name, reason), 0
    return _pause_payload(harness, event_name, reason)
