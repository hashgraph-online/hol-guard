"""Fail-safe payloads for bounded CLI harness hooks when review cannot finish."""

from __future__ import annotations

from ..daemon.hook_availability_policy import (
    hook_event_is_permission_request,
    hook_event_pauses_when_unavailable,
)

_DECISION_HOOK_HARNESSES = frozenset({"grok", "hermes", "openclaw"})


def grok_observe_event(harness: str, event_name: str) -> bool:
    compact = event_name.strip().lower().replace("_", "").replace("-", "")
    return harness == "grok" and compact in {
        "sessionstart",
        "sessionend",
        "subagentstart",
        "subagentstop",
        "posttooluse",
        "permissiondenied",
    }


def _is_permission_event(event_name: str) -> bool:
    return hook_event_is_permission_request(event_name)


def _is_prompt_event(event_name: str) -> bool:
    return event_name.strip().lower().replace("_", "").replace("-", "") in {
        "userpromptsubmit",
        "userpromptsubmitted",
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
    if _is_prompt_event(event_name):
        from ..daemon.hook_fail_closed import fail_closed_response

        return fail_closed_response(harness, event_name), 0
    if harness == "copilot":
        if _is_permission_event(event_name):
            return {
                "behavior": "deny",
                "message": reason,
                "interrupt": False,
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
    recording_only: bool,
    payload: dict[str, object] | None = None,
    continue_session: bool = False,
) -> tuple[dict[str, object], int]:
    """Fixed fail-closed payload per harness when review cannot finish.

    recording_only and continue_session are accepted for caller compatibility
    and ignored: request shape never turns an outage into an allow.
    """
    del recording_only, continue_session, payload
    if grok_observe_event(harness, event_name):
        return {}, 0
    pauses = hook_event_pauses_when_unavailable(event_name)
    if not pauses:
        # Observations continue processing completed activity without authorizing a tool action.
        return _observe_payload(harness, event_name, reason), 0
    # A failed review cannot authorize a protected action. Keep the legacy
    # keyword for callers, but continuation applies only to observer/watch
    # events handled above, never to this protected-event branch.
    return _pause_payload(harness, event_name, reason)
