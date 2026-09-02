"""Harness responses for the emergency-safe floor when native review cannot complete."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from .hook_availability_floor import (
    EMERGENCY_SAFE_REASON,
    EMERGENCY_SAFE_REASON_CODE,
    hook_action_is_emergency_safe,
)

_CURSOR_UNAVAILABLE_MESSAGE = (
    "HOL Guard paused this action because native review was unavailable "
    "and the action is outside the emergency-safe inspection floor."
)
_CURSOR_UNAVAILABLE_DENY: dict[str, object] = {
    "permission": "deny",
    "user_message": _CURSOR_UNAVAILABLE_MESSAGE,
    "agent_message": _CURSOR_UNAVAILABLE_MESSAGE,
}

# Native review covers PreToolUse and PostToolUse. Lifecycle events are inventory
# only: fail-closing them freezes the conversation without adding an enforcement
# boundary. PostToolUse and PermissionRequest stay withheld/paused.
LIFECYCLE_OBSERVE_EVENTS = frozenset(
    {
        "UserPromptSubmit",
        "SessionStart",
        "SessionEnd",
        "SubagentStart",
        "SubagentStop",
        "Stop",
        "Notification",
        "TaskStart",
        "TaskError",
        "SessionShutdown",
        "PermissionDenied",
    }
)


def lifecycle_event_is_observe_only(event_name: str) -> bool:
    return event_name.strip() in LIFECYCLE_OBSERVE_EVENTS


def availability_harness_response(
    payload: Mapping[str, object],
    *,
    harness: str,
    event_name: str,
    reason_code: str,
    reason: str,
    workspace: Path | None = None,
    home_dir: Path | None = None,
) -> dict[str, object]:
    """Render a schema-valid harness result when native review is unavailable."""

    from .hook_worker_responses import (
        harness_json_from_native_pre_tool,
        observe_lifecycle_fail_safe_response,
        post_tool_fail_safe_response,
    )

    if lifecycle_event_is_observe_only(event_name):
        return observe_lifecycle_fail_safe_response(
            harness,
            event_name=event_name,
            reason_code=reason_code,
        )
    if event_name != "PreToolUse":
        return post_tool_fail_safe_response(harness, reason=reason, reason_code=reason_code)
    if not hook_action_is_emergency_safe(
        payload,
        workspace=workspace,
        home_dir=home_dir,
    ):
        return harness_json_from_native_pre_tool(
            harness,
            {
                "decision": "deny",
                "minimum_action": "block",
                "policy_action": "block",
                "reason_code": reason_code,
                "reason": reason,
            },
        )
    return harness_json_from_native_pre_tool(
        harness,
        {
            "decision": "allow",
            "minimum_action": "warn",
            "policy_action": "warn",
            "reason_code": EMERGENCY_SAFE_REASON_CODE,
            "reason": EMERGENCY_SAFE_REASON,
        },
    )


def cursor_fallback_permission(
    payload: Mapping[str, object],
    *,
    hook_event_name: str,
    workspace: Path | None = None,
    home_dir: Path | None = None,
) -> tuple[dict[str, object], int]:
    """Return Cursor hook stdout when daemon or native review cannot complete."""

    compact = hook_event_name.strip().lower().replace("_", "").replace("-", "")
    if compact in {"aftershellexecution", "aftermcpexecution"}:
        return {}, 0
    if compact in {"beforewritefile", "beforemcpexecution"}:
        return dict(_CURSOR_UNAVAILABLE_DENY), 2
    if hook_action_is_emergency_safe(payload, workspace=workspace, home_dir=home_dir):
        return {"permission": "allow"}, 0
    response: dict[str, object] = {
        "permission": "deny",
        "user_message": _CURSOR_UNAVAILABLE_MESSAGE,
    }
    if compact != "beforereadfile":
        response["agent_message"] = _CURSOR_UNAVAILABLE_MESSAGE
    return response, 2


__all__ = [
    "EMERGENCY_SAFE_REASON",
    "EMERGENCY_SAFE_REASON_CODE",
    "LIFECYCLE_OBSERVE_EVENTS",
    "availability_harness_response",
    "cursor_fallback_permission",
    "hook_action_is_emergency_safe",
    "lifecycle_event_is_observe_only",
]
