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
# boundary. When native review cannot complete, PreToolUse and PostToolUse continue
# so the session stays moving. Completed policy and secret blocks still protect.
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


def _compact_hook_event_name(event_name: str) -> str:
    return event_name.strip().lower().replace("_", "").replace("-", "")


_LIFECYCLE_CANONICAL_BY_COMPACT = {
    **{_compact_hook_event_name(name): name for name in LIFECYCLE_OBSERVE_EVENTS},
    "userpromptsubmitted": "UserPromptSubmit",
    "subagentend": "SubagentStop",
}


def lifecycle_event_is_observe_only(event_name: str) -> bool:
    return _compact_hook_event_name(event_name) in _LIFECYCLE_CANONICAL_BY_COMPACT


def hook_event_pauses_when_unavailable(event_name: str) -> bool:
    """True when native miss must pause the harness instead of continuing the turn."""

    compact = _compact_hook_event_name(event_name)
    if compact in _LIFECYCLE_CANONICAL_BY_COMPACT:
        return False
    if compact in {"posttooluse", "posttool"} or compact.startswith("after"):
        return False
    return compact not in {"posttooluse", "posttool"} and not compact.startswith("after")


def hook_review_is_recording_only(
    *,
    guard_home: Path | None = None,
    workspace: Path | None = None,
    recording_only: bool = False,
) -> bool:
    """True when Watch/observe must record without stopping the harness."""

    if recording_only:
        return True
    if guard_home is None:
        return False
    try:
        from ..config import load_guard_config
        from ..protection_posture import protection_is_off

        config = load_guard_config(guard_home, workspace=workspace)
    except (OSError, RuntimeError, TypeError, ValueError):
        return False
    return protection_is_off(posture=config.protection_posture, mode=config.mode)


_DECISION_HOOK_HARNESSES = frozenset({"grok", "hermes", "openclaw", "pi", "omp"})
_PERMISSION_REQUEST_EVENTS = frozenset({"permissionrequest", "permissionrequestv2", "copilotpermissionrequest"})
_REVIEW_CANNOT_FINISH_REASON_CODES = frozenset(
    {
        "native_hook_disabled",
        "native_shadow_diagnostic_disabled",
        "native_policy_not_ready",
        "native_hook_event_unavailable",
        "native_pre_tool_unavailable",
        "native_post_tool_unavailable",
        "native_overloaded",
        "daemon_hook_queue_capacity",
        "daemon_hook_deadline_exhausted",
        "daemon_hook_process_deadline_exhausted",
        "daemon_worker_exception",
    }
)


def hook_event_is_permission_request(event_name: str) -> bool:
    return _compact_hook_event_name(event_name) in _PERMISSION_REQUEST_EVENTS


def recording_only_pre_tool_response(
    harness: str,
    *,
    reason_code: str,
    reason: str,
) -> dict[str, object]:
    """Continue a PreToolUse hook in Watch without changing Protected fail-closed JSON."""

    from .hook_worker_responses import harness_json_from_native_pre_tool

    if harness.strip().lower().replace("_", "-") in _DECISION_HOOK_HARNESSES:
        return {
            "decision": "allow",
            "policy_action": "warn",
            "reason_code": reason_code,
            "reason": reason,
        }
    return harness_json_from_native_pre_tool(
        harness,
        {
            "decision": "allow",
            "minimum_action": "warn",
            "policy_action": "warn",
            "reason_code": reason_code,
            "reason": reason,
        },
    )


def availability_harness_response(
    payload: Mapping[str, object],
    *,
    harness: str,
    event_name: str,
    reason_code: str,
    reason: str,
    workspace: Path | None = None,
    home_dir: Path | None = None,
    guard_home: Path | None = None,
    recording_only: bool = False,
) -> dict[str, object]:
    """Render a schema-valid harness result when native review is unavailable."""

    from .hook_worker_responses import (
        harness_json_from_native_pre_tool,
        observe_lifecycle_fail_safe_response,
    )

    canonical_lifecycle = _LIFECYCLE_CANONICAL_BY_COMPACT.get(_compact_hook_event_name(event_name))
    if canonical_lifecycle is not None:
        return observe_lifecycle_fail_safe_response(
            harness,
            event_name=canonical_lifecycle,
            reason_code=reason_code,
        )
    watch_only = hook_review_is_recording_only(
        guard_home=guard_home,
        workspace=workspace,
        recording_only=recording_only,
    )
    compact = _compact_hook_event_name(event_name)
    pre_tool_event = compact in {"pretooluse", "pretool"} or compact.startswith("before")
    if watch_only:
        if not pre_tool_event:
            return observe_lifecycle_fail_safe_response(
                harness,
                event_name=event_name,
                reason_code=reason_code,
            )
        return recording_only_pre_tool_response(
            harness,
            reason_code=reason_code,
            reason=reason,
        )
    if reason_code in _REVIEW_CANNOT_FINISH_REASON_CODES and pre_tool_event:
        return recording_only_pre_tool_response(
            harness,
            reason_code=reason_code,
            reason=reason,
        )
    if hook_event_is_permission_request(event_name):
        from .hook_worker_responses import permission_unavailable_response

        return permission_unavailable_response(
            harness,
            event_name=event_name,
            reason=reason,
            reason_code=reason_code,
        )
    if not hook_event_pauses_when_unavailable(event_name):
        return observe_lifecycle_fail_safe_response(
            harness,
            event_name=event_name,
            reason_code=reason_code,
        )
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
    guard_home: Path | None = None,
    recording_only: bool = False,
) -> tuple[dict[str, object], int]:
    """Return Cursor hook stdout when daemon or native review cannot complete."""

    del payload, workspace, home_dir, guard_home, recording_only
    compact = hook_event_name.strip().lower().replace("_", "").replace("-", "")
    if compact in {"aftershellexecution", "aftermcpexecution"}:
        return {}, 0
    return {"permission": "allow"}, 0


def cursor_unparseable_input_permission(
    hook_event_name: str,
    *,
    recording_only: bool = False,
) -> tuple[dict[str, object], int]:
    """Keep Cursor moving when stdin is empty or invalid but the event is known."""

    compact = hook_event_name.strip().lower().replace("_", "").replace("-", "")
    if compact in {"aftershellexecution", "aftermcpexecution"}:
        return {}, 0
    if recording_only or compact in {"", "beforereadfile"}:
        return {"permission": "allow"}, 0
    return dict(_CURSOR_UNAVAILABLE_DENY), 2


__all__ = [
    "EMERGENCY_SAFE_REASON",
    "EMERGENCY_SAFE_REASON_CODE",
    "LIFECYCLE_OBSERVE_EVENTS",
    "availability_harness_response",
    "cursor_fallback_permission",
    "cursor_unparseable_input_permission",
    "hook_action_is_emergency_safe",
    "hook_event_is_permission_request",
    "hook_event_pauses_when_unavailable",
    "hook_review_is_recording_only",
    "lifecycle_event_is_observe_only",
    "recording_only_pre_tool_response",
]
