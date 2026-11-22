"""Harness responses when native review cannot complete without stopping the session."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

# Native review covers tool events and supported prompt callbacks. Other
# lifecycle events remain inventory-only: failing them closed freezes a turn
# without adding enforcement. Unreviewable prompts pause protected hosts;
# acknowledged Watch and monitor-only prompt callbacks continue without enforcement.
_LIFECYCLE_OBSERVE_EVENTS = frozenset(
    {
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
    **{_compact_hook_event_name(name): name for name in _LIFECYCLE_OBSERVE_EVENTS},
    "userpromptsubmit": "UserPromptSubmit",
    "userpromptsubmitted": "UserPromptSubmit",
    "subagentend": "SubagentStop",
}


def canonical_hook_event_name(
    payload: Mapping[str, object], *, guard_home: Path | None = None, deadline: float | None = None
) -> str:
    """Recover only the wire event label for an outage response.

    Normal hook semantics use the resident's normalized event fact. This
    bounded alias lookup exists solely to preserve the harness response shape
    when the resident cannot be reached.
    """

    if guard_home is not None:
        from ..native_hook_render import native_hook_availability

        native = native_hook_availability(payload, guard_home=guard_home, deadline=deadline)
        event = native.get("event_name") if isinstance(native, dict) else None
        if isinstance(event, str) and event:
            return event
    for key in ("event", "eventName", "hook_event_name", "hookEventName", "hook_name", "hookName"):
        value = payload.get(key)
        if not isinstance(value, str) or not value.strip():
            continue
        compact = _compact_hook_event_name(value)
        if compact in {
            "pretool",
            "pretooluse",
            "pretoolcall",
            "beforeshellexecution",
            "beforereadfile",
            "beforewritefile",
            "beforemcpexecution",
        }:
            return "PreToolUse"
        if compact in {
            "posttool",
            "posttooluse",
            "posttoolcall",
            "aftershellexecution",
            "afterreadfile",
            "afterwritefile",
            "aftermcpexecution",
        }:
            return "PostToolUse"
        if compact in {"permissionrequest", "permissionrequestv2", "copilotpermissionrequest"}:
            return "PermissionRequest"
        if compact in {"prompt", "userpromptsubmit", "userpromptsubmitted"}:
            return "UserPromptSubmit"
        return value.strip()
    return "PreToolUse"


def hook_event_pauses_when_unavailable(
    event_name: str, *, guard_home: Path | None = None, deadline: float | None = None
) -> bool:
    """True when native miss must pause the harness instead of continuing the turn.

    This answer cannot come from the resident: it is the policy for the turns
    where the resident is the thing that could not be reached.
    """

    if guard_home is not None:
        from ..native_hook_render import native_hook_availability

        native = native_hook_availability({"event": event_name}, guard_home=guard_home, deadline=deadline)
        pauses = native.get("pauses") if isinstance(native, dict) else None
        if isinstance(pauses, bool):
            return pauses
    compact = _compact_hook_event_name(event_name)
    if compact in {"userpromptsubmit", "userpromptsubmitted"}:
        return True
    if compact in _LIFECYCLE_CANONICAL_BY_COMPACT:
        return False
    # The tool already ran, so pausing the turn protects nothing.
    return compact not in {"posttooluse", "posttool"} and not compact.startswith("after")


_PERMISSION_REQUEST_EVENTS = frozenset({"permissionrequest", "permissionrequestv2", "copilotpermissionrequest"})


def hook_event_is_permission_request(
    event_name: str, *, guard_home: Path | None = None, deadline: float | None = None
) -> bool:
    if guard_home is not None:
        from ..native_hook_render import native_hook_availability

        native = native_hook_availability({"event": event_name}, guard_home=guard_home, deadline=deadline)
        permission_request = native.get("permission_request") if isinstance(native, dict) else None
        if isinstance(permission_request, bool):
            return permission_request
    return _compact_hook_event_name(event_name) in _PERMISSION_REQUEST_EVENTS


def availability_harness_response(
    *,
    harness: str,
    event_name: str,
    reason_code: str,
    reason: str,
    prompt_reason: str | None = None,
    guard_home: Path | None = None,
) -> dict[str, object]:
    """Fixed harness result when native review is unavailable.

    A missing resident never authorizes the tool. Watch recording continues
    only through the resident renderer, which the caller applies after this
    deny. Integrity failures stay denied as well.
    """

    from .hook_fail_closed import fail_closed_response

    return fail_closed_response(
        harness,
        event_name,
        reason=reason,
        reason_code=reason_code,
        prompt_reason=prompt_reason,
        guard_home=guard_home,
    )


def cursor_fallback_permission(*, hook_event_name: str) -> tuple[dict[str, object], int]:
    """Deny protected Cursor actions when no evaluator supplies a decision.

    A hook script written by an older release still passes the payload and
    mode keywords; the call fails, and that script denies with the same reply.
    """

    compact = hook_event_name.strip().lower().replace("_", "").replace("-", "")
    if compact in {"aftershellexecution", "aftermcpexecution"}:
        return {}, 0
    reason = "Guard could not complete a trusted hook decision. Retry or repair Guard from a terminal."
    return {
        "permission": "deny",
        "user_message": reason,
        "agent_message": reason,
    }, 2


def cursor_unparseable_input_permission(hook_event_name: str) -> tuple[dict[str, object], int]:
    """Deny unparsed actions: unparsed input carries no acknowledged mode authority."""

    compact = hook_event_name.strip().lower().replace("_", "").replace("-", "")
    if compact in {"aftershellexecution", "aftermcpexecution"}:
        return {}, 0
    return {
        "permission": "deny",
        "user_message": "Guard could not process this hook request safely. Retry or repair Guard from a terminal.",
    }, 2


__all__ = [
    "availability_harness_response",
    "cursor_fallback_permission",
    "cursor_unparseable_input_permission",
    "hook_event_is_permission_request",
    "hook_event_pauses_when_unavailable",
]
