"""Harness responses when native review cannot complete without stopping the session."""

from __future__ import annotations

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


def hook_event_pauses_when_unavailable(event_name: str) -> bool:
    """True when native miss must pause the harness instead of continuing the turn.

    This answer cannot come from the resident: it is the policy for the turns
    where the resident is the thing that could not be reached.
    """

    compact = _compact_hook_event_name(event_name)
    if compact in {"userpromptsubmit", "userpromptsubmitted"}:
        return True
    if compact in _LIFECYCLE_CANONICAL_BY_COMPACT:
        return False
    # The tool already ran, so pausing the turn protects nothing.
    return compact not in {"posttooluse", "posttool"} and not compact.startswith("after")


_PERMISSION_REQUEST_EVENTS = frozenset({"permissionrequest", "permissionrequestv2", "copilotpermissionrequest"})


def hook_event_is_permission_request(event_name: str) -> bool:
    return _compact_hook_event_name(event_name) in _PERMISSION_REQUEST_EVENTS


def availability_harness_response(
    *,
    harness: str,
    event_name: str,
    reason_code: str,
    reason: str,
    prompt_reason: str | None = None,
) -> dict[str, object]:
    """Fixed harness result when native review is unavailable.

    A missing resident never authorizes the tool. Watch recording continues
    only through the resident renderer, which the caller applies after this
    deny. Integrity failures stay denied as well.
    """

    from .hook_fail_closed import fail_closed_response

    return fail_closed_response(
        harness, event_name, reason=reason, reason_code=reason_code, prompt_reason=prompt_reason
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
