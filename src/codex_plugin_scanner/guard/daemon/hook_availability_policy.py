"""Harness responses when native review cannot complete without stopping the session."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

# Native review covers tool events and supported prompt callbacks. Other
# lifecycle events remain inventory-only: failing them closed freezes a turn
# without adding enforcement. Unreviewable prompts pause protected hosts;
# acknowledged Watch and monitor-only prompt callbacks continue without enforcement.
LIFECYCLE_OBSERVE_EVENTS = frozenset(
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
    **{_compact_hook_event_name(name): name for name in LIFECYCLE_OBSERVE_EVENTS},
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
_REVIEW_CANNOT_FINISH_REASON_CODES = frozenset(
    {
        "native_policy_not_ready",
        "native_policy_update_in_progress",
        "native_hook_event_unavailable",
        "native_pre_tool_unavailable",
        "native_post_tool_unavailable",
        "native_overloaded",
        "native_hook_worker_unavailable",
        "native_hook_worker_unavailable_before_compatibility",
        "native_hook_worker_unsupported",
        "native_hook_worker_exception",
        "native_hook_compatibility_disabled",
        "native_hook_edge_invalid_response",
        "native_hook_edge_unavailable",
        "python_hook_oracle_unavailable",
        "python_oracle_exception",
        "watch_recording_only",
        "daemon_hook_queue_capacity",
        "daemon_hook_deadline_exhausted",
        "daemon_hook_process_deadline_exhausted",
        "daemon_hook_process_not_ready",
        "daemon_hook_process_failed",
        "daemon_hook_process_invalid_request",
        "daemon_hook_process_guard_home_mismatch",
        "daemon_worker_exception",
        "harness_not_managed",
    }
)
_INTEGRITY_FAIL_CLOSED_REASON_CODES = frozenset(
    {
        "invalid_hook_payload_reference",
        "daemon_hook_queue_bytes",
    }
)


def hook_event_is_permission_request(event_name: str) -> bool:
    return _compact_hook_event_name(event_name) in _PERMISSION_REQUEST_EVENTS


def hook_reason_continues_session(reason_code: str) -> bool:
    """True when this availability reason must not stop the harness."""

    code = reason_code.strip()
    if code in _INTEGRITY_FAIL_CLOSED_REASON_CODES:
        return False
    return code in _REVIEW_CANNOT_FINISH_REASON_CODES


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
    prompt_reason: str | None = None,
) -> dict[str, object]:
    """Fixed harness result when native review is unavailable.

    A missing resident never authorizes the tool. Watch recording continues
    only through the resident renderer, which the caller applies after this
    deny. Integrity failures stay denied as well.
    """

    del payload, workspace, home_dir, guard_home, recording_only
    from .hook_fail_closed import fail_closed_response

    return fail_closed_response(
        harness, event_name, reason=reason, reason_code=reason_code, prompt_reason=prompt_reason
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
    """Deny protected Cursor actions when no evaluator supplies a decision.

    Retain legacy keyword arguments without accepting them as mode authority.
    """

    del payload, workspace, home_dir, guard_home, recording_only
    compact = hook_event_name.strip().lower().replace("_", "").replace("-", "")
    if compact in {"aftershellexecution", "aftermcpexecution"}:
        return {}, 0
    reason = "Guard could not complete a trusted hook decision. Retry or repair Guard from a terminal."
    return {
        "permission": "deny",
        "user_message": reason,
        "agent_message": reason,
    }, 2


def cursor_unparseable_input_permission(
    hook_event_name: str,
    *,
    recording_only: bool = False,
) -> tuple[dict[str, object], int]:
    """Deny unparsed actions unless the caller supplies acknowledged mode authority.

    Set recording_only only after independently verifying acknowledged mode
    authority. A local configuration flag alone cannot establish it. Generated
    hooks with unparsed input cannot establish it and use the protected default.
    """

    compact = hook_event_name.strip().lower().replace("_", "").replace("-", "")
    if compact in {"aftershellexecution", "aftermcpexecution"}:
        return {}, 0
    if recording_only:
        return {"permission": "allow"}, 0
    return {
        "permission": "deny",
        "user_message": "Guard could not process this hook request safely. Retry or repair Guard from a terminal.",
    }, 2


__all__ = [
    "LIFECYCLE_OBSERVE_EVENTS",
    "availability_harness_response",
    "cursor_fallback_permission",
    "cursor_unparseable_input_permission",
    "hook_event_is_permission_request",
    "hook_event_pauses_when_unavailable",
    "hook_reason_continues_session",
]
