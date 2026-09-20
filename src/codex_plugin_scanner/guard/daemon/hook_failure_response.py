"""Mechanical hook failure rendering with current authority admission fencing."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ..config import load_guard_config
from ..protection_posture import protection_is_off
from .hook_policy_authority import policy_authority_required
from .hook_worker_responses import integrity_fail_closed_pre_tool_response


def runtime_hook_failure_response(
    handler: Any,
    payload: Mapping[str, object],
    params: Mapping[str, list[str]],
    *,
    default_harness: str,
    reason: str,
    reason_code: str,
    native_authoritative: bool = False,
) -> dict[str, object]:
    runtime_harness = handler._optional_string(params.get("runtime-harness", [None])[-1])
    harness = (runtime_harness or default_harness).strip().lower().replace("_", "-")
    event = handler._optional_string(payload.get("hook_event_name", payload.get("event"))) or "PreToolUse"
    daemon_server = getattr(handler, "server", None)
    workspace_path, home_path = handler._validated_fail_safe_hook_paths(params)
    guard_home = None if daemon_server is None else daemon_server.store.guard_home
    publisher = getattr(getattr(daemon_server, "hook_worker", None), "policy_snapshot_publisher", None)
    if event == "PreToolUse" and policy_authority_required(publisher):
        return integrity_fail_closed_pre_tool_response(
            harness,
            reason="HOL Guard could not verify the current policy authority.",
            reason_code="native_scoped_authority_unavailable",
        )
    try:
        loaded = None if guard_home is None else load_guard_config(guard_home, workspace=workspace_path)
        observe_mode = loaded is not None and protection_is_off(posture=loaded.protection_posture, mode=loaded.mode)
    except (OSError, RuntimeError, TypeError, ValueError):
        observe_mode = False
    if observe_mode and not native_authoritative:
        if harness in {"pi", "omp"}:
            return {"decision": "allow", "reason_code": reason_code, "observed_review_failure": True}
        if event == "PermissionRequest":
            return {
                "reason_code": reason_code,
                "hookSpecificOutput": {"hookEventName": event, "decision": {"behavior": "allow"}},
            }
        if event == "PreToolUse":
            return {
                "reason_code": reason_code,
                "hookSpecificOutput": {"hookEventName": event, "permissionDecision": "allow"},
            }
        return {"continue": True, "reason_code": reason_code, "observed_review_failure": True}
    from .hook_availability_policy import availability_harness_response

    payload_dict = dict(payload) if isinstance(payload, Mapping) else {}
    return availability_harness_response(
        payload_dict,
        harness=harness,
        event_name=event,
        reason_code=reason_code,
        reason=reason,
        workspace=workspace_path,
        home_dir=home_path,
        guard_home=guard_home,
        recording_only=observe_mode,
    )
