"""Native-policy barrier applied before a hook is admitted to the worker."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from ..native_policy_snapshot_constants import POLICY_SNAPSHOT_PERSISTENT_ERRORS
from ..native_policy_snapshot_resident_recovery import RESIDENT_FAIL_FAST_STREAK, is_resident_class_error
from .hook_fail_closed import unmanaged_passthrough
from .hook_managed_install_state import _canonical_managed_harness, _hook_harness_is_unmanaged
from .hook_policy_fence_window import POLICY_SOURCE_FENCE_ERRORS, policy_update_pending_reason


def _native_policy_not_ready_reason(daemon_server: Any) -> str:
    reason = "HOL Guard could not prepare the native policy safely."
    retry = "This is usually temporary. Retry this action."
    # An install whose files disagree rejects every snapshot, so telling the
    # agent to retry sends it around the same failure until the user repairs
    # the install.
    repair = "Guard's installed files disagree, so retrying will not clear it. Ask the user to run `hol-guard doctor`."
    # The resident stopped answering and the failures have repeated: a retry
    # may land on a recovered resident, but only the user can restart it if not.
    resident_down = (
        "Guard's native runtime is not answering. Retry once more; if it still fails, "
        "ask the user to run `hol-guard repair` in a terminal."
    )
    publisher = getattr(getattr(daemon_server, "hook_worker", None), "policy_snapshot_publisher", None)
    last_error = getattr(publisher, "last_error", None)
    if isinstance(last_error, str) and last_error.strip():
        code = last_error.strip()
        if code in POLICY_SOURCE_FENCE_ERRORS:
            return policy_update_pending_reason()
        advice = repair if code in POLICY_SNAPSHOT_PERSISTENT_ERRORS else retry
        streak_reader = getattr(publisher, "resident_failure_streak", None)
        streak = streak_reader() if callable(streak_reader) else 0
        if is_resident_class_error(code) and isinstance(streak, int) and streak >= RESIDENT_FAIL_FAST_STREAK:
            advice = resident_down
        return f"{reason} {code}. {advice}"
    return f"{reason} {retry}"


def prepare_native_hook_policy(
    handler: Any,
    daemon_server: Any,
    payload: dict[str, object],
    params: Mapping[str, list[str]],
    default_harness: str,
    workspace: str | None,
    deadline: float,
) -> bool:
    """Apply the production native-policy barrier before hook admission."""

    harness = _canonical_managed_harness(default_harness)
    if _hook_harness_is_unmanaged(daemon_server, harness):
        handler._write_json(unmanaged_passthrough(harness))
        return False
    workspace_path = Path(workspace) if workspace is not None else None
    prepared_policy = daemon_server.hook_worker.prepare_workspace_policy(
        workspace_path,
        deadline=deadline,
    )
    if prepared_policy is not None:
        return True
    daemon_server.hook_worker.metrics.record_route("native_fail_safe")
    handler._write_json(
        handler._runtime_hook_fail_safe_response(
            payload,
            params,
            default_harness=default_harness,
            reason=_native_policy_not_ready_reason(daemon_server),
            reason_code="native_policy_not_ready",
        )
    )
    return False
