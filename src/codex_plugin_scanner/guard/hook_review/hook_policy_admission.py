"""Native-policy barrier applied before a hook is admitted to the worker."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from ..native_policy_admission import native_policy_not_ready_reason
from ..native_policy_snapshot_resident_recovery import RESIDENT_FAIL_FAST_STREAK, is_resident_class_error
from .hook_fail_closed import unmanaged_passthrough
from .hook_policy_fence_window import policy_update_pending_reason

_NATIVE_POLICY_NOT_READY_FALLBACK = (
    "HOL Guard could not prepare the native policy safely. This is usually temporary. Retry this action."
)
_NATIVE_POLICY_INSTALL_REPAIR_FALLBACK = (
    "HOL Guard could not prepare the native policy safely. Guard's installed files disagree, so retrying will not "
    "clear it. Ask the user to run `hol-guard doctor`."
)
_NATIVE_POLICY_RESIDENT_DOWN_FALLBACK = (
    "HOL Guard could not prepare the native policy safely. The native runtime is not answering. "
    "Retry once more; if it still fails, ask the user to run `hol-guard repair` in a terminal."
)


def _native_managed_install_unmanaged(store: Any, harness: str) -> bool:
    """Read the resident's atomic managed-install admission answer."""

    native_store_call = getattr(store, "_native_store_call", None)
    if not callable(native_store_call):
        return False
    try:
        admission = native_store_call("hook_managed_install_admission", {"harness": harness})
    except (OSError, RuntimeError, TypeError, ValueError, AttributeError):
        return False
    return isinstance(admission, Mapping) and admission.get("unmanaged") is True


def _native_policy_not_ready_reason(daemon_server: Any, *, deadline: float | None = None) -> str:
    publisher = getattr(getattr(daemon_server, "hook_worker", None), "policy_snapshot_publisher", None)
    last_error = getattr(publisher, "last_error", None)
    streak_reader = getattr(publisher, "resident_failure_streak", None)
    streak = streak_reader() if callable(streak_reader) else 0
    worker = getattr(daemon_server, "hook_worker", None)
    guard_home = getattr(worker, "guard_home", None)
    resident_down = (
        isinstance(last_error, str)
        and is_resident_class_error(last_error.strip())
        and isinstance(streak, int)
        and not isinstance(streak, bool)
        and streak >= RESIDENT_FAIL_FAST_STREAK
    )
    if resident_down:
        return _NATIVE_POLICY_RESIDENT_DOWN_FALLBACK
    if isinstance(guard_home, Path):
        reason = native_policy_not_ready_reason(last_error, streak, guard_home, deadline=deadline)
        if reason is not None:
            return reason
    if last_error == "native_business_source_mutation_in_progress":
        return policy_update_pending_reason()
    # A resident that is already down cannot answer the Rust posture query.
    # Keep this fixed transport-outage response local so repeated failures do
    # not send the hook back into an unproductive retry loop.
    if last_error == "native_command_program_binding_mismatch":
        return _NATIVE_POLICY_INSTALL_REPAIR_FALLBACK
    return _NATIVE_POLICY_NOT_READY_FALLBACK


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

    from ..native_harness_client import canonical_harness

    harness = canonical_harness(default_harness)
    store = getattr(daemon_server, "store", None)
    if _native_managed_install_unmanaged(store, harness):
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
            reason=_native_policy_not_ready_reason(daemon_server, deadline=deadline),
            reason_code="native_policy_not_ready",
        )
    )
    return False
