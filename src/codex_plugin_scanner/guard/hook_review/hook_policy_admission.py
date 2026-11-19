"""Native-policy barrier applied before a hook is admitted to the worker."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from ..native_policy_admission import native_policy_not_ready_reason
from .hook_fail_closed import unmanaged_passthrough
from .hook_managed_install_state import _canonical_managed_harness, _hook_harness_is_unmanaged

_NATIVE_POLICY_NOT_READY_FALLBACK = (
    "HOL Guard could not prepare the native policy safely. This is usually temporary. Retry this action."
)


def _native_policy_not_ready_reason(daemon_server: Any) -> str:
    publisher = getattr(getattr(daemon_server, "hook_worker", None), "policy_snapshot_publisher", None)
    last_error = getattr(publisher, "last_error", None)
    streak_reader = getattr(publisher, "resident_failure_streak", None)
    streak = streak_reader() if callable(streak_reader) else 0
    worker = getattr(daemon_server, "hook_worker", None)
    guard_home = getattr(worker, "guard_home", None)
    if isinstance(guard_home, Path):
        reason = native_policy_not_ready_reason(last_error, streak, guard_home)
        if reason is not None:
            return reason
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
