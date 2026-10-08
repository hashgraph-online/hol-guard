"""Bounded workspace admission after native publication acknowledgement."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .hook_worker import HookWorker


def prepare_workspace_policy(
    worker: HookWorker,
    workspace: Path | None = None,
    *,
    deadline: float | None = None,
    now: float,
) -> dict[str, object] | None:
    """Prepare an ACKed workspace policy before admitting a native hook.

    Workspace overlays are published asynchronously, so the first hook
    for a workspace must complete this same barrier used by normal hook
    evaluation. The barrier is always capped at the native readiness
    budget. Publishing workers fail closed when readiness is unavailable;
    non-publishing workers may reuse a still-valid resident-accepted snapshot.
    """

    from . import hook_worker as owner

    if owner.native_mode() not in {"auto", "force", "shadow"}:
        return None
    workspace_pending = getattr(worker.policy_snapshot_publisher, "workspace_policy_pending", None)
    if worker._publish_native_policy:
        register_workspace = getattr(worker.policy_snapshot_publisher, "register_workspace", None)
        if callable(register_workspace):
            _ = register_workspace(workspace)
        worker.policy_snapshot_publisher.start()
        if owner.native_mode() in {"auto", "force"}:
            wait_until_ready = getattr(worker.policy_snapshot_publisher, "wait_until_ready", None)
            last_error = getattr(worker.policy_snapshot_publisher, "last_error", None)
            # A replacement resident can serve persisted policy before the
            # publisher confirms its new generation. Its restart-budget
            # lock can also be briefly held by a concurrent native client.
            # Await the fresh ACK within the existing deadline; unrelated
            # publication errors still fail immediately.
            transient_publication_error = (
                isinstance(last_error, str) and last_error in owner._TRANSIENT_RESIDENT_PUBLICATION_ERRORS
            )
            no_publication_error = last_error is None or (isinstance(last_error, str) and not last_error.strip())
            if callable(wait_until_ready) and (transient_publication_error or no_publication_error):
                readiness_deadline = now + owner._NATIVE_POLICY_READY_TIMEOUT_SECONDS
                if deadline is not None:
                    readiness_deadline = min(readiness_deadline, deadline)
                if callable(workspace_pending) and workspace_pending(workspace):
                    _ = wait_until_ready(readiness_deadline, workspace=workspace)
                else:
                    _ = wait_until_ready(readiness_deadline)
        if callable(workspace_pending) and workspace_pending(workspace):
            # Never admit a new workspace on a snapshot without its overlay.
            return None
    current_snapshot_binding = getattr(worker.policy_snapshot_publisher, "current_snapshot_binding", None)
    if callable(current_snapshot_binding):
        snapshot = current_snapshot_binding()
        if isinstance(snapshot, dict):
            return snapshot
    current_snapshot = getattr(worker.policy_snapshot_publisher, "current_snapshot", None)
    if callable(current_snapshot):
        snapshot = current_snapshot()
        if isinstance(snapshot, dict):
            return snapshot
    if worker._publish_native_policy:
        return None
    return owner.acked_snapshot_binding_for_store(worker.store)
