"""Bounded workspace admission after native publication acknowledgement."""

from __future__ import annotations

import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast
from uuid import uuid4

from ..native_execution import _resident_request
from ..native_policy_snapshot_constants import POLICY_SNAPSHOT_UNRECOVERABLE_ERRORS
from ..native_policy_snapshot_resident_recovery import (
    RESIDENT_FAIL_FAST_STREAK,
    RESIDENT_NUDGE_MIN_INTERVAL_SECONDS,
    is_resident_class_error,
)
from ..native_runtime import NativeRuntimeStatus, native_runtime_status

if TYPE_CHECKING:
    from .hook_worker import HookWorker


def _resident_streak(publisher: Any) -> int:
    reader = getattr(publisher, "resident_failure_streak", None)
    streak = reader() if callable(reader) else 0
    return streak if isinstance(streak, int) else 0


def _native_wait_for_ack(
    publisher: Any,
    last_error: object,
    resident_failure_streak: int,
    deadline: float,
) -> bool | None:
    """Ask Rust whether this publisher state merits another ACK attempt.

    The publisher remains Python-owned transport. Rust owns the bounded error
    classification so the hook worker does not duplicate the daemon's policy
    admission rules. ``None`` keeps older residents on the compatibility path.
    """

    guard_home = getattr(publisher, "guard_home", None)
    if not isinstance(guard_home, Path):
        return None
    probe_deadline = min(deadline, time.monotonic() + 0.1)
    if probe_deadline <= time.monotonic():
        return None
    try:
        status_reader = getattr(publisher, "current_runtime_status", None)
        status = cast(NativeRuntimeStatus | None, status_reader() if callable(status_reader) else None)
        if status is None:
            status = native_runtime_status(deadline_monotonic=probe_deadline)
        timeout_seconds = probe_deadline - time.monotonic()
        if timeout_seconds <= 0:
            return None
        request_id = f"hook-policy-admission-{uuid4().hex}"
        request: dict[str, object] = {
            "schema": "guard-hook-policy-admission-request.v1",
            "request_id": request_id,
            "resident_failure_streak": resident_failure_streak,
        }
        if isinstance(last_error, str):
            request["last_error"] = last_error
        response = _resident_request(
            operation="hook_policy_admission",
            request=request,
            guard_home=guard_home,
            timeout_seconds=timeout_seconds,
            required_feature="hook-policy-admission-v1",
            response_schema="guard-hook-policy-admission-result.v1",
            record_resilience=False,
            diagnostic=True,
            status=status,
        )
        result = response.get("result") if response is not None else None
        if isinstance(result, dict) and result.get("request_id") == request_id:
            wait_for_ack = result.get("wait_for_ack")
            if isinstance(wait_for_ack, bool):
                return wait_for_ack
    except (OSError, RuntimeError, TypeError, ValueError):
        pass
    return None


def _wait_nudging_publisher(
    publisher: Any,
    wait_until_ready: Any,
    deadline: float,
    *,
    workspace: Path | None,
    pending: bool,
) -> None:
    """Wait for the ACK while pulling the publisher's next attempt forward.

    The publisher backs off between failed attempts for up to five seconds,
    longer than a hook can wait, so a bare wait would sit out the whole budget
    on a resident that has already come back. Waiting in short slices and
    nudging between them lets the first attempt after recovery decide the hook.
    The wait ends once the failures repeat: a resident that stays down answers
    the next hook fast with advice rather than costing it the whole deadline.
    """

    nudge = publisher.nudge_retry
    while True:
        # A retired publisher returns immediately from wait_until_ready. Do
        # not spin on its closed state for the remainder of the hook budget.
        if getattr(publisher, "closed", False) is True:
            return
        _ = nudge()
        slice_deadline = min(deadline, time.monotonic() + RESIDENT_NUDGE_MIN_INTERVAL_SECONDS)
        ready = wait_until_ready(slice_deadline, workspace=workspace) if pending else wait_until_ready(slice_deadline)
        if ready or time.monotonic() >= deadline:
            return
        if getattr(publisher, "closed", False) is True:
            return
        last_error = getattr(publisher, "last_error", None)
        if last_error in POLICY_SNAPSHOT_UNRECOVERABLE_ERRORS:
            return
        if is_resident_class_error(last_error) and _resident_streak(publisher) >= RESIDENT_FAIL_FAST_STREAK:
            return


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

    workspace_pending = getattr(worker.policy_snapshot_publisher, "workspace_policy_pending", None)
    admissible_without_overlay = getattr(worker.policy_snapshot_publisher, "workspace_admissible_without_overlay", None)
    if worker._publish_native_policy:
        readiness_deadline = now + owner._NATIVE_POLICY_READY_TIMEOUT_SECONDS
        if deadline is not None:
            readiness_deadline = min(readiness_deadline, deadline)
        register_workspace = getattr(worker.policy_snapshot_publisher, "register_workspace", None)
        if callable(register_workspace):
            _ = register_workspace(workspace, deadline=readiness_deadline)
        worker.policy_snapshot_publisher.start()
        wait_until_ready = getattr(worker.policy_snapshot_publisher, "wait_until_ready", None)
        last_error = getattr(worker.policy_snapshot_publisher, "last_error", None)
        # A replacement resident can serve persisted policy before the
        # publisher confirms its new generation. Its restart-budget
        # lock can also be briefly held by a concurrent native client.
        # Await the fresh ACK within the existing deadline; unrelated
        # publication errors still fail immediately.
        # A resident that stopped answering recovers on the same terms, so it
        # is waited for too, until its failures repeat (see _wait_nudging_publisher).
        transient_publication_error = isinstance(last_error, str) and (
            last_error in owner._TRANSIENT_RESIDENT_PUBLICATION_ERRORS
            or (
                is_resident_class_error(last_error)
                and _resident_streak(worker.policy_snapshot_publisher) < RESIDENT_FAIL_FAST_STREAK
            )
        )
        no_publication_error = last_error is None or (isinstance(last_error, str) and not last_error.strip())
        native_wait = (
            None
            if no_publication_error
            else _native_wait_for_ack(
                worker.policy_snapshot_publisher,
                last_error,
                _resident_streak(worker.policy_snapshot_publisher),
                readiness_deadline,
            )
        )
        # A file-less directory adds no overlay, so the current ACK already
        # carries its policy unless an unsettled ancestor overlay is about to
        # join it. Hooks right after `cd` into it need not wait for a publish.
        covered = callable(admissible_without_overlay) and admissible_without_overlay(
            workspace, deadline=readiness_deadline
        )
        # Older installed residents do not expose the Rust posture yet.
        should_wait = native_wait if native_wait is not None else (transient_publication_error or no_publication_error)
        if callable(wait_until_ready) and should_wait:
            pending = not covered and callable(workspace_pending) and bool(workspace_pending(workspace))
            if callable(getattr(worker.policy_snapshot_publisher, "nudge_retry", None)):
                _wait_nudging_publisher(
                    worker.policy_snapshot_publisher,
                    wait_until_ready,
                    readiness_deadline,
                    workspace=workspace,
                    pending=pending,
                )
            elif pending:
                _ = wait_until_ready(readiness_deadline, workspace=workspace)
            else:
                _ = wait_until_ready(readiness_deadline)
        elif callable(getattr(worker.policy_snapshot_publisher, "nudge_retry", None)):
            # Failing fast: still ask for one more attempt, so the next hook
            # finds the resident back if it recovered in the meantime.
            _ = worker.policy_snapshot_publisher.nudge_retry()
        if not covered and callable(workspace_pending) and workspace_pending(workspace):
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
