"""Per-workspace readiness for the home-wide native policy snapshot."""

from __future__ import annotations

import time
import uuid
from pathlib import Path
from typing import TYPE_CHECKING, cast

from .native_context import ensure_resident_prerequisite
from .native_execution import _resident_request
from .native_runtime import native_runtime_status

if TYPE_CHECKING:
    from .native_policy_snapshot_publisher import NativePolicySnapshotPublisher


_OVERLAY_READINESS_BUDGET_SECONDS = 0.15


def _workspace_overlay_readiness(
    publisher: NativePolicySnapshotPublisher, candidate: Path, deadline: float | None
) -> object:
    now = time.monotonic()
    probe_deadline = now + _OVERLAY_READINESS_BUDGET_SECONDS
    if deadline is not None:
        probe_deadline = min(probe_deadline, deadline)
    if probe_deadline <= now:
        return None
    guard_home = publisher.guard_home
    if not ensure_resident_prerequisite(guard_home, store=publisher.store):
        return None
    status = native_runtime_status(deadline_monotonic=probe_deadline)
    timeout_seconds = probe_deadline - time.monotonic()
    if timeout_seconds <= 0:
        return None
    request_id = uuid.uuid4().hex
    try:
        result = _resident_request(
            operation="hook_workspace_overlay_readiness",
            request={
                "schema": "guard-hook-workspace-overlay-readiness-request.v1",
                "request_id": request_id,
                "workspace": str(candidate),
            },
            guard_home=guard_home,
            timeout_seconds=timeout_seconds,
            required_feature="hook-workspace-overlay-readiness-v1",
            response_schema="guard-hook-workspace-overlay-readiness-result.v1",
            record_resilience=False,
            status=status,
        )
    except (OSError, RuntimeError, TypeError, ValueError):
        return None
    return result.get("readiness") if result and result.get("request_id") == request_id else None


class NativePolicySnapshotWorkspaceReadinessMixin:
    """Gate only a newly observed workspace while its overlay is published.

    The snapshot merges every registered workspace overlay strictest-first.
    A new workspace may add a stricter overlay, so its own hooks must wait
    for an ACK that compiled it. Workspaces already compiled into the ACKed
    snapshot keep that exact authority meanwhile: withdrawing it home-wide
    stalls every concurrent harness, and bumping the publish epoch discards
    in-flight ACKs so a stream of new workspaces can starve readiness.
    """

    def register_workspace(self, workspace: Path | None, *, deadline: float | None = None) -> bool:
        """Track workspace override files without reading them on a hook."""

        publisher = cast("NativePolicySnapshotPublisher", self)
        if workspace is None:
            return False
        candidate = publisher._resolved_workspace(workspace)
        with publisher._condition:
            # Only a new or deferred workspace needs the overlay scans below.
            if candidate in publisher._workspace_paths and candidate not in publisher._deferred_workspace_paths:
                return False
            can_reuse_snapshot = publisher._acked or publisher._under_settled_workspace_locked(candidate)
        readiness = _workspace_overlay_readiness(publisher, candidate, deadline) if can_reuse_snapshot else None
        file_less = readiness in ("directory_only", "directory_and_ancestors")
        free_ancestors = readiness == "directory_and_ancestors"
        with publisher._condition:
            if candidate in publisher._workspace_paths:
                if candidate not in publisher._deferred_workspace_paths or (
                    file_less and publisher._covered_by_ack_locked(candidate, free_ancestors=free_ancestors)
                ):
                    return False
                # A deferred workspace gained an overlay; it now needs its own ACK.
                publisher._deferred_workspace_paths.discard(candidate)
                registered = False
            else:
                publisher._workspace_paths.add(candidate)
                publisher._pending_workspace_paths.add(candidate)
                # Re-read input files including this workspace's overlays.
                publisher._input_fingerprint = None
                registered = True
                if file_less and publisher._covered_by_ack_locked(candidate, free_ancestors=free_ancestors):
                    # The current ACK already carries this workspace's policy.
                    # A publish now would supersede the generation its hooks
                    # are presenting, so it compiles with the next publish.
                    publisher._deferred_workspace_paths.add(candidate)
                    return True
            if publisher._closed:
                return registered
            publisher._queue_pending_workspace_publish_locked()
            publisher._condition.notify_all()
        publisher._publish_event.set()
        return registered

    def workspace_policy_pending(self, workspace: Path | None) -> bool:
        """True until an ACKed snapshot compiled this workspace's overlays."""

        publisher = cast("NativePolicySnapshotPublisher", self)
        if workspace is None:
            return False
        candidate = publisher._resolved_workspace(workspace)
        with publisher._condition:
            return candidate in publisher._pending_workspace_paths

    def workspace_admissible_without_overlay(self, workspace: Path | None, *, deadline: float | None = None) -> bool:
        """True when the ACKed snapshot already holds this pending workspace's policy.

        A workspace config reads only that directory's own overlay files, and
        the snapshot merges every overlay strictest-first over the home config.
        A canonical directory that has no overlay file therefore contributes
        nothing beyond the home config, so its hooks may use the current ACK
        until a later publish compiles it. That holds below an already compiled
        workspace, or where no ancestor holds an overlay; below an unsettled
        overlay the directory waits, since that overlay joins the merge once it
        settles. Any overlay entry, read error, symlink or junction keeps the
        workspace gated on its own ACK.
        """

        publisher = cast("NativePolicySnapshotPublisher", self)
        if workspace is None:
            return False
        candidate = publisher._resolved_workspace(workspace)
        with publisher._condition:
            if candidate not in publisher._deferred_workspace_paths:
                return False
        readiness = _workspace_overlay_readiness(publisher, candidate, deadline)
        if readiness not in ("directory_only", "directory_and_ancestors"):
            return False
        with publisher._condition:
            return candidate in publisher._deferred_workspace_paths and publisher._covered_by_ack_locked(
                candidate, free_ancestors=readiness == "directory_and_ancestors"
            )

    def _covered_by_ack_locked(self, candidate: Path, *, free_ancestors: bool) -> bool:
        publisher = cast("NativePolicySnapshotPublisher", self)
        if publisher._under_settled_workspace_locked(candidate):
            return True
        return free_ancestors and publisher._acked and publisher._snapshot is not None

    def _under_settled_workspace_locked(self, candidate: Path) -> bool:
        publisher = cast("NativePolicySnapshotPublisher", self)
        settled = publisher._workspace_paths - publisher._pending_workspace_paths
        return any(candidate != parent and candidate.is_relative_to(parent) for parent in settled)

    def _queue_pending_workspace_publish_locked(self) -> None:
        publisher = cast("NativePolicySnapshotPublisher", self)
        snapshot = publisher._snapshot
        generation = snapshot.get("generation") if snapshot is not None else None
        if publisher._acked and isinstance(generation, int) and generation > 0:
            publisher._renewal_after_generation = generation
        publisher._retry_not_before_monotonic = publisher._monotonic_clock()
        publisher._failure_count = 0
        # The queued publish supersedes an earlier attempt's error. Hooks for
        # the pending workspace wait for it instead of failing on stale state;
        # admission still requires an ACK that compiled the workspace.
        publisher._last_error = None

    def _commit_workspace_readiness_locked(self, compiled_workspaces: frozenset[Path]) -> None:
        """Release workspaces compiled into the ACK; requeue later arrivals."""

        publisher = cast("NativePolicySnapshotPublisher", self)
        publisher._pending_workspace_paths.difference_update(compiled_workspaces)
        publisher._deferred_workspace_paths.intersection_update(publisher._pending_workspace_paths)
        if publisher._pending_workspace_paths - publisher._deferred_workspace_paths:
            publisher._queue_pending_workspace_publish_locked()
            publisher._publish_event.set()
