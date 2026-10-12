"""Per-workspace readiness for the home-wide native policy snapshot."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from .native_policy_snapshot_publisher import NativePolicySnapshotPublisher


class NativePolicySnapshotWorkspaceReadinessMixin:
    """Gate only a newly observed workspace while its overlay is published.

    The snapshot merges every registered workspace overlay strictest-first.
    A new workspace may add a stricter overlay, so its own hooks must wait
    for an ACK that compiled it. Workspaces already compiled into the ACKed
    snapshot keep that exact authority meanwhile: withdrawing it home-wide
    stalls every concurrent harness, and bumping the publish epoch discards
    in-flight ACKs so a stream of new workspaces can starve readiness.
    """

    def register_workspace(self, workspace: Path | None) -> bool:
        """Track workspace override files without reading them on a hook."""

        publisher = cast("NativePolicySnapshotPublisher", self)
        if workspace is None:
            return False
        candidate = publisher._resolved_workspace(workspace)
        with publisher._condition:
            if candidate in publisher._workspace_paths:
                return False
            publisher._workspace_paths.add(candidate)
            publisher._pending_workspace_paths.add(candidate)
            # Re-read input files including this workspace's overlays.
            publisher._input_fingerprint = None
            if publisher._closed:
                return True
            publisher._queue_pending_workspace_publish_locked()
            publisher._condition.notify_all()
        publisher._publish_event.set()
        return True

    def workspace_policy_pending(self, workspace: Path | None) -> bool:
        """True until an ACKed snapshot compiled this workspace's overlays."""

        publisher = cast("NativePolicySnapshotPublisher", self)
        if workspace is None:
            return False
        candidate = publisher._resolved_workspace(workspace)
        with publisher._condition:
            return candidate in publisher._pending_workspace_paths

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
        if publisher._pending_workspace_paths:
            publisher._queue_pending_workspace_publish_locked()
            publisher._publish_event.set()
