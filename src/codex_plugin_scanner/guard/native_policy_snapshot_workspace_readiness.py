"""Per-workspace readiness for the home-wide native policy snapshot."""

from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING, cast

from .native_guard_config import WORKSPACE_CONFIG_FILENAMES

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
            # Only a new or deferred workspace needs the overlay scans below.
            if candidate in publisher._workspace_paths and candidate not in publisher._deferred_workspace_paths:
                return False
        file_less = publisher._file_less_canonical_workspace(candidate)
        free_ancestors = file_less and publisher._overlay_free_ancestors(candidate)
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

    def workspace_admissible_without_overlay(self, workspace: Path | None) -> bool:
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
        if not publisher._file_less_canonical_workspace(candidate):
            return False
        free_ancestors = publisher._overlay_free_ancestors(candidate)
        with publisher._condition:
            return candidate in publisher._deferred_workspace_paths and publisher._covered_by_ack_locked(
                candidate, free_ancestors=free_ancestors
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

    @staticmethod
    def _file_less_canonical_workspace(candidate: Path) -> bool:
        try:
            if os.path.realpath(candidate) != os.fspath(candidate):
                return False
        except (OSError, ValueError):
            return False
        return NativePolicySnapshotWorkspaceReadinessMixin._overlay_absent(candidate)

    @staticmethod
    def _overlay_free_ancestors(candidate: Path) -> bool:
        return candidate.is_absolute() and all(
            NativePolicySnapshotWorkspaceReadinessMixin._overlay_absent(parent) for parent in candidate.parents
        )

    @staticmethod
    def _overlay_absent(directory: Path) -> bool:
        for name in WORKSPACE_CONFIG_FILENAMES:
            try:
                _ = os.lstat(directory / name)
            except FileNotFoundError:
                continue
            except (OSError, ValueError):
                return False
            return False
        return True

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
