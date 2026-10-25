"""Background loop for workspace assessments.

Only worktrees a user admitted (from the dashboard or the CLI) are watched.
Each poll takes a cheap stat snapshot of every admitted worktree and a digest
of the cached advisory bundles; a change queues an assessment, and the
coordinator's debounce and interval decide when it runs. Nothing here runs in
a hook path, and the Cloud audit is never used.
"""

from __future__ import annotations

import hashlib
import os
import threading
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any, Final

from . import workspace_assessment_store as assessments
from .native_workspace_snapshot import WorkspaceSnapshotError, workspace_snapshot
from .workspace_assessment_runner import DETECTOR_SET_DIGEST, feed_context_digest, now_ms, run_next

POLL_INTERVAL_SECONDS: Final = 30.0
# Recorded when an admitted root is missing, unreadable or now names another
# worktree. Losing the root is itself a change: it queues one run, which fails
# with the reason, and staying lost queues nothing more.
UNAVAILABLE_STAT_DIGEST: Final = hashlib.sha256(b"guard.workspace-stat.unavailable.v1").hexdigest()
# Runs per poll; the rest wait for the next poll so shutdown stays prompt.
_MAX_RUNS_PER_POLL: Final = 4


class WorkspaceAdmissionError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def admit_workspace(store: Any, root: str, *, clock: Callable[[], int] = now_ms) -> dict[str, object]:
    """Admit a worktree for background assessment and queue its first run."""

    path = Path(root)
    if not path.is_absolute():
        raise WorkspaceAdmissionError("workspace_root_not_absolute")
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise WorkspaceAdmissionError("workspace_root_missing") from error
    if not resolved.is_dir():
        raise WorkspaceAdmissionError("workspace_root_not_directory")
    try:
        snapshot = workspace_snapshot(resolved, mode="stat")
    except WorkspaceSnapshotError as error:
        raise WorkspaceAdmissionError(error.code) from error
    keys = assessments.WorktreeKeys(snapshot.codebase_key, snapshot.worktree_key)
    current = clock()
    assessments.admit_worktree(store, keys, root=str(resolved), now_ms=current)
    assessments.record_observation(
        store, keys, stat_digest=snapshot.snapshot_digest, feed_digest=feed_context_digest(store)
    )
    run_id = assessments.enqueue(
        store, keys, trigger_kind="workspace_open", detector_set_digest=DETECTOR_SET_DIGEST, now_ms=current
    )
    return {"codebase_key": keys.codebase_key, "worktree_key": keys.worktree_key, "run_id": run_id}


def queue_manual_run(
    store: Any,
    keys: assessments.WorktreeKeys,
    *,
    trigger_kind: str = "manual",
    clock: Callable[[], int] = now_ms,
) -> str | None:
    return assessments.enqueue(
        store, keys, trigger_kind=trigger_kind, detector_set_digest=DETECTOR_SET_DIGEST, now_ms=clock()
    )


def observe(store: Any, *, clock: Callable[[], int] = now_ms) -> int:
    """Queue assessments for admitted worktrees whose files or feed changed."""

    queued = 0
    feed_digest = feed_context_digest(store)
    for worktree in assessments.list_worktrees(store, include_paused=False):
        keys = assessments.WorktreeKeys(str(worktree["codebase_key"]), str(worktree["worktree_key"]))
        try:
            snapshot = workspace_snapshot(Path(str(worktree["root"])), mode="stat")
        except WorkspaceSnapshotError:
            snapshot = None
        available = snapshot is not None and snapshot.worktree_key == keys.worktree_key
        triggers = assessments.record_observation(
            store,
            keys,
            stat_digest=snapshot.snapshot_digest if snapshot is not None and available else UNAVAILABLE_STAT_DIGEST,
            feed_digest=feed_digest,
        )
        for trigger in triggers:
            if assessments.enqueue(
                store, keys, trigger_kind=trigger, detector_set_digest=DETECTOR_SET_DIGEST, now_ms=clock()
            ):
                queued += 1
    return queued


def poll_once(store: Any, *, owner: str, stop: threading.Event | None = None) -> int:
    from .config import load_guard_config

    observe(store)
    ran = 0
    config = None
    while ran < _MAX_RUNS_PER_POLL and not (stop is not None and stop.is_set()):
        if config is None:
            config = load_guard_config(store.guard_home)
        if not run_next(store, config, owner=owner):
            break
        ran += 1
    return ran


def start_workspace_assessment_worker(
    store: Any,
    *,
    stop: threading.Event,
    on_error: Callable[[str], object],
    interval: float = POLL_INTERVAL_SECONDS,
) -> threading.Thread:
    """Poll admitted worktrees on a daemon thread until ``stop`` is set."""

    owner = f"daemon:{os.getpid()}:{uuid.uuid4().hex[:12]}"

    def loop() -> None:
        while not stop.wait(interval):
            try:
                poll_once(store, owner=owner, stop=stop)
            except Exception:
                on_error("workspace_assessment_poll_failed")

    thread = threading.Thread(target=loop, name="guard-workspace-assessment", daemon=True)
    thread.start()
    return thread


__all__ = [
    "POLL_INTERVAL_SECONDS",
    "UNAVAILABLE_STAT_DIGEST",
    "WorkspaceAdmissionError",
    "admit_workspace",
    "observe",
    "poll_once",
    "queue_manual_run",
    "start_workspace_assessment_worker",
]
