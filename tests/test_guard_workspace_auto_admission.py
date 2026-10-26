from __future__ import annotations

import sqlite3
import threading
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import config as guard_config
from codex_plugin_scanner.guard import native_workspace_snapshot as native
from codex_plugin_scanner.guard import workspace_assessment_admissions as admissions
from codex_plugin_scanner.guard import workspace_assessment_store as assessments
from codex_plugin_scanner.guard import workspace_assessment_worker as worker
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_workspace_assessment_runner import KEYS, SNAPSHOT, T0, digest, snapshots

STAT = replace(SNAPSHOT, mode="stat")
NOW = "2026-10-25T00:00:00+00:00"


def register(store: GuardStore, harness: str, workspace: str | None, *, active: bool = True) -> None:
    store.set_managed_install(harness, active, workspace, {}, NOW)


def test_registered_workspace_is_admitted_once_with_a_workspace_open_run(tmp_path: Path, monkeypatch) -> None:
    store = GuardStore(tmp_path / "home")
    modes = snapshots(monkeypatch, worker, STAT)
    register(store, "claude-code", str(tmp_path))
    register(store, "codex", str(tmp_path))

    assert worker.admit_registered_workspaces(store, clock=lambda: T0) == 1
    [worktree] = assessments.list_worktrees(store)
    assert (worktree["worktree_key"], worktree["root"]) == (KEYS.worktree_key, str(tmp_path.resolve()))
    [run] = assessments.recent_runs(store)
    assert run["trigger_kind"] == "workspace_open"
    # Already admitted: no second snapshot, no second run.
    assert worker.admit_registered_workspaces(store, clock=lambda: T0) == 0
    assert modes == ["stat"]
    assert len(assessments.recent_runs(store)) == 1


def test_installs_without_a_usable_workspace_admit_nothing(tmp_path: Path, monkeypatch) -> None:
    store = GuardStore(tmp_path / "home")
    monkeypatch.setattr(worker, "workspace_snapshot", pytest.fail)
    register(store, "claude-code", None)
    register(store, "codex", "relative/project")
    register(store, "cursor", str(tmp_path / "missing"))
    register(store, "opencode", str(tmp_path), active=False)

    assert worker.admit_registered_workspaces(store, clock=lambda: T0) == 0
    assert assessments.list_worktrees(store) == []


def test_automatic_admission_never_resumes_a_paused_worktree(tmp_path: Path, monkeypatch) -> None:
    store = GuardStore(tmp_path / "home")
    old_root = tmp_path / "old"
    old_root.mkdir()
    assessments.admit_worktree(store, KEYS, root=str(old_root), now_ms=T0)
    assert assessments.set_paused(store, KEYS, paused=True)
    # The same worktree, reached through a newly registered root.
    snapshots(monkeypatch, worker, STAT)
    register(store, "claude-code", str(tmp_path))

    assert worker.admit_registered_workspaces(store, clock=lambda: T0) == 0
    [worktree] = assessments.list_worktrees(store)
    assert worktree["paused"] is True
    assert worktree["root"] == str(old_root)
    assert assessments.recent_runs(store) == []


def test_rejected_root_is_not_walked_again(tmp_path: Path, monkeypatch) -> None:
    store = GuardStore(tmp_path / "home")
    calls: list[Path] = []

    def unavailable(root: Path, **_: object) -> native.WorkspaceSnapshot:
        calls.append(root)
        raise native.WorkspaceSnapshotError("workspace_snapshot_unavailable")

    monkeypatch.setattr(worker, "workspace_snapshot", unavailable)
    register(store, "claude-code", str(tmp_path))
    attempted: dict[str, int] = {}

    assert worker.admit_registered_workspaces(store, attempted=attempted, clock=lambda: T0) == 0
    assert worker.admit_registered_workspaces(store, attempted=attempted, clock=lambda: T0 + 1) == 0
    assert len(calls) == 1
    assert assessments.list_worktrees(store) == []


def test_failed_admission_is_retried_after_the_backoff(tmp_path: Path, monkeypatch) -> None:
    store = GuardStore(tmp_path / "home")
    calls: list[Path] = []

    def unavailable(root: Path, **_: object) -> native.WorkspaceSnapshot:
        calls.append(root)
        raise native.WorkspaceSnapshotError("native_runtime_unavailable")

    monkeypatch.setattr(worker, "workspace_snapshot", unavailable)
    register(store, "claude-code", str(tmp_path))
    attempted: dict[str, int] = {}
    assert worker.admit_registered_workspaces(store, attempted=attempted, clock=lambda: T0) == 0

    # The native runtime comes back; the root is tried again once its wait ends.
    snapshots(monkeypatch, worker, STAT)
    retry_at = T0 + worker.ADMISSION_RETRY_MS
    assert worker.admit_registered_workspaces(store, attempted=attempted, clock=lambda: retry_at - 1) == 0
    assert worker.admit_registered_workspaces(store, attempted=attempted, clock=lambda: retry_at) == 1
    assert len(calls) == 1
    assert attempted == {}
    assert [run["trigger_kind"] for run in assessments.recent_runs(store)] == ["workspace_open"]


def test_symlink_loop_skips_only_that_workspace(tmp_path: Path, monkeypatch) -> None:
    store = GuardStore(tmp_path / "home")
    snapshots(monkeypatch, worker, STAT)
    loop = tmp_path / "loop"
    loop.symlink_to(tmp_path / "back")
    (tmp_path / "back").symlink_to(loop)
    project = tmp_path / "project"
    project.mkdir()
    register(store, "claude-code", str(loop))
    register(store, "codex", str(project))

    assert worker.admit_registered_workspaces(store, attempted={}, clock=lambda: T0) == 1
    assert [item["root"] for item in assessments.list_worktrees(store)] == [str(project.resolve())]
    with pytest.raises(worker.WorkspaceAdmissionError, match="workspace_root_missing"):
        worker.admit_workspace(store, str(loop))


def test_root_that_now_names_another_worktree_is_admitted_again(tmp_path: Path, monkeypatch) -> None:
    store = GuardStore(tmp_path / "home")
    snapshots(monkeypatch, worker, STAT)
    register(store, "claude-code", str(tmp_path))
    assert worker.admit_registered_workspaces(store, clock=lambda: T0) == 1
    # The path became another repository; the next observation lost the old worktree.
    assessments.record_observation(store, KEYS, stat_digest=worker.UNAVAILABLE_STAT_DIGEST)
    other = replace(STAT, codebase_key=digest("codebase-2"), worktree_key=digest("worktree-2"))
    snapshots(monkeypatch, worker, other)

    assert worker.admit_registered_workspaces(store, clock=lambda: T0 + 1) == 1
    [worktree] = assessments.list_worktrees(store)
    assert (worktree["codebase_key"], worktree["worktree_key"]) == (other.codebase_key, other.worktree_key)
    [run] = assessments.recent_runs(store)
    assert run["trigger_kind"] == "workspace_open"


def test_failed_enqueue_leaves_no_admission_behind(tmp_path: Path, monkeypatch) -> None:
    store = GuardStore(tmp_path / "home")
    snapshots(monkeypatch, worker, STAT)
    register(store, "claude-code", str(tmp_path))

    def broken(*_: object, **__: object) -> str:
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(admissions, "_enqueue_locked", broken)
    with pytest.raises(sqlite3.OperationalError):
        worker.admit_registered_workspaces(store, clock=lambda: T0)
    assert assessments.list_worktrees(store) == []

    monkeypatch.undo()
    snapshots(monkeypatch, worker, STAT)
    assert worker.admit_registered_workspaces(store, clock=lambda: T0) == 1
    assert len(assessments.recent_runs(store)) == 1


def test_uninstall_ends_an_automatic_admission(tmp_path: Path, monkeypatch) -> None:
    store = GuardStore(tmp_path / "home")
    snapshots(monkeypatch, worker, STAT)
    register(store, "claude-code", str(tmp_path))
    register(store, "codex", str(tmp_path))
    assert worker.admit_registered_workspaces(store, clock=lambda: T0) == 1

    register(store, "claude-code", str(tmp_path), active=False)
    worker.admit_registered_workspaces(store, clock=lambda: T0)
    assert len(assessments.list_worktrees(store)) == 1

    register(store, "codex", str(tmp_path), active=False)
    worker.admit_registered_workspaces(store, clock=lambda: T0)
    assert assessments.list_worktrees(store) == []
    assert assessments.recent_runs(store) == []


def test_uninstall_keeps_an_admission_someone_made_themselves(tmp_path: Path, monkeypatch) -> None:
    store = GuardStore(tmp_path / "home")
    snapshots(monkeypatch, worker, STAT)
    register(store, "claude-code", str(tmp_path))
    assert worker.admit_registered_workspaces(store, clock=lambda: T0) == 1
    worker.admit_workspace(store, str(tmp_path), clock=lambda: T0)

    register(store, "claude-code", str(tmp_path), active=False)
    worker.admit_registered_workspaces(store, clock=lambda: T0)
    assert [item["worktree_key"] for item in assessments.list_worktrees(store)] == [KEYS.worktree_key]


def test_poll_admits_registered_workspaces_before_observing(tmp_path: Path, monkeypatch) -> None:
    store = GuardStore(tmp_path / "home")
    snapshots(monkeypatch, worker, replace(STAT, snapshot_digest=digest("stat-1")))
    monkeypatch.setattr(guard_config, "load_guard_config", lambda home: object())
    monkeypatch.setattr(worker, "run_next", lambda store, config, owner, user_only=False: False)
    monkeypatch.setattr(worker, "host_resource_pressure", lambda: None)
    register(store, "claude-code", str(tmp_path))

    assert worker.poll_once(store, owner="test", stop=threading.Event(), attempted={}) == 0
    [run] = assessments.recent_runs(store)
    assert run["trigger_kind"] == "workspace_open"


def test_manual_admission_still_resumes_a_paused_worktree(tmp_path: Path, monkeypatch) -> None:
    store = GuardStore(tmp_path / "home")
    snapshots(monkeypatch, worker, STAT)
    worker.admit_workspace(store, str(tmp_path), clock=lambda: T0)
    assert assessments.set_paused(store, KEYS, paused=True)

    worker.admit_workspace(store, str(tmp_path), clock=lambda: T0)
    assert assessments.list_worktrees(store)[0]["paused"] is False


def test_removing_an_install_withdraws_its_admission_while_the_host_is_busy(tmp_path: Path, monkeypatch) -> None:
    store = GuardStore(tmp_path / "home")
    snapshots(monkeypatch, worker, STAT)
    register(store, "claude-code", str(tmp_path))
    assert worker.admit_registered_workspaces(store, clock=lambda: T0) == 1
    register(store, "claude-code", str(tmp_path), active=False)
    monkeypatch.setattr(worker, "host_resource_pressure", lambda: "resource_pressure")

    worker.poll_once(store, owner="test")
    assert assessments.list_worktrees(store) == []
