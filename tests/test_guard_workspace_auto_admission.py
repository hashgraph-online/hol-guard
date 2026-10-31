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
from tests.workspace_fix_support import admit_worktree

STAT = replace(SNAPSHOT, mode="stat")
NOW = "2026-10-25T00:00:00+00:00"


def seed_applied_fix_proposal(store: GuardStore, *, state: str = "verified_fixed") -> None:
    """A proposal for an edit Guard made: the only record of that edit."""

    with store._connect() as connection:
        connection.execute(
            """
            insert into workspace_fix_proposals (
              proposal_id, codebase_key, worktree_key, finding_id, ecosystem, package_name, fix_version,
              advisory_ids_json, rule_ids_json, source_run_id, snapshot_digest, manifest_path, base_sha256,
              new_sha256, edits_json, diff_text, state, created_at_ms, updated_at_ms, applied_at_ms,
              verified_at_ms, verification_run_id
            ) values (?, ?, ?, ?, 'npm', 'minimist', '1.2.9', '[]', '[]', 'run', ?, 'package.json', ?, ?, '[]',
                      '-old\\n+new', ?, ?, ?, ?, ?, 'run-2')
            """,
            (
                "proposal-1",
                KEYS.codebase_key,
                KEYS.worktree_key,
                "f" * 32,
                digest("snapshot"),
                digest("before"),
                digest("after"),
                state,
                T0,
                T0 + 2,
                T0 + 1,
                T0 + 2,
            ),
        )


def stored_records(store: GuardStore) -> dict[str, int]:
    tables = ("workspace_assessment_runs", "workspace_fix_proposals", "workspace_assessment_state")
    with store._connect() as connection:
        return {table: connection.execute(f"select count(*) from {table}").fetchone()[0] for table in tables}


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
    admit_worktree(store, KEYS, root=str(old_root), now_ms=T0)
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
    by_key = {item["worktree_key"]: item for item in assessments.list_worktrees(store)}
    assert by_key[other.worktree_key]["paused"] is False and by_key[other.worktree_key]["ended"] is False
    # The old worktree stops being watched but keeps its history.
    assert by_key[KEYS.worktree_key]["paused"] is True and by_key[KEYS.worktree_key]["ended"] is True
    assert [item["root"] for item in assessments.list_worktrees(store, include_paused=False)] == [
        str(tmp_path.resolve())
    ]
    assert {run["worktree_key"] for run in assessments.recent_runs(store)} == {KEYS.worktree_key, other.worktree_key}


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
    # The admission ended: nothing is watched, and the history is still there.
    assert assessments.list_worktrees(store, include_paused=False) == []
    [worktree] = assessments.list_worktrees(store)
    assert worktree["ended"] is True and worktree["paused"] is True
    assert len(assessments.recent_runs(store)) == 1


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
    monkeypatch.setattr(guard_config, "load_guard_config", lambda home: object())
    monkeypatch.setattr(worker, "run_next", lambda store, config, owner, user_only=False: False)

    worker.poll_once(store, owner="test")
    assert assessments.list_worktrees(store, include_paused=False) == []
    assert [item["ended"] for item in assessments.list_worktrees(store)] == [True]


def admitted_with_records(tmp_path: Path, monkeypatch) -> GuardStore:
    store = GuardStore(tmp_path / "home")
    snapshots(monkeypatch, worker, STAT)
    register(store, "claude-code", str(tmp_path))
    assert worker.admit_registered_workspaces(store, clock=lambda: T0) == 1
    [run] = assessments.recent_runs(store)
    claimed = assessments.claim_next(store, owner="test", now_ms=T0 + 60_000)
    assert claimed is not None and claimed.run_id == run["run_id"]
    finding = {"finding_id": "f" * 32, "source_kind": "supply_chain", "package_name": "minimist"}
    outcome = assessments.RunOutcome(state="completed", snapshot_digest=digest("snapshot"), findings=[finding])
    assert assessments.finish(store, claimed, outcome, now_ms=T0 + 61_000)
    seed_applied_fix_proposal(store)
    return store


def test_ending_an_admission_keeps_runs_findings_and_fix_proposals(tmp_path: Path, monkeypatch) -> None:
    store = admitted_with_records(tmp_path, monkeypatch)
    before = stored_records(store)
    assert before == {"workspace_assessment_runs": 1, "workspace_fix_proposals": 1, "workspace_assessment_state": 1}

    register(store, "claude-code", str(tmp_path), active=False)
    worker.admit_registered_workspaces(store, clock=lambda: T0 + 70_000)

    assert stored_records(store) == before
    [run] = assessments.recent_runs(store)
    assert run["finding_count"] == 1
    [latest] = assessments.latest_assessed_runs(store)
    assert [item["package_name"] for item in latest["findings"]] == ["minimist"]
    with store._connect() as connection:
        [(state, edits)] = connection.execute("select state, edits_json from workspace_fix_proposals").fetchall()
    assert (state, edits) == ("verified_fixed", "[]")


def test_an_ended_worktree_is_no_longer_scheduled(tmp_path: Path, monkeypatch) -> None:
    store = admitted_with_records(tmp_path, monkeypatch)
    register(store, "claude-code", str(tmp_path), active=False)
    worker.admit_registered_workspaces(store, clock=lambda: T0 + 70_000)
    snapshots(monkeypatch, worker, replace(STAT, snapshot_digest=digest("changed")))
    monkeypatch.setattr(worker, "cached_runtime_digest", pytest.fail)

    assert assessments.list_worktrees(store, include_paused=False) == []
    assert worker.observe(store, clock=lambda: T0 + 80_000) == 0
    assert worker.watched_roots(store, unavailable_digest=worker.UNAVAILABLE_STAT_DIGEST) == set()
    assert worker.queue_manual_run(store, KEYS, clock=lambda: T0 + 80_000) is None
    assert assessments.claim_next(store, owner="test", now_ms=T0 + 10_000_000) is None


def test_registering_the_same_root_again_resumes_an_ended_worktree(tmp_path: Path, monkeypatch) -> None:
    store = admitted_with_records(tmp_path, monkeypatch)
    register(store, "claude-code", str(tmp_path), active=False)
    worker.admit_registered_workspaces(store, clock=lambda: T0 + 70_000)
    assert [item["ended"] for item in assessments.list_worktrees(store)] == [True]

    register(store, "claude-code", str(tmp_path))
    assert worker.admit_registered_workspaces(store, clock=lambda: T0 + 80_000) == 1

    [worktree] = assessments.list_worktrees(store)
    assert worktree["ended"] is False and worktree["paused"] is False
    assert [item["root"] for item in assessments.list_worktrees(store, include_paused=False)] == [
        str(tmp_path.resolve())
    ]
    runs = assessments.recent_runs(store)
    assert [run["state"] for run in runs] == ["queued", "completed"]
    assert stored_records(store)["workspace_fix_proposals"] == 1
    # An ended admission is revived once; an admitted worktree is left alone again.
    assert worker.admit_registered_workspaces(store, clock=lambda: T0 + 90_000) == 0


def test_a_person_can_take_over_or_resume_an_ended_worktree(tmp_path: Path, monkeypatch) -> None:
    store = admitted_with_records(tmp_path, monkeypatch)
    register(store, "claude-code", str(tmp_path), active=False)
    worker.admit_registered_workspaces(store, clock=lambda: T0 + 70_000)

    assert assessments.set_paused(store, KEYS, paused=False)
    [worktree] = assessments.list_worktrees(store)
    assert worktree["ended"] is False and worktree["paused"] is False

    register(store, "claude-code", str(tmp_path))
    register(store, "claude-code", str(tmp_path), active=False)
    # Resumed by hand, it is no longer tied to the install, so removing it ends nothing.
    worker.admit_registered_workspaces(store, clock=lambda: T0 + 80_000)
    assert [item["ended"] for item in assessments.list_worktrees(store)] == [False]
