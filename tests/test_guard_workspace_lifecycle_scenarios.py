"""Workspace lifecycle scenarios against the compiled runtime.

They extend the protection scenarios to the ways a worktree changes under
Guard: switching branches in place, being deleted, and holding only lockfiles
Guard cannot read. Each drives the real admission, observation, scheduling and
native snapshot path with a cached advisory bundle and no network.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import workspace_assessment_store as assessments
from codex_plugin_scanner.guard import workspace_assessment_worker as worker
from tests.test_guard_workspace_protection_scenarios import (
    AFFECTED,
    FIXED,
    Clock,
    _admit,
    _latest,
    _minimist,
    _queued,
    _run_all,
    _store,
    _write_lock,
    _write_project,
    native_binary,
    offline,
)

__all__ = ["native_binary", "offline"]

_GIT = ["git", "-c", "user.name=fixture", "-c", "user.email=fixture@example.test", "-c", "commit.gpgsign=false"]


def _git(root: Path, *args: str) -> None:
    subprocess.run([*_GIT, "-C", str(root), *args], check=True, capture_output=True)


@pytest.mark.skipif(shutil.which("git") is None, reason="needs git for branches")
def test_switching_branches_in_place_reassesses_the_same_worktree(
    tmp_path: Path, native_binary: None, offline: None
) -> None:
    clock = Clock()
    store = _store(tmp_path)
    root = tmp_path / "workspace"
    _write_project(root, FIXED)
    subprocess.run([*_GIT, "init", "-q", "-b", "main", str(root)], check=True)
    _git(root, "add", ".")
    _git(root, "commit", "-q", "-m", "fixed")
    _git(root, "checkout", "-q", "-b", "risky")
    _write_lock(root, AFFECTED)
    _git(root, "commit", "-q", "-am", "downgrade")
    _git(root, "checkout", "-q", "main")

    keys = _admit(store, root, clock)
    assert _run_all(store, clock) == 1
    on_main = _latest(store, keys)
    assert _minimist(on_main) == []
    assert worker.observe(store, clock=clock) == 0

    _git(root, "checkout", "-q", "risky")
    assert worker.observe(store, clock=clock) == 1
    [queued] = _queued(store, keys)
    assert queued["trigger_kind"] == "file_change"
    assert _run_all(store, clock) == 1
    on_risky = _latest(store, keys)
    assert on_risky["worktree_key"] == on_main["worktree_key"]
    assert on_risky["coverage"]["head_commit"] != on_main["coverage"]["head_commit"]
    [finding] = _minimist(on_risky)
    assert (finding["decision"], finding["package_version"]) == ("block", AFFECTED)

    _git(root, "checkout", "-q", "main")
    assert worker.observe(store, clock=clock) == 1
    assert _run_all(store, clock) == 1
    back = _latest(store, keys)
    assert back["coverage"]["head_commit"] == on_main["coverage"]["head_commit"]
    assert _minimist(back) == []
    assert [item["worktree_key"] for item in assessments.list_worktrees(store)] == [keys.worktree_key]


def test_a_deleted_worktree_fails_once_and_keeps_its_last_findings(
    tmp_path: Path, native_binary: None, offline: None
) -> None:
    clock = Clock()
    store = _store(tmp_path)
    root = tmp_path / "workspace"
    _write_project(root, AFFECTED)
    keys = _admit(store, root, clock)
    assert _run_all(store, clock) == 1
    assert len(_minimist(_latest(store, keys))) == 1
    assert worker.observe(store, clock=clock) == 0

    shutil.rmtree(root)
    assert worker.observe(store, clock=clock) == 1
    assert _run_all(store, clock) == 1
    newest = assessments.recent_runs(store, keys)[0]
    assert (newest["state"], newest["trigger_kind"], newest["error_code"]) == (
        "failed",
        "file_change",
        "workspace_snapshot_root_missing",
    )
    kept = _latest(store, keys)
    assert kept["state"] == "completed"
    assert len(_minimist(kept)) == 1
    for _ in range(3):
        clock.advance()
        assert worker.observe(store, clock=clock) == 0
        assert _run_all(store, clock) == 0


def test_only_unsupported_lockfiles_are_never_reported_clean(
    tmp_path: Path, native_binary: None, offline: None
) -> None:
    clock = Clock()
    store = _store(tmp_path)
    root = tmp_path / "workspace"
    root.mkdir()
    (root / "mix.exs").write_text("defmodule App.MixProject do\nend\n", encoding="utf-8")
    (root / "mix.lock").write_text('%{"plug": {:hex, :plug, "1.14.0"}}\n', encoding="utf-8")
    (root / "pubspec.yaml").write_text("name: app\ndependencies:\n  http: ^0.13.0\n", encoding="utf-8")
    (root / "pubspec.lock").write_text('packages:\n  http:\n    version: "0.13.0"\n', encoding="utf-8")
    keys = _admit(store, root, clock)
    assert _run_all(store, clock) == 1
    run = _latest(store, keys)
    assert run["state"] == "partial"
    assert run["findings"] == []
    coverage = run["coverage"]
    assert coverage["status"] == "partial"
    assert coverage["reasons"] == ["snapshot_unsupported_dependency_input"]
    assert coverage["detectors"]["supply_chain"] == "no_inputs"


def test_dependency_files_below_audit_discovery_are_never_reported_clean(
    tmp_path: Path, native_binary: None, offline: None
) -> None:
    clock = Clock()
    store = _store(tmp_path)
    root = tmp_path / "workspace"
    package = root / "services" / "api" / "web" / "client"
    package.mkdir(parents=True)
    (package / "package.json").write_text('{"dependencies": {"lodash": "4.17.20"}}\n', encoding="utf-8")
    keys = _admit(store, root, clock)
    assert _run_all(store, clock) == 1
    run = _latest(store, keys)
    assert run["state"] == "partial"
    assert run["findings"] == []
    coverage = run["coverage"]
    assert coverage["reasons"] == ["snapshot_undiscovered_dependency_input"]
    assert coverage["detectors"]["supply_chain"] == "no_inputs"
