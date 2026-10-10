from __future__ import annotations

import json
import os
import socket
import tempfile
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.repair_engine import build_report, repair_onefile_leaks, run_repair
from codex_plugin_scanner.guard.resident_state_prune import (
    OWNER_LOCK_NAME,
    probe_owner_lock,
    probe_socket,
    prune_native_runtime,
)
from codex_plugin_scanner.guard.store import GuardStore

NOW = 1_800_000_000.0
OLD = NOW - 3 * 3600


def _age(path: Path, mtime: float) -> None:
    for item in [*path.rglob("*"), path]:
        os.utime(item, (mtime, mtime), follow_symlinks=False)


def _resident(root: Path, name: str, *, pids: tuple[int, int] = (111, 222), mtime: float = OLD) -> Path:
    directory = root / "native-runtime" / f"resident-v3-{name}"
    directory.mkdir(parents=True)
    (directory / "generation-0000000000000001.json").write_text(
        json.dumps({"process_id": pids[0], "owner_process_id": pids[1]})
    )
    (directory / OWNER_LOCK_NAME).write_text("")
    _age(directory, mtime)
    return directory


def _prune(home: Path, **overrides: object):
    options: dict[str, object] = {
        "now": NOW,
        "pid_alive": lambda _pid: False,
        "lock_probe": lambda _path: True,
        "socket_probe": lambda _path: "dead",
        "socket_roots": (),
    }
    options.update(overrides)
    return prune_native_runtime(home, **options)  # type: ignore[arg-type]


def test_stale_dir_with_dead_owners_is_removed(tmp_path: Path) -> None:
    stale = _resident(tmp_path, "a" * 16)
    report = _prune(tmp_path)
    assert not stale.exists()
    assert report.removed_dirs == [str(stale)]
    assert not list((tmp_path / "native-runtime").glob(".pruned-*"))


def test_dry_run_reports_without_deleting(tmp_path: Path) -> None:
    stale = _resident(tmp_path, "a" * 16)
    report = _prune(tmp_path, dry_run=True)
    assert stale.exists()
    assert report.removed_dirs == [str(stale)]


@pytest.mark.parametrize(
    ("label", "overrides", "mutate"),
    [
        ("live pid", {"pid_alive": lambda pid: pid == 222}, None),
        ("held lock", {"lock_probe": lambda _path: False}, None),
        ("unknowable lock", {"lock_probe": lambda _path: None}, None),
        ("recent", {}, lambda directory: _age(directory, NOW - 60)),
        ("unparseable state", {}, lambda directory: (directory / "generation-0000000000000001.json").write_text("{")),
    ],
)
def test_dirs_without_full_proof_are_kept(tmp_path: Path, label: str, overrides: dict, mutate) -> None:
    directory = _resident(tmp_path, "b" * 16)
    if mutate is not None:
        mutate(directory)
        if label == "unparseable state":
            _age(directory, OLD)
    report = _prune(tmp_path, **overrides)
    assert directory.exists(), label
    assert report.removed_dirs == []


def test_symlinked_resident_dir_is_never_followed(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep.txt").write_text("x")
    link = tmp_path / "native-runtime" / ("resident-v3-" + "c" * 16)
    link.parent.mkdir(parents=True)
    link.symlink_to(outside, target_is_directory=True)
    _prune(tmp_path)
    assert (outside / "keep.txt").exists()
    assert link.is_symlink()


def _bound_socket(path: Path, *, listening: bool) -> socket.socket:
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(path))
    if listening:
        server.listen(1)
    return server


def test_probe_socket_distinguishes_dead_from_live() -> None:
    root = Path(tempfile.mkdtemp(prefix="hgrp", dir="/tmp"))
    try:
        dead_path, live_path = root / "d.sock", root / "l.sock"
        dead = _bound_socket(dead_path, listening=False)
        dead.close()  # file stays, nothing listens
        live = _bound_socket(live_path, listening=True)
        try:
            assert probe_socket(dead_path) == "dead"
            assert probe_socket(live_path) == "live"
            assert probe_socket(root / "missing.sock") == "gone"
        finally:
            live.close()
    finally:
        for item in root.iterdir():
            item.unlink()
        root.rmdir()


def test_only_dead_old_resident_sockets_are_removed(tmp_path: Path) -> None:
    root = Path(tempfile.mkdtemp(prefix="hgrp", dir="/tmp"))
    try:
        names = ("hook-v2-1.sock", "h3-aaaa-0000000000000001.sock", "other.sock")
        for name in names:
            _bound_socket(root / name, listening=False).close()
        (root / "hook-v2-notasocket.sock").write_text("x")
        _age(root, OLD)
        report = _prune(tmp_path, socket_roots=(root,), socket_probe=lambda _p: "dead")
        assert not (root / names[0]).exists() and not (root / names[1]).exists()
        assert (root / "other.sock").exists()
        assert (root / "hook-v2-notasocket.sock").exists()
        assert len(report.removed_sockets) == 2
        # a socket that still answers is never removed
        _bound_socket(root / "hook-v2-live.sock", listening=False).close()
        _age(root, OLD)
        kept = _prune(tmp_path, socket_roots=(root,), socket_probe=lambda _p: "live")
        assert (root / "hook-v2-live.sock").exists() and kept.removed_sockets == []
    finally:
        for item in root.iterdir():
            item.unlink()
        root.rmdir()


def test_probe_owner_lock_sees_a_held_flock(tmp_path: Path) -> None:
    import fcntl

    directory = tmp_path / "d"
    directory.mkdir()
    assert probe_owner_lock(directory) is True  # no lock file: nothing ever owned it
    lock = directory / OWNER_LOCK_NAME
    lock.write_text("")
    descriptor = os.open(lock, os.O_RDWR)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        assert probe_owner_lock(directory) is False
    finally:
        os.close(descriptor)
    assert probe_owner_lock(directory) is True


def test_entry_budget_bounds_work(tmp_path: Path) -> None:
    for index in range(5):
        _resident(tmp_path, f"{index:016x}")
    report = _prune(tmp_path, max_entries=2)
    assert report.budget_exhausted
    assert len(report.removed_dirs) == 2


def test_missing_state_dir_is_a_clean_no_op(tmp_path: Path) -> None:
    report = _prune(tmp_path)
    assert report.status == "ok" and report.removed_dirs == [] and report.removed_sockets == []


def _context(tmp_path: Path) -> HarnessContext:
    home = tmp_path / "home"
    home.mkdir()
    return HarnessContext(home_dir=home, workspace_dir=None, guard_home=tmp_path / "guard-home")


def test_repair_dry_run_on_custom_home_is_scoped_and_changes_nothing(tmp_path: Path) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    stale = _resident(context.guard_home, "d" * 16)
    report = run_repair(guard_home=context.guard_home, context=context, store=store, dry_run=True)
    steps = {item["step"]: item for item in report["steps"]}  # type: ignore[union-attr]
    assert stale.exists()
    assert steps["daemon"]["status"] == "ok"
    assert steps["onefile_leaks"]["status"] == "skipped"
    assert steps["hooks"]["status"] == "ok"
    assert report["dry_run"] is True and report["schema"] == "guard.repair.v1"


def test_repair_prunes_stale_state_for_custom_home(tmp_path: Path) -> None:
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    stale = _resident(context.guard_home, "e" * 16, pids=(2**22 + 7, 2**22 + 9), mtime=time.time() - 3 * 3600)
    report = run_repair(guard_home=context.guard_home, context=context, store=store, include_daemon=False)
    assert not stale.exists()
    native = next(item for item in report["steps"] if item["step"] == "native_runtime")  # type: ignore[union-attr]
    assert native["status"] == "changed"
    assert report["status"] == "repaired"
    # Idempotent: a second run has nothing left to do.
    again = run_repair(guard_home=context.guard_home, context=context, store=store, include_daemon=False)
    assert again["status"] == "healthy"


def test_harness_scoped_repair_only_touches_that_harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard import repair_engine

    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    stale = _resident(context.guard_home, "f" * 16, pids=(2**22 + 11, 2**22 + 13), mtime=time.time() - 3 * 3600)
    broken = [{"harness": "codex", "status": "broken"}, {"harness": "cursor", "status": "broken"}]
    monkeypatch.setattr(repair_engine, "broken_hook_harnesses", lambda _context, _store: broken)
    report = run_repair(guard_home=context.guard_home, context=context, store=store, dry_run=True, harness="cursor")
    steps = report["steps"]
    assert isinstance(steps, list)
    assert [item["step"] for item in steps] == ["hooks"]
    assert steps[0]["broken"] == [{"harness": "cursor", "status": "broken"}]
    assert stale.exists()


def test_repair_onefile_step_uses_injected_root_and_fails_closed(tmp_path: Path) -> None:
    from datetime import datetime, timezone

    leaked = tmp_path / "_MEIabc123"
    leaked.mkdir()
    (leaked / "codex_plugin_scanner" / "guard" / "daemon" / "static").mkdir(parents=True)
    (leaked / "codex_plugin_scanner" / "guard" / "daemon" / "static" / "index.html").write_text("x")
    moment = datetime.fromtimestamp(NOW, tz=timezone.utc)
    _age(leaked, OLD - 3600)
    unavailable = repair_onefile_leaks(dry_run=False, temp_root=tmp_path, now=moment, scanner=lambda _root: None)
    assert unavailable["status"] == "skipped" and leaked.exists()
    in_use = repair_onefile_leaks(
        dry_run=False, temp_root=tmp_path, now=moment, scanner=lambda _root: frozenset({leaked.name})
    )
    assert in_use["status"] == "ok" and leaked.exists()
    planned = repair_onefile_leaks(dry_run=True, temp_root=tmp_path, now=moment, scanner=lambda _root: frozenset())
    assert planned["status"] == "planned" and leaked.exists()
    assert planned["unmarked_remaining"] == 0
    done = repair_onefile_leaks(dry_run=False, temp_root=tmp_path, now=moment, scanner=lambda _root: frozenset())
    assert done["status"] == "changed" and not leaked.exists()


def test_report_status_rollup() -> None:
    def step(status: str) -> dict[str, object]:
        return {"step": "daemon", "title": "Guard daemon", "status": status, "summary": "s"}

    assert build_report([step("ok")], dry_run=False)["status"] == "healthy"
    assert build_report([step("ok"), step("changed")], dry_run=False)["status"] == "repaired"
    assert build_report([step("planned")], dry_run=True)["status"] == "needs_repair"
    assert build_report([step("changed"), step("error")], dry_run=False)["status"] == "partial"
