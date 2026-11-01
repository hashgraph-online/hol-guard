from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.repair_engine import build_report, repair_onefile_leaks, run_repair
from codex_plugin_scanner.guard.resident_state_prune import (
    OWNER_LOCK_NAME,
    probe_owner_lock,
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


def test_prune_reports_none_for_a_malformed_runtime_answer(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard.mdm import runtime_request

    answers: list[dict[str, object] | None] = [
        {"outcome": "ok", "stale_dirs": -1, "dead_sockets": 0, "removed_dirs": [], "removed_sockets": []},
        None,
    ]
    requests: list[object] = []

    def fake_answer(_feature: str, _command: str, request: object, **_options: object) -> dict[str, object] | None:
        requests.append(request)
        return answers.pop(0)

    monkeypatch.setattr(runtime_request, "runtime_answer", fake_answer)
    assert prune_native_runtime(tmp_path, include_system_sockets=False) is None
    assert requests[0] == {
        "schema": "resident-state-prune.v1",
        "guard_home": str(tmp_path),
        "dry_run": False,
        "include_system_sockets": False,
    }
    context = _context(tmp_path)
    store = GuardStore(context.guard_home)
    report = run_repair(guard_home=context.guard_home, context=context, store=store, include_daemon=False)
    native = next(item for item in report["steps"] if item["step"] == "native_runtime")  # type: ignore[union-attr]
    assert native["status"] == "skipped"


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


def test_repair_onefile_step_uses_injected_root_and_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from datetime import datetime, timezone

    from codex_plugin_scanner.guard import onefile_extraction
    from codex_plugin_scanner.guard.onefile_extraction import ExtractionReclaimResult

    moment = datetime.fromtimestamp(NOW, tz=timezone.utc)
    calls: list[dict[str, object]] = []
    results: list[ExtractionReclaimResult] = []

    def fake_reclaim(**kwargs: object) -> ExtractionReclaimResult:
        calls.append(kwargs)
        return results.pop(0)

    monkeypatch.setattr(onefile_extraction, "reclaim_orphaned_extraction_dirs", fake_reclaim)
    results.append(ExtractionReclaimResult(unmarked_count=1, unmarked_scan="unavailable"))
    unavailable = repair_onefile_leaks(dry_run=False, temp_root=tmp_path, now=moment)
    assert unavailable["status"] == "skipped"
    assert calls[0]["temp_root"] == tmp_path and calls[0]["now"] == moment
    assert calls[0]["scan_open_paths"] is True
    results.append(ExtractionReclaimResult(unmarked_count=1, unmarked_scan="ok"))
    assert repair_onefile_leaks(dry_run=False, temp_root=tmp_path, now=moment)["status"] == "ok"
    results.append(ExtractionReclaimResult(reclaimed_count=1, unmarked_scan="ok"))
    planned = repair_onefile_leaks(dry_run=True, temp_root=tmp_path, now=moment)
    assert planned["status"] == "planned" and planned["unmarked_remaining"] == 0
    assert calls[2]["dry_run"] is True
    results.append(ExtractionReclaimResult(reclaimed_count=1, unmarked_scan="ok"))
    assert repair_onefile_leaks(dry_run=False, temp_root=tmp_path, now=moment)["status"] == "changed"

    def unavailable_runtime(**_kwargs: object) -> ExtractionReclaimResult:
        raise onefile_extraction.ExtractionReclaimUnavailableError("onefile_extraction_reclaim_unavailable")

    monkeypatch.setattr(onefile_extraction, "reclaim_orphaned_extraction_dirs", unavailable_runtime)
    assert repair_onefile_leaks(dry_run=False, temp_root=tmp_path, now=moment)["status"] == "error"


def test_report_status_rollup() -> None:
    def step(status: str) -> dict[str, object]:
        return {"step": "daemon", "title": "Guard daemon", "status": status, "summary": "s"}

    assert build_report([step("ok")], dry_run=False)["status"] == "healthy"
    assert build_report([step("ok"), step("changed")], dry_run=False)["status"] == "repaired"
    assert build_report([step("planned")], dry_run=True)["status"] == "needs_repair"
    assert build_report([step("changed"), step("error")], dry_run=False)["status"] == "partial"
