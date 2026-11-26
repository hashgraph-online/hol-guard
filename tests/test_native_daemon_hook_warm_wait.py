"""The test daemon launcher waits for the daemon's start-time hook warm-up."""

from __future__ import annotations

import json
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from ci.native_daemon_harness import HookWorkerWarmTimeoutError, NativeGuardDaemon


class _Process:
    def __init__(self, returncode: int | None = None, pid: int = 4242) -> None:
        self.returncode = returncode
        self.pid = pid

    def poll(self) -> int | None:
        return self.returncode


def _daemon(guard_home: Path, pid: int, process: _Process | None) -> NativeGuardDaemon:
    daemon = object.__new__(NativeGuardDaemon)
    daemon.store = SimpleNamespace(guard_home=guard_home)
    daemon.pid = pid
    daemon._process = process
    return daemon


def _record(guard_home: Path, pid: int, event: str, reason: str | None = None) -> None:
    directory = guard_home / "daemon-lifecycle"
    directory.mkdir(parents=True, exist_ok=True)
    record: dict[str, object] = {"event": event, "pid": pid, "version": 1}
    if reason is not None:
        record["reason"] = reason
    stamp = time.time_ns()
    (directory / f"{stamp:020d}-{pid:010d}-{stamp:032x}.json").write_text(json.dumps(record), encoding="utf-8")


def test_returns_true_once_the_warm_up_built_the_worker(tmp_path: Path) -> None:
    _record(tmp_path, 4242, "hook_worker_warming")
    _record(tmp_path, 4242, "hook_worker_warmed", "ok")

    assert _daemon(tmp_path, 4242, _Process()).wait_for_hook_worker(timeout_seconds=1.0) is True


def test_returns_false_when_the_warm_up_could_not_build_the_worker(tmp_path: Path) -> None:
    _record(tmp_path, 4242, "hook_worker_warmed", "unavailable")

    assert _daemon(tmp_path, 4242, _Process()).wait_for_hook_worker(timeout_seconds=1.0) is False


def test_ignores_another_daemons_record(tmp_path: Path) -> None:
    _record(tmp_path, 1111, "hook_worker_warmed", "ok")
    started = time.monotonic()

    with pytest.raises(HookWorkerWarmTimeoutError):
        _daemon(tmp_path, 4242, _Process()).wait_for_hook_worker(timeout_seconds=0.3)
    assert time.monotonic() - started >= 0.3


def test_finds_the_record_under_the_daemon_process_id_when_it_announced_its_launcher(tmp_path: Path) -> None:
    # On Windows the daemon announces its launcher's pid, but its lifecycle
    # records carry its own.
    _record(tmp_path, 5151, "hook_worker_warmed", "ok")
    started = time.monotonic()

    assert _daemon(tmp_path, 4242, _Process(pid=5151)).wait_for_hook_worker(timeout_seconds=30.0) is True
    assert time.monotonic() - started < 5.0


def test_a_warm_up_that_never_ends_is_an_error_not_an_unavailable_worker(tmp_path: Path) -> None:
    _record(tmp_path, 4242, "hook_worker_warming")

    with pytest.raises(HookWorkerWarmTimeoutError):
        _daemon(tmp_path, 4242, _Process()).wait_for_hook_worker(timeout_seconds=0.3)


def test_stops_waiting_when_the_daemon_exited(tmp_path: Path) -> None:
    started = time.monotonic()

    assert _daemon(tmp_path, 4242, _Process(returncode=1)).wait_for_hook_worker(timeout_seconds=30.0) is False
    assert time.monotonic() - started < 5.0
