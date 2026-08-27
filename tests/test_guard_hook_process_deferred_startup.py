from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import cast
from unittest.mock import MagicMock

import pytest

from codex_plugin_scanner.guard.daemon.hook_process_runner import HookProcessRunner
from codex_plugin_scanner.guard.daemon.hook_process_worker import HookWorkerSlot


def test_initial_capacity_is_mandatory_before_daemon_readiness(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = HookProcessRunner(process_limit=1)
    wait_for_capacity = MagicMock(return_value=False)
    monkeypatch.setattr(runner, "wait_for_capacity", wait_for_capacity)

    with pytest.raises(RuntimeError, match="did not become ready"):
        runner.require_initial_capacity()

    wait_for_capacity.assert_called_once_with(minimum_workers=1, timeout_seconds=14.0)


def test_adaptive_deferred_start_returns_before_startup_floor_is_ready(monkeypatch, tmp_path: Path) -> None:
    runner = HookProcessRunner(guard_home=tmp_path)
    spawn_attempted = threading.Event()
    release_spawn = threading.Event()

    def delayed_start(_generation: int) -> None:
        spawn_attempted.set()
        assert release_spawn.wait(timeout=2.0)
        return None

    monkeypatch.setattr(runner, "_start_slot_interruptibly", delayed_start)

    started_at = time.monotonic()
    runner.start(defer_backfill=True)
    elapsed = time.monotonic() - started_at

    assert elapsed < 0.5
    assert runner.stats()["target"] >= 1
    assert spawn_attempted.wait(timeout=0.5)

    with runner._state_lock:
        startup_not_before = runner._backfill_not_before
    runner.enable_full_capacity(delay_seconds=0, active_deferral_seconds=0)
    with runner._state_lock:
        enabled_not_before = runner._backfill_not_before

    assert enabled_not_before >= startup_not_before
    assert enabled_not_before > time.monotonic()
    release_spawn.set()
    assert runner.close_contained()


def test_queued_work_releases_deferred_backfill() -> None:
    runner = HookProcessRunner()
    runner._backfill_not_before = time.monotonic() + 30  # pyright: ignore[reportPrivateUsage]
    runner._backfill_force_after = time.monotonic() + 35  # pyright: ignore[reportPrivateUsage]

    runner.notify_queued_work()

    assert runner._backfill_not_before == 0.0  # pyright: ignore[reportPrivateUsage]
    assert runner._backfill_force_after == 0.0  # pyright: ignore[reportPrivateUsage]
    assert runner._recovery_event.is_set()  # pyright: ignore[reportPrivateUsage]


def test_close_waits_for_inflight_spawn_thread_and_leaves_no_runner_threads(
    monkeypatch,
    tmp_path: Path,
) -> None:
    runner = HookProcessRunner(guard_home=tmp_path, process_limit=1)
    spawn_entered = threading.Event()
    release_spawn = threading.Event()

    def delayed_start(*, generation: int) -> HookWorkerSlot:
        spawn_entered.set()
        assert release_spawn.wait(timeout=2.0)
        return cast(HookWorkerSlot, object())

    monkeypatch.setattr(runner, "_start_slot", delayed_start)
    with runner._state_lock:
        runner._closed = False
        runner._started = True
        runner._generation = 1

    start_result: list[HookWorkerSlot | None] = []
    starter = threading.Thread(
        target=lambda: start_result.append(runner._start_slot_interruptibly(1)),
        name="test-hook-spawn-owner",
    )
    starter.start()
    assert spawn_entered.wait(timeout=1.0)

    close_result: list[bool] = []
    closer = threading.Thread(target=lambda: close_result.append(runner.close_contained()))
    closer.start()
    time.sleep(0.05)
    assert closer.is_alive()

    release_spawn.set()
    starter.join(timeout=2.0)
    closer.join(timeout=2.0)

    assert not starter.is_alive()
    assert not closer.is_alive()
    assert start_result == [None]
    assert close_result == [True]
    with runner._state_lock:
        assert not runner._spawn_threads
        assert runner._supervisor_thread is None
