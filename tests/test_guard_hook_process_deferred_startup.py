from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import cast
from unittest.mock import MagicMock

import pytest

from codex_plugin_scanner.guard.daemon import hook_process_runner as hook_runner_module
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

    assert enabled_not_before == startup_not_before
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


def test_default_full_capacity_preserves_quiet_startup_delay(monkeypatch: pytest.MonkeyPatch) -> None:
    runner = HookProcessRunner()
    with runner._state_lock:  # pyright: ignore[reportPrivateUsage]
        runner._started = True  # pyright: ignore[reportPrivateUsage]
        runner._backfill_not_before = 130.0  # pyright: ignore[reportPrivateUsage]
        runner._backfill_force_after = 135.0  # pyright: ignore[reportPrivateUsage]
    monkeypatch.setattr(hook_runner_module.time, "monotonic", lambda: 100.0)

    runner.enable_full_capacity()

    assert runner._backfill_not_before == 130.0  # pyright: ignore[reportPrivateUsage]
    assert runner._backfill_force_after == 135.0  # pyright: ignore[reportPrivateUsage]


def test_zero_delay_full_capacity_bounds_active_review_deferral(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = HookProcessRunner()
    with runner._state_lock:  # pyright: ignore[reportPrivateUsage]
        runner._started = True  # pyright: ignore[reportPrivateUsage]
        runner._generation = 1  # pyright: ignore[reportPrivateUsage]
        runner._active_reviews[1] = 1  # pyright: ignore[reportPrivateUsage]
        runner._backfill_not_before = 0.0  # pyright: ignore[reportPrivateUsage]
        runner._backfill_force_after = 0.0  # pyright: ignore[reportPrivateUsage]
    monkeypatch.setattr(hook_runner_module.time, "monotonic", lambda: 100.0)

    runner.enable_full_capacity(delay_seconds=0, active_deferral_seconds=0.2)

    assert runner._backfill_not_before == 0.0  # pyright: ignore[reportPrivateUsage]
    assert runner._backfill_force_after == 100.2  # pyright: ignore[reportPrivateUsage]


def test_zero_delay_full_capacity_preserves_existing_backfill_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = HookProcessRunner()
    with runner._state_lock:  # pyright: ignore[reportPrivateUsage]
        runner._started = True  # pyright: ignore[reportPrivateUsage]
        runner._backfill_not_before = 130.0  # pyright: ignore[reportPrivateUsage]
        runner._backfill_force_after = 135.0  # pyright: ignore[reportPrivateUsage]
    monkeypatch.setattr(hook_runner_module.time, "monotonic", lambda: 100.0)

    runner.enable_full_capacity(delay_seconds=0, active_deferral_seconds=0.2)

    assert runner._backfill_not_before == 130.0  # pyright: ignore[reportPrivateUsage]
    assert runner._backfill_force_after == 135.0  # pyright: ignore[reportPrivateUsage]


def test_full_capacity_batches_slow_worker_spawns_within_startup_deadline(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    runner = HookProcessRunner(guard_home=tmp_path, process_limit=4)
    first_spawn_entered = threading.Event()
    all_spawns_entered = threading.Event()
    release_spawns = threading.Event()
    state_lock = threading.Lock()
    active_spawns = 0
    maximum_active_spawns = 0
    next_process_id = 9000

    def slow_start(*, generation: int) -> HookWorkerSlot:
        nonlocal active_spawns, maximum_active_spawns, next_process_id
        with state_lock:
            active_spawns += 1
            maximum_active_spawns = max(maximum_active_spawns, active_spawns)
            if next_process_id == 9000:
                first_spawn_entered.set()
            elif active_spawns == 3:
                all_spawns_entered.set()
        try:
            assert release_spawns.wait(timeout=2.0)
            with state_lock:
                process_id = next_process_id
                next_process_id += 1
            process = MagicMock()
            process.pid = process_id
            process.is_alive.return_value = False
            slot = HookWorkerSlot(process=process, connection=MagicMock())
            with runner._state_lock:  # pyright: ignore[reportPrivateUsage]
                if not runner._closed and generation == runner._generation:  # pyright: ignore[reportPrivateUsage]
                    runner._all_slots[process_id] = slot  # pyright: ignore[reportPrivateUsage]
            return slot
        finally:
            with state_lock:
                active_spawns -= 1

    monkeypatch.setattr(runner, "_start_slot", slow_start)
    monkeypatch.setattr(hook_runner_module, "hook_worker_became_ready", lambda *_args: True)
    start_errors: list[BaseException] = []

    def start_runner() -> None:
        try:
            runner.start(defer_backfill=True)
        except BaseException as error:
            start_errors.append(error)

    starter = threading.Thread(target=start_runner, name="test-slow-worker-start")
    starter.start()
    try:
        assert first_spawn_entered.wait(timeout=1.0)
        release_spawns.set()
        starter.join(timeout=3.0)
        assert not starter.is_alive()
        assert not start_errors
        runner.enable_full_capacity(delay_seconds=0)
        assert all_spawns_entered.wait(timeout=1.0), "capacity startup remained serialized"
        release_spawns.set()
        assert runner.wait_for_capacity(minimum_workers=4, timeout_seconds=3.0)
        assert maximum_active_spawns == 3
        assert runner.stats()["ready"] == 4
    finally:
        release_spawns.set()
        if starter.is_alive():
            starter.join(timeout=3.0)
        assert runner.close_contained()


def test_close_contains_parallel_worker_spawns_without_leaking_threads(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    runner = HookProcessRunner(guard_home=tmp_path, process_limit=4)
    all_spawns_entered = threading.Event()
    release_spawns = threading.Event()
    state_lock = threading.Lock()
    entered_spawns = 0
    fake_processes: list[MagicMock] = []

    def blocking_start(*, generation: int) -> HookWorkerSlot:
        nonlocal entered_spawns
        with state_lock:
            entered_spawns += 1
            if entered_spawns == 3:
                all_spawns_entered.set()
        assert release_spawns.wait(timeout=2.0)
        process = MagicMock()
        process.pid = 9100 + len(fake_processes)
        process.is_alive.return_value = True
        fake_processes.append(process)
        with runner._state_lock:  # pyright: ignore[reportPrivateUsage]
            if runner._closed or generation != runner._generation:  # pyright: ignore[reportPrivateUsage]
                process.is_alive.return_value = False
                process.kill()
            else:
                runner._all_slots[process.pid] = HookWorkerSlot(  # pyright: ignore[reportPrivateUsage]
                    process=process,
                    connection=MagicMock(),
                )
        return HookWorkerSlot(process=process, connection=MagicMock())

    monkeypatch.setattr(runner, "_start_slot", blocking_start)
    with runner._state_lock:  # pyright: ignore[reportPrivateUsage]
        runner._started = True  # pyright: ignore[reportPrivateUsage]
        runner._generation = 1  # pyright: ignore[reportPrivateUsage]

    batch_result: list[list[HookWorkerSlot]] = []
    batch = threading.Thread(
        target=lambda: batch_result.append(runner._start_slots_interruptibly(1, 3)),  # pyright: ignore[reportPrivateUsage]
        name="test-parallel-worker-spawn",
    )
    batch.start()
    close_result: list[bool] = []
    closer = threading.Thread(target=lambda: close_result.append(runner.close_contained()), name="test-close-spawns")
    try:
        assert all_spawns_entered.wait(timeout=1.0), "parallel spawn batch did not launch all workers"
        closer.start()
        time.sleep(0.05)
        assert closer.is_alive()
        release_spawns.set()
        batch.join(timeout=3.0)
        closer.join(timeout=3.0)
    finally:
        release_spawns.set()
        batch.join(timeout=3.0)
        if closer.ident is not None:
            closer.join(timeout=3.0)

    assert not batch.is_alive()
    assert not closer.is_alive()
    assert batch_result == [[]]
    assert close_result == [True]
    assert all(process.kill.called for process in fake_processes)
    with runner._state_lock:  # pyright: ignore[reportPrivateUsage]
        assert not runner._spawn_threads  # pyright: ignore[reportPrivateUsage]
        assert not runner._all_slots  # pyright: ignore[reportPrivateUsage]


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


def test_close_waits_for_process_bootstrap_before_containment(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    runner = HookProcessRunner(guard_home=tmp_path, process_limit=1)
    spawn_entered = threading.Event()
    release_spawn = threading.Event()

    def delayed_spawn(_guard_home: Path | None) -> HookWorkerSlot:
        spawn_entered.set()
        assert release_spawn.wait(timeout=2.0)
        raise EOFError("bootstrap interrupted")

    monkeypatch.setattr(hook_runner_module, "spawn_hook_worker", delayed_spawn)
    with runner._state_lock:
        runner._closed = False
        runner._started = True
        runner._generation = 1

    spawn_result: list[HookWorkerSlot | None] = []
    starter = threading.Thread(
        target=lambda: spawn_result.append(runner._start_slot_interruptibly(1)),
        name="test-hook-bootstrap-owner",
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
    assert spawn_result == [None]
    assert close_result == [True]
    with runner._state_lock:
        assert not runner._spawn_threads
