from __future__ import annotations

import multiprocessing
import os
import signal
import subprocess
import sys
import threading
import time
from contextlib import suppress
from pathlib import Path
from typing import final

import pytest

from codex_plugin_scanner.guard.adapters.pi_extension_source import GUARD_DAEMON_HOOK_TIMEOUT_MS
from codex_plugin_scanner.guard.daemon import hook_process_runner as hook_runner_module
from codex_plugin_scanner.guard.daemon import hook_process_worker as hook_worker_module
from codex_plugin_scanner.guard.daemon.hook_process_runner import HookProcessRunner
from codex_plugin_scanner.guard.daemon.hook_process_worker import (
    HookProcessReview,
    HookWorkerSlot,
    retire_worker_slot,
)


def _spawn_term_ignoring_descendant(ready_path: str, escaped_path: str) -> None:
    os.setsid()
    child_code = (
        "import signal,time;"
        "from pathlib import Path;"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN);"
        f"Path({ready_path!r}).touch();"
        "time.sleep(1);"
        f"Path({escaped_path!r}).touch()"
    )
    _ = subprocess.Popen(
        [sys.executable, "-c", child_code],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    deadline = time.monotonic() + 2
    while not Path(ready_path).is_file() and time.monotonic() < deadline:
        time.sleep(0.01)
    time.sleep(10)


@final
class _SlowConnection:
    def __init__(
        self,
        *,
        entered: list[int],
        entered_lock: threading.Lock,
        all_entered: threading.Event,
    ) -> None:
        self._entered = entered
        self._entered_lock = entered_lock
        self._all_entered = all_entered

    def send(self, obj: object) -> None:
        del obj

    def recv(self) -> object:
        raise AssertionError("timed-out worker must not be read")

    def poll(self, timeout: float = 0.0) -> bool:
        with self._entered_lock:
            self._entered[0] += 1
            if self._entered[0] == 4:
                self._all_entered.set()
        time.sleep(timeout)
        return False

    def close(self) -> None:
        return


@final
class _LateResultConnection:
    def send(self, obj: object) -> None:
        del obj

    def poll(self, timeout: float = 0.0) -> bool:
        del timeout
        return True

    def recv(self) -> object:
        time.sleep(0.03)
        return "result", {"payload": {"decision": "allow"}}

    def close(self) -> None:
        return


class _FakeProcess:
    def __init__(self, pid: int) -> None:
        self.pid = pid
        self._alive = True

    def is_alive(self) -> bool:
        return self._alive

    def join(self, timeout: float | None = None) -> None:
        if self._alive and timeout is not None:
            time.sleep(timeout)

    def terminate(self) -> None:
        return

    def kill(self) -> None:
        self._alive = False


def _contain_fake_process(process: _FakeProcess, signal_number: int) -> bool:
    if signal_number == getattr(signal, "SIGKILL", 9):
        process.kill()
    else:
        process.terminate()
    return True


@pytest.mark.skipif(os.name == "nt", reason="POSIX process-group containment")
def test_retirement_kills_descendant_that_ignores_term(tmp_path) -> None:
    ready_path = tmp_path / "descendant-ready"
    escaped_path = tmp_path / "descendant-escaped"
    process = multiprocessing.get_context("spawn").Process(
        target=_spawn_term_ignoring_descendant,
        args=(str(ready_path), str(escaped_path)),
    )
    process.start()
    process_group_id = process.pid
    assert process_group_id is not None
    deadline = time.monotonic() + 3
    while not ready_path.is_file() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert ready_path.is_file()
    slot = HookWorkerSlot(
        process=process,
        connection=_SlowConnection(
            entered=[0],
            entered_lock=threading.Lock(),
            all_entered=threading.Event(),
        ),
        isolation_ready=True,
    )

    try:
        assert retire_worker_slot(slot)
        time.sleep(1.1)
        assert not escaped_path.exists()
    finally:
        with suppress(OSError, ProcessLookupError):
            os.killpg(process_group_id, getattr(signal, "SIGKILL", 9))
        process.join(timeout=1)


def test_windows_taskkill_failure_requires_job_containment_proof(
    tmp_path,
    monkeypatch,
) -> None:
    del tmp_path

    @final
    class _WindowsProcess(_FakeProcess):
        def join(self, timeout: float | None = None) -> None:
            del timeout

    monkeypatch.setattr(hook_worker_module.os, "name", "nt")
    monkeypatch.setattr(
        hook_worker_module,
        "windows_system_executable_path",
        lambda _filename: r"C:\Windows\System32\taskkill.exe",
    )
    monkeypatch.setattr(
        hook_worker_module.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 1),
    )
    unproven_process = _WindowsProcess(1)
    unproven = HookWorkerSlot(
        process=unproven_process,
        connection=_SlowConnection(
            entered=[0],
            entered_lock=threading.Lock(),
            all_entered=threading.Event(),
        ),
        isolation_ready=True,
    )
    contained_process = _WindowsProcess(2)
    job_contained = HookWorkerSlot(
        process=contained_process,
        connection=_SlowConnection(
            entered=[0],
            entered_lock=threading.Lock(),
            all_entered=threading.Event(),
        ),
        windows_job_contained=True,
        isolation_ready=True,
    )

    assert not retire_worker_slot(unproven)
    assert retire_worker_slot(job_contained)


def test_slow_pi_reviews_release_every_slot_within_client_daemon_budget(
    tmp_path,
    monkeypatch,
) -> None:
    worker_timeout = 0.08
    runner = HookProcessRunner(
        guard_home=tmp_path,
        process_limit=4,
        timeout_seconds=worker_timeout,
    )
    runner._started = True  # pyright: ignore[reportPrivateUsage]
    entered = [0]
    entered_lock = threading.Lock()
    all_entered = threading.Event()
    results: list[HookProcessReview] = []

    monkeypatch.setattr(hook_worker_module, "terminate_worker_tree", _contain_fake_process)

    for index in range(4):
        process = _FakeProcess(index + 1)
        slot = HookWorkerSlot(
            process=process,
            connection=_SlowConnection(
                entered=entered,
                entered_lock=entered_lock,
                all_entered=all_entered,
            ),
            pre_isolation_contained=True,
        )
        runner._all_slots[process.pid] = slot  # pyright: ignore[reportPrivateUsage]
        runner._slots.put_nowait(slot)  # pyright: ignore[reportPrivateUsage]

    def review() -> None:
        results.append(
            runner.review(
                payload={"hook_event_name": "PreToolUse"},
                harness="pi",
                home_dir=tmp_path,
                guard_home=tmp_path,
                workspace=tmp_path,
                hook_env={},
            )
        )

    threads = [threading.Thread(target=review) for _ in range(4)]
    started_at = time.monotonic()
    for thread in threads:
        thread.start()
    assert all_entered.wait(timeout=0.5)
    overloaded = runner.review(
        payload={"hook_event_name": "PreToolUse"},
        harness="pi",
        home_dir=tmp_path,
        guard_home=tmp_path,
        workspace=tmp_path,
        hook_env={},
    )
    for thread in threads:
        thread.join(timeout=0.5)
    elapsed = time.monotonic() - started_at

    assert overloaded.reason_code == "daemon_hook_process_not_ready"
    assert len(results) == 4
    assert {result.reason_code for result in results} == {"daemon_hook_process_timeout"}
    assert elapsed < 0.3
    retire_deadline = time.monotonic() + 0.8
    while runner.stats()["workers"] and time.monotonic() < retire_deadline:
        time.sleep(0.01)
    assert runner.stats()["workers"] == 0
    assert runner._recovery_event.is_set()  # pyright: ignore[reportPrivateUsage]
    assert worker_timeout < GUARD_DAEMON_HOOK_TIMEOUT_MS / 1000


def test_poll_phase_caller_deadline_retires_worker_without_timeout_metric(
    tmp_path,
    monkeypatch,
) -> None:
    runner = HookProcessRunner(
        guard_home=tmp_path,
        process_limit=1,
        timeout_seconds=1,
    )
    runner._started = True  # pyright: ignore[reportPrivateUsage]
    process = _FakeProcess(1)
    slot = HookWorkerSlot(
        process=process,
        connection=_SlowConnection(
            entered=[0],
            entered_lock=threading.Lock(),
            all_entered=threading.Event(),
        ),
        pre_isolation_contained=True,
    )
    runner._all_slots[process.pid] = slot  # pyright: ignore[reportPrivateUsage]
    runner._slots.put_nowait(slot)  # pyright: ignore[reportPrivateUsage]
    monkeypatch.setattr(hook_worker_module, "terminate_worker_tree", _contain_fake_process)

    result = runner.review(
        payload={"hook_event_name": "PreToolUse"},
        harness="pi",
        home_dir=tmp_path,
        guard_home=tmp_path,
        workspace=tmp_path,
        hook_env={},
        deadline=time.monotonic() + 0.02,
    )

    assert result.reason_code == "daemon_hook_process_deadline_exhausted"
    assert runner.stats()["timeouts"] == 0
    retire_deadline = time.monotonic() + 0.5
    while runner.stats()["workers"] and time.monotonic() < retire_deadline:
        time.sleep(0.01)
    assert runner.stats()["workers"] == 0
    assert runner.close_contained()


def test_response_received_after_caller_deadline_is_rejected(
    tmp_path,
    monkeypatch,
) -> None:
    runner = HookProcessRunner(guard_home=tmp_path, process_limit=1, timeout_seconds=1)
    runner._started = True  # pyright: ignore[reportPrivateUsage]
    process = _FakeProcess(1)
    slot = HookWorkerSlot(
        process=process,
        connection=_LateResultConnection(),
        pre_isolation_contained=True,
    )
    runner._all_slots[process.pid] = slot  # pyright: ignore[reportPrivateUsage]
    runner._slots.put_nowait(slot)  # pyright: ignore[reportPrivateUsage]
    monkeypatch.setattr(hook_worker_module, "terminate_worker_tree", _contain_fake_process)

    result = runner.review(
        payload={"hook_event_name": "PreToolUse"},
        harness="pi",
        home_dir=tmp_path,
        guard_home=tmp_path,
        workspace=tmp_path,
        hook_env={},
        deadline=time.monotonic() + 0.01,
    )

    assert result.payload is None
    assert result.reason_code == "daemon_hook_process_deadline_exhausted"
    assert runner._slots.qsize() == 0  # pyright: ignore[reportPrivateUsage]


def test_response_processed_after_caller_deadline_is_rejected(
    tmp_path,
    monkeypatch,
) -> None:
    runner = HookProcessRunner(guard_home=tmp_path, process_limit=1, timeout_seconds=1)
    runner._started = True  # pyright: ignore[reportPrivateUsage]
    process = _FakeProcess(1)
    slot = HookWorkerSlot(
        process=process,
        connection=_LateResultConnection(),
        pre_isolation_contained=True,
    )
    runner._all_slots[process.pid] = slot  # pyright: ignore[reportPrivateUsage]
    runner._slots.put_nowait(slot)  # pyright: ignore[reportPrivateUsage]
    original_decode = hook_runner_module.as_string_object_dict

    def slow_decode(value: object) -> dict[str, object] | None:
        time.sleep(0.05)
        return original_decode(value)

    monkeypatch.setattr(hook_runner_module, "as_string_object_dict", slow_decode)

    result = runner.review(
        payload={"hook_event_name": "PreToolUse"},
        harness="pi",
        home_dir=tmp_path,
        guard_home=tmp_path,
        workspace=tmp_path,
        hook_env={},
        deadline=time.monotonic() + 0.11,
    )

    assert result.payload is None
    assert result.reason_code == "daemon_hook_process_deadline_exhausted"
    assert runner._slots.qsize() == 1  # pyright: ignore[reportPrivateUsage]


def test_response_metrics_contention_does_not_outlive_caller_deadline(
    tmp_path,
) -> None:
    runner = HookProcessRunner(guard_home=tmp_path, process_limit=1, timeout_seconds=1)
    runner._started = True  # pyright: ignore[reportPrivateUsage]
    process = _FakeProcess(1)
    slot = HookWorkerSlot(
        process=process,
        connection=_LateResultConnection(),
        pre_isolation_contained=True,
    )
    runner._all_slots[process.pid] = slot  # pyright: ignore[reportPrivateUsage]
    runner._slots.put_nowait(slot)  # pyright: ignore[reportPrivateUsage]
    lock_held = threading.Event()

    def hold_metrics_lock() -> None:
        with runner._metrics_lock:  # pyright: ignore[reportPrivateUsage]
            lock_held.set()
            time.sleep(0.15)

    holder = threading.Thread(target=hold_metrics_lock)
    holder.start()
    assert lock_held.wait(timeout=0.5)
    started_at = time.monotonic()
    result = runner.review(
        payload={"hook_event_name": "PreToolUse"},
        harness="pi",
        home_dir=tmp_path,
        guard_home=tmp_path,
        workspace=tmp_path,
        hook_env={},
        deadline=started_at + 0.08,
    )
    elapsed = time.monotonic() - started_at
    holder.join(timeout=0.5)

    assert result.payload == {"decision": "allow"}
    assert result.reason_code is None
    assert elapsed < 0.08


def test_successful_review_is_constructed_before_final_deadline_check(
    tmp_path,
    monkeypatch,
) -> None:
    runner = HookProcessRunner(guard_home=tmp_path, process_limit=1, timeout_seconds=1)
    runner._started = True  # pyright: ignore[reportPrivateUsage]
    process = _FakeProcess(1)
    slot = HookWorkerSlot(
        process=process,
        connection=_LateResultConnection(),
        pre_isolation_contained=True,
    )
    runner._all_slots[process.pid] = slot  # pyright: ignore[reportPrivateUsage]
    runner._slots.put_nowait(slot)  # pyright: ignore[reportPrivateUsage]
    review_type = hook_runner_module.HookProcessReview

    def slow_success(payload: dict[str, object] | None, reason_code: str | None) -> HookProcessReview:
        if payload is not None:
            time.sleep(0.06)
        return review_type(payload, reason_code)

    monkeypatch.setattr(hook_runner_module, "HookProcessReview", slow_success)

    result = runner.review(
        payload={"hook_event_name": "PreToolUse"},
        harness="pi",
        home_dir=tmp_path,
        guard_home=tmp_path,
        workspace=tmp_path,
        hook_env={},
        deadline=time.monotonic() + 0.05,
    )

    assert result.payload is None
    assert result.reason_code == "daemon_hook_process_deadline_exhausted"


def test_retirement_thread_exhaustion_fails_pool_closed_without_delaying_review(
    tmp_path,
    monkeypatch,
) -> None:
    runner = HookProcessRunner(guard_home=tmp_path, process_limit=1, timeout_seconds=0.01)
    runner._started = True  # pyright: ignore[reportPrivateUsage]
    process = _FakeProcess(1)
    slot = HookWorkerSlot(
        process=process,
        connection=_SlowConnection(
            entered=[0],
            entered_lock=threading.Lock(),
            all_entered=threading.Event(),
        ),
        pre_isolation_contained=True,
    )
    runner._all_slots[1] = slot  # pyright: ignore[reportPrivateUsage]
    runner._slots.put_nowait(slot)  # pyright: ignore[reportPrivateUsage]
    monkeypatch.setattr(hook_worker_module, "terminate_worker_tree", _contain_fake_process)
    original_start = threading.Thread.start

    def fail_retirement_start(thread: threading.Thread) -> None:
        if thread.name == "hol-guard-hook-worker-retire":
            raise RuntimeError("thread exhaustion")
        original_start(thread)

    started_at = time.monotonic()
    with monkeypatch.context() as exhausted:
        exhausted.setattr(threading.Thread, "start", fail_retirement_start)
        result = runner.review(
            payload={"hook_event_name": "PreToolUse"},
            harness="pi",
            home_dir=tmp_path,
            guard_home=tmp_path,
            workspace=tmp_path,
            hook_env={},
        )
    elapsed = time.monotonic() - started_at
    retry = runner.review(
        payload={"hook_event_name": "PreToolUse"},
        harness="pi",
        home_dir=tmp_path,
        guard_home=tmp_path,
        workspace=tmp_path,
        hook_env={},
    )

    assert result.reason_code == "daemon_hook_process_timeout"
    assert elapsed < 0.1
    assert retry.reason_code == "daemon_hook_process_closed"
    assert runner.close_contained()


def test_close_waits_until_registered_retirement_thread_has_started(
    tmp_path,
    monkeypatch,
) -> None:
    runner = HookProcessRunner(guard_home=tmp_path, process_limit=1, timeout_seconds=0.01)
    runner._started = True  # pyright: ignore[reportPrivateUsage]
    process = _FakeProcess(1)
    slot = HookWorkerSlot(
        process=process,
        connection=_SlowConnection(
            entered=[0],
            entered_lock=threading.Lock(),
            all_entered=threading.Event(),
        ),
        pre_isolation_contained=True,
    )
    runner._all_slots[1] = slot  # pyright: ignore[reportPrivateUsage]
    runner._slots.put_nowait(slot)  # pyright: ignore[reportPrivateUsage]
    monkeypatch.setattr(hook_worker_module, "terminate_worker_tree", _contain_fake_process)
    original_start = threading.Thread.start
    retirement_start_entered = threading.Event()
    release_retirement_start = threading.Event()
    reviews: list[HookProcessReview] = []
    close_results: list[bool] = []
    close_errors: list[BaseException] = []

    def delayed_retirement_start(thread: threading.Thread) -> None:
        if thread.name == "hol-guard-hook-worker-retire":
            retirement_start_entered.set()
            assert release_retirement_start.wait(timeout=0.5)
        original_start(thread)

    def review() -> None:
        reviews.append(
            runner.review(
                payload={"hook_event_name": "PreToolUse"},
                harness="pi",
                home_dir=tmp_path,
                guard_home=tmp_path,
                workspace=tmp_path,
                hook_env={},
            )
        )

    def close() -> None:
        try:
            close_results.append(runner.close_contained())
        except BaseException as error:
            close_errors.append(error)

    monkeypatch.setattr(threading.Thread, "start", delayed_retirement_start)
    review_thread = threading.Thread(target=review)
    review_thread.start()
    assert retirement_start_entered.wait(timeout=0.5)
    close_thread = threading.Thread(target=close)
    close_thread.start()
    time.sleep(0.02)
    assert close_thread.is_alive()
    release_retirement_start.set()
    review_thread.join(timeout=1.5)
    close_thread.join(timeout=1.5)

    assert not close_errors
    assert close_results == [True]
    assert [result.reason_code for result in reviews] == ["daemon_hook_process_timeout"]


def test_supervisor_thread_exhaustion_leaves_runner_closed(
    tmp_path,
    monkeypatch,
) -> None:
    runner = HookProcessRunner(guard_home=tmp_path, process_limit=1)
    original_start = threading.Thread.start

    def fail_supervisor_start(thread: threading.Thread) -> None:
        if thread.name == "hol-guard-hook-worker-supervisor":
            raise RuntimeError("thread exhaustion")
        original_start(thread)

    monkeypatch.setattr(threading.Thread, "start", fail_supervisor_start)
    runner.start()
    result = runner.review(
        payload={"hook_event_name": "PreToolUse"},
        harness="pi",
        home_dir=tmp_path,
        guard_home=tmp_path,
        workspace=tmp_path,
        hook_env={},
    )

    assert result.reason_code == "daemon_hook_process_closed"
    assert runner.stats()["failures"] == 1
    assert runner.close_contained()


def test_close_waits_until_registered_supervisor_thread_has_started(
    tmp_path,
    monkeypatch,
) -> None:
    runner = HookProcessRunner(guard_home=tmp_path, process_limit=1)
    monkeypatch.setattr(hook_runner_module, "_HOOK_PROCESS_READY_TIMEOUT_SECONDS", 0.05)
    monkeypatch.setattr(runner, "_supervise_capacity", lambda _generation: None)
    original_start = threading.Thread.start
    supervisor_start_entered = threading.Event()
    release_supervisor_start = threading.Event()
    start_errors: list[BaseException] = []
    close_results: list[bool] = []
    close_errors: list[BaseException] = []

    def delayed_supervisor_start(thread: threading.Thread) -> None:
        if thread.name == "hol-guard-hook-worker-supervisor":
            supervisor_start_entered.set()
            assert release_supervisor_start.wait(timeout=0.5)
        original_start(thread)

    def start() -> None:
        try:
            runner.start()
        except BaseException as error:
            start_errors.append(error)

    def close() -> None:
        try:
            close_results.append(runner.close_contained())
        except BaseException as error:
            close_errors.append(error)

    monkeypatch.setattr(threading.Thread, "start", delayed_supervisor_start)
    start_thread = threading.Thread(target=start)
    start_thread.start()
    assert supervisor_start_entered.wait(timeout=0.5)
    close_thread = threading.Thread(target=close)
    close_thread.start()
    time.sleep(0.02)
    assert close_thread.is_alive()
    release_supervisor_start.set()
    start_thread.join(timeout=1)
    close_thread.join(timeout=1)

    assert not start_errors
    assert not close_errors
    assert close_results == [True]


def test_transient_spawn_thread_exhaustion_replenishes_capacity(
    tmp_path,
    monkeypatch,
) -> None:
    runner = HookProcessRunner(guard_home=tmp_path, process_limit=1)
    original_start = threading.Thread.start
    failed_once = False

    def transient_spawn_failure(thread: threading.Thread) -> None:
        nonlocal failed_once
        if thread.name == "hol-guard-hook-worker-spawn" and not failed_once:
            failed_once = True
            raise RuntimeError("thread exhaustion")
        original_start(thread)

    monkeypatch.setattr(threading.Thread, "start", transient_spawn_failure)
    try:
        runner.start()
        result = runner.review(
            payload={"hook_event_name": "SessionStart"},
            harness="pi",
            home_dir=tmp_path,
            guard_home=tmp_path,
            workspace=tmp_path,
            hook_env={},
        )
    finally:
        runner.close()

    assert failed_once
    assert result.payload is not None
    assert runner.stats()["failures"] >= 1
