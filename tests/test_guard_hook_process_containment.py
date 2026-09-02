from __future__ import annotations

import os
import signal
import threading
from contextlib import suppress
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import hook_process_runner as hook_runner_module
from codex_plugin_scanner.guard.daemon import hook_process_worker as hook_worker_module
from codex_plugin_scanner.guard.daemon.hook_process_runner import HookProcessRunner
from codex_plugin_scanner.guard.daemon.hook_process_spawner import hook_worker_became_ready
from codex_plugin_scanner.guard.daemon.hook_process_worker import HookWorkerSlot, retire_worker_slot


class _DeadGuardian:
    pid = 12345

    def is_alive(self) -> bool:
        return False

    def join(self, timeout: float | None = None) -> None:
        del timeout

    def terminate(self) -> None:
        return

    def kill(self) -> None:
        return


class _SlowlyScheduledGuardian(_DeadGuardian):
    def __init__(self) -> None:
        self._alive = True

    def is_alive(self) -> bool:
        return self._alive

    def join(self, timeout: float | None = None) -> None:
        if timeout is not None and timeout >= 1:
            self._alive = False


class _Connection:
    def send(self, obj: object) -> None:
        del obj

    def recv(self) -> object:
        raise AssertionError("dead guardian connection must not be read")

    def poll(self, timeout: float = 0.0) -> bool:
        del timeout
        return False

    def close(self) -> None:
        return


class _ProtocolConnection(_Connection):
    def __init__(self, message: object) -> None:
        self._message = message

    def recv(self) -> object:
        return self._message

    def poll(self, timeout: float = 0.0) -> bool:
        del timeout
        return True


def test_post_request_unknown_isolation_does_not_signal_group_without_live_guardian(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    slot = HookWorkerSlot(
        process=_DeadGuardian(),
        connection=_Connection(),
        retire_lock=threading.Lock(),
        request_exposed=True,
    )
    monkeypatch.setattr(
        hook_worker_module.os,
        "killpg",
        lambda *_args: pytest.fail("a dead guardian cannot authorize process-group signaling"),
    )

    assert not retire_worker_slot(slot)


def test_explicit_pre_isolation_failure_allows_direct_cleanup() -> None:
    slot = HookWorkerSlot(
        process=_DeadGuardian(),
        connection=_ProtocolConnection(("isolation_failed", None)),
    )

    assert not hook_worker_became_ready(slot, 0.1)
    assert slot.pre_isolation_contained
    assert retire_worker_slot(slot)


def test_contained_guardian_gets_bounded_time_to_exit_after_kill(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    guardian = _SlowlyScheduledGuardian()
    slot = HookWorkerSlot(
        process=guardian,
        connection=_Connection(),
        isolation_ready=True,
    )
    monkeypatch.setattr(hook_worker_module.os, "name", "posix")
    monkeypatch.setattr(hook_worker_module.os, "killpg", lambda *_args: None)

    assert retire_worker_slot(slot)
    assert not guardian.is_alive()


def test_close_retains_worker_when_guardian_identity_is_lost(tmp_path: Path) -> None:
    runner = HookProcessRunner(guard_home=tmp_path, process_limit=1, timeout_seconds=0.5)
    runner.start()
    slot = runner._slots.get_nowait()  # pyright: ignore[reportPrivateUsage]
    process_group_id = slot.process.pid
    assert process_group_id is not None
    slot.process.kill()
    slot.process.join(timeout=1)
    runner._slots.put_nowait(slot)  # pyright: ignore[reportPrivateUsage]

    _ = runner.review(
        payload={"hook_event_name": "SessionStart"},
        harness="pi",
        home_dir=tmp_path,
        guard_home=tmp_path,
        workspace=tmp_path,
        hook_env={},
    )
    supervisor = runner._supervisor_thread  # pyright: ignore[reportPrivateUsage]
    contained = runner.close_contained()

    assert not contained
    assert runner.stats()["workers"] == 1
    assert supervisor is None or not supervisor.is_alive()
    with suppress(OSError, ProcessLookupError):
        os.killpg(process_group_id, getattr(signal, "SIGKILL", 9))
    slot.isolation_ready = False
    slot.pre_isolation_contained = True
    assert runner.close_contained()


def test_close_waits_for_inflight_worker_isolation_before_retirement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = HookProcessRunner(guard_home=tmp_path, process_limit=1, timeout_seconds=0.5)
    runner.start()
    assert runner.wait_for_capacity(minimum_workers=1, timeout_seconds=10)
    slot = runner._slots.get_nowait()  # pyright: ignore[reportPrivateUsage]
    runner._slots.put_nowait(slot)  # pyright: ignore[reportPrivateUsage]
    slot.isolation_ready = False
    slot.pre_isolation_contained = False
    isolation_waits: list[float] = []

    def complete_isolation(candidate: HookWorkerSlot, timeout: float) -> bool:
        isolation_waits.append(timeout)
        candidate.isolation_ready = True
        return True

    monkeypatch.setattr(hook_runner_module, "hook_worker_became_isolated", complete_isolation)

    assert runner.close_contained()
    assert len(isolation_waits) == 1
    assert 0 < isolation_waits[0] <= hook_runner_module._HOOK_PROCESS_READY_TIMEOUT_SECONDS
    assert runner.stats()["workers"] == 0


def test_close_retains_uncontained_worker_for_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = HookProcessRunner(guard_home=tmp_path, process_limit=1, timeout_seconds=0.5)
    runner.start()
    slot = runner._slots.get_nowait()  # pyright: ignore[reportPrivateUsage]
    runner._slots.put_nowait(slot)  # pyright: ignore[reportPrivateUsage]

    def ignore_join(timeout: float | None = None) -> None:
        del timeout

    def ignore_terminate(_process: object, _signal: int) -> None:
        return

    with monkeypatch.context() as containment_failure:
        containment_failure.setattr(slot.process, "is_alive", lambda: True)
        containment_failure.setattr(slot.process, "join", ignore_join)
        containment_failure.setattr(hook_worker_module, "terminate_owned_process_group", ignore_terminate)

        assert not runner.close_contained()
        assert runner.stats()["workers"] == 1

    assert runner.close_contained()
    assert runner.stats()["workers"] == 0


def test_runner_rejects_invalid_limits() -> None:
    with pytest.raises(ValueError, match="process_limit"):
        _ = HookProcessRunner(process_limit=0)
    with pytest.raises(ValueError, match="timeout_seconds"):
        _ = HookProcessRunner(timeout_seconds=0)
    with pytest.raises(ValueError, match="must not exceed 16"):
        _ = HookProcessRunner(process_limit=17)
