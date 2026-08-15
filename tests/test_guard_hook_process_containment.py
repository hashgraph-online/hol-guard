from __future__ import annotations

import threading

import pytest

from codex_plugin_scanner.guard.daemon import hook_process_worker as hook_worker_module
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
