from __future__ import annotations

import threading
from collections import deque
from pathlib import Path
from typing import final

import pytest

from codex_plugin_scanner.guard.daemon.hook_process_runner import HookProcessRunner
from codex_plugin_scanner.guard.daemon.hook_process_spawner import (
    hook_worker_became_isolated,
    hook_worker_became_ready,
)
from codex_plugin_scanner.guard.daemon.hook_process_worker import (
    HookWorkerSlot,
    WorkerConnection,
    WorkerProcess,
    allowlisted_startup_failure_code,
)


@final
class _Process:
    pid: int = 4312

    def is_alive(self) -> bool:
        return True

    def join(self, timeout: float | None = None) -> None:
        del timeout

    def terminate(self) -> None:
        return

    def kill(self) -> None:
        return


@final
class _Connection:
    def __init__(
        self,
        *messages: object,
        poll_result: bool = True,
        recv_fail_after: int | None = None,
    ) -> None:
        self._messages: deque[object] = deque(messages)
        self._poll_result: bool = poll_result
        self._recv_fail_after = recv_fail_after
        self._recv_count = 0

    def poll(self, timeout: float = 0.0) -> bool:
        del timeout
        return self._poll_result and (
            bool(self._messages) or (self._recv_fail_after is not None and self._recv_count >= self._recv_fail_after)
        )

    def recv(self) -> object:
        self._recv_count += 1
        if self._recv_fail_after is not None and self._recv_count > self._recv_fail_after:
            raise OSError("private transport detail")
        return self._messages.popleft()

    def send(self, obj: object) -> None:
        del obj

    def close(self) -> None:
        return


def _slot(connection: _Connection) -> HookWorkerSlot:
    process: WorkerProcess = _Process()
    worker_connection: WorkerConnection = connection
    return HookWorkerSlot(process=process, connection=worker_connection)


def _isolation_proof() -> tuple[str, dict[str, object]]:
    return "isolated", {"process_group_id": _Process.pid, "windows_job_contained": True}


def test_normal_worker_handshake_keeps_startup_diagnostic_empty() -> None:
    slot = _slot(
        _Connection(
            _isolation_proof(),
            ("ready", None),
        )
    )

    assert hook_worker_became_ready(slot, 0.1)
    assert slot.startup_failure_code is None


def test_worker_failure_reports_allowlisted_evaluator_stage() -> None:
    slot = _slot(
        _Connection(
            _isolation_proof(),
            ("worker_failed", {"reason_code": "hook_process_evaluator_ready_timeout"}),
        )
    )

    assert not hook_worker_became_ready(slot, 0.1)
    assert slot.startup_failure_code == "hook_process_evaluator_ready_timeout"


def test_worker_failure_collapses_untrusted_reason_to_protocol_code() -> None:
    slot = _slot(
        _Connection(
            _isolation_proof(),
            ("worker_failed", {"reason_code": "secret/path-or-payload"}),
        )
    )

    assert not hook_worker_became_ready(slot, 0.1)
    assert slot.startup_failure_code == "hook_process_ready_protocol"
    assert "secret" not in slot.startup_failure_code


def test_malformed_ready_message_cannot_claim_evaluator_failure() -> None:
    slot = _slot(
        _Connection(
            _isolation_proof(),
            ("ready", {"reason_code": "hook_process_evaluator_ready_timeout"}),
        )
    )
    assert not hook_worker_became_ready(slot, 0.1)
    assert slot.startup_failure_code == "hook_process_ready_protocol"


def test_worker_pipe_failure_uses_io_safe_stage_code() -> None:
    slot = _slot(
        _Connection(
            _isolation_proof(),
            recv_fail_after=1,
        )
    )
    assert not hook_worker_became_ready(slot, 0.1)
    assert slot.startup_failure_code == "hook_process_ready_pipe_failed"


def test_isolation_failure_preserves_stage_reason() -> None:
    slot = _slot(_Connection(("isolation_failed", {"reason_code": "hook_process_isolation_failed"})))

    assert not hook_worker_became_isolated(slot, 0.1)
    assert slot.pre_isolation_contained
    assert slot.startup_failure_code == "hook_process_isolation_failed"


def test_runner_stats_and_startup_exception_keep_allowlisted_reason(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = HookProcessRunner(guard_home=tmp_path, process_limit=1)
    slot = _slot(_Connection())
    slot.startup_failure_code = "hook_process_evaluator_pipe_failed"
    runner._remember_startup_failure(slot)

    def never_ready(**_kwargs: object) -> bool:
        return False

    monkeypatch.setattr(runner, "wait_for_capacity", never_ready)

    with pytest.raises(RuntimeError, match="hook_process_evaluator_pipe_failed"):
        runner.require_initial_capacity()
    assert runner.stats()["last_startup_failure"] == "hook_process_evaluator_pipe_failed"


def test_runner_drops_unallowlisted_slot_reason() -> None:
    slot = _slot(_Connection())
    slot.startup_failure_code = "untrusted-detail"

    assert allowlisted_startup_failure_code(slot.startup_failure_code) is None


@pytest.mark.parametrize("reader", [False, True])
def test_startup_failure_reader_and_writer_share_lock(tmp_path: Path, reader: bool) -> None:
    runner = HookProcessRunner(guard_home=tmp_path, process_limit=1)
    slot = _slot(_Connection())
    slot.startup_failure_code = "hook_process_ready_timeout" if reader else None
    started = threading.Event()
    completed = threading.Event()

    def access_failure() -> None:
        started.set()
        if reader:
            runner._remember_startup_failure(slot)
        else:
            _ = hook_worker_became_ready(slot, 0)
        completed.set()

    thread = threading.Thread(target=access_failure)
    with slot.startup_failure_lock:
        thread.start()
        assert started.wait(2)
        assert not completed.wait(0.05)
    thread.join(timeout=2)
    assert not thread.is_alive()
    assert completed.is_set()
    assert slot.startup_failure_code == "hook_process_ready_timeout"
    if reader:
        assert runner.stats()["last_startup_failure"] == "hook_process_ready_timeout"
