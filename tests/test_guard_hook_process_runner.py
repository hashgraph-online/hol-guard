from __future__ import annotations

import os
import subprocess
import threading
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from types import SimpleNamespace
from typing import TextIO, final

import pytest

from codex_plugin_scanner.guard.codex_hook_launch_runtime import (
    BoundedHookProcessResult,
    isolated_daemon_start_command,
    isolated_hook_environment,
)
from codex_plugin_scanner.guard.codex_hook_runtime_trust import TrustedCodexHookLaunch
from codex_plugin_scanner.guard.codex_hook_windows_job import (
    _JOB_OBJECT_LIMIT_BREAKAWAY_OK,  # pyright: ignore[reportPrivateUsage]
    _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,  # pyright: ignore[reportPrivateUsage]
    _job_limit_flags,  # pyright: ignore[reportPrivateUsage]
)
from codex_plugin_scanner.guard.daemon import hook_process_runner as hook_runner_module
from codex_plugin_scanner.guard.daemon import hook_process_worker as hook_worker_module
from codex_plugin_scanner.guard.daemon.hook_process_protocol import capture_hook_command
from codex_plugin_scanner.guard.daemon.hook_process_runner import HookProcessRunner
from codex_plugin_scanner.guard.daemon.hook_process_worker import HookWorkerSlot
from codex_plugin_scanner.guard.store import GuardStore


def test_windows_worker_timeout_terminates_entire_process_tree(monkeypatch: pytest.MonkeyPatch) -> None:
    commands: list[list[str]] = []

    @final
    class FakeProcess:
        pid: int = 4321

        def is_alive(self) -> bool:
            return True

        def join(self, timeout: float | None = None) -> None:
            del timeout

        def terminate(self) -> None:
            pytest.fail("taskkill must terminate the Windows worker tree")

        def kill(self) -> None:
            pytest.fail("taskkill must terminate the Windows worker tree")

    monkeypatch.setattr(
        hook_worker_module,
        "os",
        SimpleNamespace(
            name="nt",
            environ={"SYSTEMROOT": r"C:\Windows"},
            path=os.path,
        ),
    )

    def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        commands.append(command)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(subprocess, "run", fake_run)

    hook_worker_module.terminate_worker_tree(FakeProcess(), 15)

    assert commands == [[r"C:\Windows/System32/taskkill.exe", "/PID", "4321", "/T", "/F"]]


def test_windows_hook_job_breakaway_is_recovery_only() -> None:
    assert _job_limit_flags(allow_breakaway=False) == _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    assert _job_limit_flags(allow_breakaway=True) == (
        _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | _JOB_OBJECT_LIMIT_BREAKAWAY_OK
    )


def test_windows_worker_taskkill_failure_falls_back_to_direct_termination(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    terminated = False

    @final
    class FakeProcess:
        pid: int = 4321

        def is_alive(self) -> bool:
            return True

        def join(self, timeout: float | None = None) -> None:
            del timeout

        def terminate(self) -> None:
            nonlocal terminated
            terminated = True

        def kill(self) -> None:
            pytest.fail("SIGTERM fallback should terminate the direct worker")

    monkeypatch.setattr(
        hook_worker_module,
        "os",
        SimpleNamespace(
            name="nt",
            environ={"SYSTEMROOT": r"C:\Windows"},
            path=os.path,
        ),
    )

    def failed_taskkill(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess([], 1, b"", b"")

    monkeypatch.setattr(subprocess, "run", failed_taskkill)

    hook_worker_module.terminate_worker_tree(FakeProcess(), 15)

    assert terminated


def test_worker_request_returns_parsed_hook_json() -> None:
    def run(output_stream: TextIO) -> int:
        _ = output_stream.write('{"decision":"deny"}')
        return 0

    result = capture_hook_command(run)

    assert result == {"payload": {"decision": "deny"}, "reason_code": None}


def test_worker_request_fails_safe_on_invalid_json() -> None:
    def run(output_stream: TextIO) -> int:
        _ = output_stream.write("not-json")
        return 0

    result = capture_hook_command(run)

    assert result == {"payload": None, "reason_code": "daemon_hook_process_invalid_json"}


def test_prewarmed_runner_handles_real_hook_and_closes(tmp_path: Path) -> None:
    runner = HookProcessRunner(process_limit=1, timeout_seconds=2)
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
        runner.close()

    assert result.reason_code is None
    assert result.payload is not None


def test_worker_prewarm_does_not_create_approval_request(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    runner = HookProcessRunner(guard_home=tmp_path, process_limit=1)
    try:
        runner.start()
    finally:
        runner.close()

    assert store.count_approval_requests() == 0


def test_transient_initial_worker_failure_replenishes_capacity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = HookProcessRunner(guard_home=tmp_path, process_limit=1)
    original_ready = runner._slot_became_ready  # pyright: ignore[reportPrivateUsage]
    attempts = 0

    def transient_ready(slot: HookWorkerSlot, timeout: float) -> bool:
        nonlocal attempts
        attempts += 1
        return attempts > 1 and original_ready(slot, timeout)

    monkeypatch.setattr(runner, "_slot_became_ready", transient_ready)
    ready_workers = 0
    review_payload: dict[str, object] | None = None
    try:
        runner.start()
        deadline = time.monotonic() + 3
        while runner.stats()["ready"] != 1 and time.monotonic() < deadline:
            time.sleep(0.02)
        ready_workers = runner.stats()["ready"]
        review_payload = runner.review(
            payload={"hook_event_name": "SessionStart"},
            harness="pi",
            home_dir=tmp_path,
            guard_home=tmp_path,
            workspace=tmp_path,
            hook_env={},
        ).payload
    finally:
        runner.close()

    assert attempts >= 2
    assert ready_workers == 1
    assert review_payload is not None
    assert runner.stats()["workers"] == 0


def test_transient_worker_spawn_failure_replenishes_capacity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = HookProcessRunner(guard_home=tmp_path, process_limit=1)
    original_start = runner._start_slot  # pyright: ignore[reportPrivateUsage]
    attempts = 0

    def transient_start(*, generation: int) -> HookWorkerSlot:
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise MemoryError("temporary process exhaustion")
        return original_start(generation=generation)

    monkeypatch.setattr(runner, "_start_slot", transient_start)
    try:
        runner.start()
        assert runner.stats()["ready"] == 1
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

    assert attempts == 3
    assert result.payload is not None


def test_persistent_spawn_failure_uses_one_bounded_backoff_supervisor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = HookProcessRunner(guard_home=tmp_path, process_limit=4)
    attempts = 0

    def unavailable_start(*, generation: int) -> HookWorkerSlot:
        del generation
        nonlocal attempts
        attempts += 1
        raise OSError("process table exhausted")

    monkeypatch.setattr(hook_runner_module, "_HOOK_PROCESS_READY_TIMEOUT_SECONDS", 0.3)
    monkeypatch.setattr(runner, "_start_slot", unavailable_start)
    runner.start()
    try:
        assert attempts <= 4
        assert runner.stats()["workers"] == 0
        assert runner.stats()["failures"] == attempts
    finally:
        runner.close()


def test_blocked_worker_spawn_does_not_block_supervisor_shutdown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = HookProcessRunner(guard_home=tmp_path, process_limit=1)
    original_start = runner._start_slot  # pyright: ignore[reportPrivateUsage]
    spawn_started = threading.Event()
    release_spawn = threading.Event()
    attempts = 0

    def controlled_start(*, generation: int) -> HookWorkerSlot:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            spawn_started.set()
            assert release_spawn.wait(timeout=5)
        return original_start(generation=generation)

    monkeypatch.setattr(hook_runner_module, "_HOOK_PROCESS_READY_TIMEOUT_SECONDS", 0.1)
    monkeypatch.setattr(runner, "_start_slot", controlled_start)
    runner.start()
    assert spawn_started.wait(timeout=1)
    supervisor = runner._supervisor_thread  # pyright: ignore[reportPrivateUsage]
    spawn_thread = runner._spawn_thread  # pyright: ignore[reportPrivateUsage]

    started = time.monotonic()
    runner.close()
    elapsed = time.monotonic() - started

    assert supervisor is not None and not supervisor.is_alive()
    assert spawn_thread is not None and spawn_thread.is_alive()
    assert elapsed < 0.5
    monkeypatch.setattr(hook_runner_module, "_HOOK_PROCESS_READY_TIMEOUT_SECONDS", 5.0)
    runner.start()
    deadline = time.monotonic() + 3
    while runner.stats()["ready"] != 1 and time.monotonic() < deadline:
        time.sleep(0.02)
    assert runner.stats()["ready"] == 1
    release_spawn.set()
    spawn_thread.join(timeout=2)
    deadline = time.monotonic() + 1
    while runner.stats()["workers"] != 1 and time.monotonic() < deadline:
        time.sleep(0.02)
    assert not spawn_thread.is_alive()
    assert runner.stats()["workers"] == 1
    runner.close()


def test_crashed_worker_is_replaced_and_reviews_resume(tmp_path: Path) -> None:
    runner = HookProcessRunner(guard_home=tmp_path, process_limit=1, timeout_seconds=0.5)
    runner.start()
    try:
        slot = runner._slots.get_nowait()  # pyright: ignore[reportPrivateUsage]
        slot.process.kill()
        slot.process.join(timeout=1)
        runner._slots.put_nowait(slot)  # pyright: ignore[reportPrivateUsage]

        failed = runner.review(
            payload={"hook_event_name": "SessionStart"},
            harness="pi",
            home_dir=tmp_path,
            guard_home=tmp_path,
            workspace=tmp_path,
            hook_env={},
        )
        deadline = time.monotonic() + 2
        while runner.stats()["ready"] != 1 and time.monotonic() < deadline:
            time.sleep(0.02)
        recovered = runner.review(
            payload={"hook_event_name": "SessionStart"},
            harness="pi",
            home_dir=tmp_path,
            guard_home=tmp_path,
            workspace=tmp_path,
            hook_env={},
        )
    finally:
        runner.close()

    assert failed.payload is None
    assert runner.stats()["restarts"] == 1
    assert recovered.payload is not None


def test_close_joins_in_flight_worker_recovery(tmp_path: Path) -> None:
    runner = HookProcessRunner(guard_home=tmp_path, process_limit=1, timeout_seconds=0.5)
    runner.start()
    slot = runner._slots.get_nowait()  # pyright: ignore[reportPrivateUsage]
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
    runner.close()

    assert runner.stats()["workers"] == 0
    assert supervisor is None or not supervisor.is_alive()


def test_runner_rejects_invalid_limits() -> None:
    with pytest.raises(ValueError, match="process_limit"):
        _ = HookProcessRunner(process_limit=0)
    with pytest.raises(ValueError, match="timeout_seconds"):
        _ = HookProcessRunner(timeout_seconds=0)


def test_recovery_failure_kind_is_tightly_allowlisted(tmp_path: Path) -> None:
    environment = isolated_hook_environment(
        {
            "HOL_GUARD_HOOK_FAILURE_KIND": "overload",
            "HOL_GUARD_UNTRUSTED_FAILURE_KIND": "authenticated-control-plane-failure",
        }
    )
    command = isolated_daemon_start_command("python", tmp_path, tmp_path / "guard")

    assert environment == {"HOL_GUARD_HOOK_FAILURE_KIND": "overload"}
    assert "'transport-failure'" in command[3]
    assert "'overload'" in command[3]
    assert "HOL_GUARD_UNTRUSTED_FAILURE_KIND" not in command[3]


def test_trusted_recovery_overlays_only_valid_failure_kind(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    environments: list[dict[str, str]] = []

    def capture_process(
        command: Sequence[str],
        *,
        input_text: str,
        cwd: Path,
        environment: Mapping[str, str],
        timeout_seconds: float,
        output_limit: int = 1_000_000,
        allow_windows_breakaway: bool = False,
    ) -> BoundedHookProcessResult:
        del command, input_text, cwd, timeout_seconds, output_limit
        assert allow_windows_breakaway
        environments.append(dict(environment))
        return BoundedHookProcessResult(0, "", False, False)

    monkeypatch.setattr(
        "codex_plugin_scanner.guard.codex_hook_runtime_trust.run_isolated_hook_process",
        capture_process,
    )
    launch = TrustedCodexHookLaunch(cwd=tmp_path, environment={"HOME": str(tmp_path)})

    assert launch.run_start(("python",), timeout_seconds=1, failure_kind="overload")
    assert launch.run_start(("python",), timeout_seconds=1, failure_kind="invalid")

    assert environments[0]["HOL_GUARD_HOOK_FAILURE_KIND"] == "overload"
    assert environments[1]["HOL_GUARD_HOOK_FAILURE_KIND"] == "transport-failure"
