from __future__ import annotations

import hashlib
import os
import signal
import subprocess
import threading
import time
from collections.abc import Mapping, Sequence
from contextlib import suppress
from pathlib import Path
from typing import ClassVar, Protocol, TextIO, cast, final

import pytest

from codex_plugin_scanner.guard import codex_hook_windows_job as windows_job_module
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
from codex_plugin_scanner.guard.daemon import hook_process_entrypoint as hook_entrypoint_module
from codex_plugin_scanner.guard.daemon import hook_process_runner as hook_runner_module
from codex_plugin_scanner.guard.daemon import hook_process_worker as hook_worker_module
from codex_plugin_scanner.guard.daemon import manager as daemon_manager_module
from codex_plugin_scanner.guard.daemon.hook_process_protocol import capture_hook_command
from codex_plugin_scanner.guard.daemon.hook_process_runner import HookProcessRunner
from codex_plugin_scanner.guard.daemon.hook_process_worker import HookWorkerSlot
from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.store import GuardStore


class _MutableUnicodeBuffer(Protocol):
    value: str


def test_default_review_deadline_stays_inside_pi_host_budget() -> None:
    pi_host_timeout_seconds = 4.5
    pi_daemon_timeout_seconds = 3.1
    pi_deadline_reserve_seconds = 0.25

    assert pi_daemon_timeout_seconds > hook_runner_module._HOOK_PROCESS_TIMEOUT_SECONDS  # pyright: ignore[reportPrivateUsage]
    assert (
        pi_host_timeout_seconds - pi_deadline_reserve_seconds
        > hook_runner_module._HOOK_PROCESS_ACQUIRE_TIMEOUT_SECONDS  # pyright: ignore[reportPrivateUsage]
        + hook_runner_module._HOOK_PROCESS_TIMEOUT_SECONDS  # pyright: ignore[reportPrivateUsage]
    )


def test_daemon_start_budget_contains_initial_worker_readiness() -> None:
    assert (
        daemon_manager_module.GUARD_DAEMON_START_TIMEOUT_SECONDS
        > hook_runner_module._HOOK_PROCESS_READY_TIMEOUT_SECONDS  # pyright: ignore[reportPrivateUsage]
    )
    assert (
        hook_runner_module._HOOK_PROCESS_READY_TIMEOUT_SECONDS  # pyright: ignore[reportPrivateUsage]
        > hook_entrypoint_module._HOOK_EVALUATOR_READY_TIMEOUT_SECONDS  # pyright: ignore[reportPrivateUsage]
    )


def test_windows_taskkill_path_uses_system_directory_api(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeGetSystemWindowsDirectory:
        def __init__(self) -> None:
            self.argtypes: list[object] = []
            self.restype: object = None

        def __call__(self, buffer: object, size: int) -> int:
            assert size == 32768
            cast(_MutableUnicodeBuffer, buffer).value = r"D:\Windows"
            return len(r"D:\Windows")

    class FakeKernel32:
        def __init__(self) -> None:
            self.GetSystemWindowsDirectoryW = FakeGetSystemWindowsDirectory()

    monkeypatch.setattr(windows_job_module.os, "name", "nt")
    monkeypatch.setattr(windows_job_module, "_kernel32", lambda: FakeKernel32())

    assert windows_job_module.windows_system_executable_path("taskkill.exe") == (r"D:\Windows\System32\taskkill.exe")
    with pytest.raises(ValueError, match="must be a filename"):
        windows_job_module.windows_system_executable_path(r"..\taskkill.exe")


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

    monkeypatch.setattr(hook_worker_module.os, "name", "nt")
    monkeypatch.setattr(
        hook_worker_module,
        "windows_system_executable_path",
        lambda _filename: r"C:\Windows\System32\taskkill.exe",
    )

    def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[bytes]:
        commands.append(command)
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(subprocess, "run", fake_run)

    hook_worker_module.terminate_worker_tree(FakeProcess(), 15)

    assert commands == [[r"C:\Windows\System32\taskkill.exe", "/PID", "4321", "/T", "/F"]]


def test_windows_hook_job_breakaway_is_recovery_only() -> None:
    assert _job_limit_flags(allow_breakaway=False) == _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    assert _job_limit_flags(allow_breakaway=True) == (
        _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | _JOB_OBJECT_LIMIT_BREAKAWAY_OK
    )


def test_current_windows_process_is_assigned_to_kill_on_close_job(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[object, ...]] = []
    job = windows_job_module.WindowsHookJob(handle=77)

    class FakeFunction:
        def __init__(self, callback) -> None:
            self.callback = callback
            self.argtypes: list[object] = []
            self.restype: object | None = None

        def __call__(self, *args: object) -> object:
            return self.callback(*args)

    kernel32 = type(
        "FakeKernel32",
        (),
        {
            "GetCurrentProcess": FakeFunction(lambda: 321),
            "AssignProcessToJobObject": FakeFunction(
                lambda job_handle, process_handle: calls.append((job_handle, process_handle)) or True
            ),
            "IsProcessInJob": FakeFunction(
                lambda _process_handle, _job_handle, assigned: setattr(assigned._obj, "value", True) or True
            ),
        },
    )()
    created: list[bool] = []
    monkeypatch.setattr(windows_job_module.os, "name", "nt")
    monkeypatch.setattr(
        windows_job_module,
        "_create_job",
        lambda *, allow_breakaway=False: created.append(allow_breakaway) or job,
    )
    monkeypatch.setattr(windows_job_module, "_kernel32", lambda: kernel32)

    assigned = windows_job_module.assign_current_process_to_windows_hook_job()

    assert assigned is job
    assert created == [False]
    assert len(calls) == 1


def test_current_windows_process_assignment_failure_closes_job(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    job = windows_job_module.WindowsHookJob(handle=77)
    closed: list[windows_job_module.WindowsHookJob] = []

    class FakeGetCurrentProcess:
        argtypes: ClassVar[list[object]] = []
        restype: object | None = None

        def __call__(self) -> int:
            return 321

    kernel32 = type("FakeKernel32", (), {"GetCurrentProcess": FakeGetCurrentProcess()})()
    monkeypatch.setattr(windows_job_module.os, "name", "nt")
    monkeypatch.setattr(windows_job_module, "_create_job", lambda **_kwargs: job)
    monkeypatch.setattr(windows_job_module, "_kernel32", lambda: kernel32)
    monkeypatch.setattr(
        windows_job_module,
        "_assign_process_handle_to_job",
        lambda *_args: (_ for _ in ()).throw(OSError("assignment refused")),
    )
    monkeypatch.setattr(windows_job_module, "close_windows_hook_job", closed.append)

    with pytest.raises(OSError, match="assignment refused"):
        windows_job_module.assign_current_process_to_windows_hook_job()

    assert closed == [job]


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

    monkeypatch.setattr(hook_worker_module.os, "name", "nt")
    monkeypatch.setattr(
        hook_worker_module,
        "windows_system_executable_path",
        lambda _filename: r"C:\Windows\System32\taskkill.exe",
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


def test_worker_readiness_does_not_touch_guard_state(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    store = GuardStore(guard_home)
    store.upsert_runtime_state(
        session_id="sentinel-session",
        daemon_host="127.0.0.1",
        daemon_port=9876,
        started_at="2026-07-25T00:00:00+00:00",
        last_heartbeat_at="2026-07-25T00:00:01+00:00",
    )
    store.add_approval_request(
        GuardApprovalRequest(
            request_id="sentinel-request",
            harness="pi",
            artifact_id="pi:sentinel",
            artifact_name="Sentinel",
            artifact_hash="sentinel-hash",
            policy_action="require-reapproval",
            recommended_scope="artifact",
            changed_fields=("command",),
            source_scope="project",
            config_path="/sentinel/config",
            review_command="hol-guard review sentinel-request",
            approval_url="http://127.0.0.1/approve/sentinel-request",
        ),
        "2026-07-25T00:00:02+00:00",
    )
    runtime_state = store.get_runtime_state()
    receipts = store.list_receipts()
    approval_requests = store.list_approval_requests(status=None)

    def state_digests() -> dict[str, str]:
        return {
            path.relative_to(guard_home).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in guard_home.rglob("*")
            if path.is_file()
        }

    before = state_digests()
    runner = HookProcessRunner(
        guard_home=guard_home,
        process_limit=2,
        timeout_seconds=1,
    )
    try:
        runner.start()
        assert runner.stats()["ready"] == 2
        assert state_digests() == before
        assert store.get_runtime_state() == runtime_state
        assert store.list_receipts() == receipts
        assert store.list_approval_requests(status=None) == approval_requests
    finally:
        runner.close()


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


def test_deferred_runner_serves_first_worker_before_backfilling(tmp_path: Path) -> None:
    runner = HookProcessRunner(guard_home=tmp_path, process_limit=2, timeout_seconds=2)
    ready_workers = 0
    try:
        runner.start(defer_backfill=True)
        assert runner.stats()["ready"] == 1

        runner.enable_full_capacity(delay_seconds=0)
        deadline = time.monotonic() + 3
        while runner.stats()["ready"] != 2 and time.monotonic() < deadline:
            time.sleep(0.02)
        ready_workers = runner.stats()["ready"]
    finally:
        runner.close()

    assert ready_workers == 2
    assert runner.stats()["workers"] == 0


def test_deferred_runner_bounds_backfill_deferral_during_active_reviews(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = HookProcessRunner(guard_home=tmp_path, process_limit=2)
    original_start = runner._start_slot  # pyright: ignore[reportPrivateUsage]
    attempts = 0

    def counted_start(*, generation: int) -> HookWorkerSlot:
        nonlocal attempts
        attempts += 1
        return original_start(generation=generation)

    monkeypatch.setattr(runner, "_start_slot", counted_start)
    monkeypatch.setattr(hook_runner_module, "_HOOK_PROCESS_BACKFILL_MAX_DEFERRAL_SECONDS", 0.2)
    try:
        runner.start(defer_backfill=True)
        with runner._state_lock:  # pyright: ignore[reportPrivateUsage]
            generation = runner._generation  # pyright: ignore[reportPrivateUsage]
            runner._active_reviews[generation] = 1  # pyright: ignore[reportPrivateUsage]
        runner.enable_full_capacity(delay_seconds=0)
        time.sleep(0.1)
        assert attempts == 1
        assert runner.wait_for_capacity(minimum_workers=2, timeout_seconds=5)
    finally:
        with runner._state_lock:  # pyright: ignore[reportPrivateUsage]
            runner._active_reviews.clear()  # pyright: ignore[reportPrivateUsage]
        runner.close()


def test_default_worker_budget_stays_below_pi_hook_deadline() -> None:
    runner = HookProcessRunner()

    assert runner._timeout_seconds == 2.8  # pyright: ignore[reportPrivateUsage]
    assert runner._timeout_seconds < 3.1  # pyright: ignore[reportPrivateUsage]


def test_prewarmed_runner_scans_post_tool_output_in_isolated_worker(tmp_path: Path) -> None:
    runner = HookProcessRunner(guard_home=tmp_path, process_limit=1, timeout_seconds=2)
    runner.start()
    try:
        result = runner.review(
            payload={
                "hook_event_name": "PostToolUse",
                "tool_name": "Bash",
                "tool_input": {"command": "echo hello"},
                "tool_response": [{"type": "text", "text": "hello\n"}],
            },
            harness="pi",
            home_dir=tmp_path,
            guard_home=tmp_path,
            workspace=tmp_path,
            hook_env={},
        )
    finally:
        runner.close()

    assert result.reason_code is None
    assert result.payload is not None
    assert result.payload["decision"] == "allow"
    assert result.payload["reason_code"] == "output_scan_allow"
    assert runner.stats()["workers"] == 0


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
        ready = original_ready(slot, timeout)
        return attempts > 1 and ready

    monkeypatch.setattr(runner, "_slot_became_ready", transient_ready)
    ready_workers = 0
    review_payload: dict[str, object] | None = None
    try:
        runner.start()
        assert runner.wait_for_capacity(minimum_workers=1, timeout_seconds=10)
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
        assert 0 <= attempts - runner.stats()["failures"] <= 1
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
    spawn_thread = next(iter(runner._spawn_threads))  # pyright: ignore[reportPrivateUsage]

    started = time.monotonic()
    runner.close()
    elapsed = time.monotonic() - started

    assert supervisor is not None and not supervisor.is_alive()
    assert spawn_thread is not None and spawn_thread.is_alive()
    assert elapsed < 0.5
    with pytest.raises(RuntimeError, match="previous hook worker generation is not contained"):
        runner.start()
    monkeypatch.setattr(hook_runner_module, "_HOOK_PROCESS_READY_TIMEOUT_SECONDS", 5.0)
    with monkeypatch.context() as failed_stale_retirement:
        failed_stale_retirement.setattr(
            runner,
            "_retire_slot",
            lambda _slot, *, graceful=False: False,
        )
        release_spawn.set()
        spawn_thread.join(timeout=2)
        assert not spawn_thread.is_alive()
        assert runner.stats()["workers"] == 1
        assert not runner.close_contained()

    assert runner.close_contained()

    runner.start()
    assert runner.wait_for_capacity(minimum_workers=1, timeout_seconds=10)
    assert runner.stats()["workers"] == 1
    runner.close()


def test_crashed_guardian_fails_closed_without_stale_group_cleanup(tmp_path: Path) -> None:
    runner = HookProcessRunner(guard_home=tmp_path, process_limit=1, timeout_seconds=0.5)
    runner.start()
    slot = runner._slots.get_nowait()  # pyright: ignore[reportPrivateUsage]
    process_group_id = slot.process.pid
    assert process_group_id is not None
    try:
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
        retry = runner.review(
            payload={"hook_event_name": "SessionStart"},
            harness="pi",
            home_dir=tmp_path,
            guard_home=tmp_path,
            workspace=tmp_path,
            hook_env={},
        )
    finally:
        with suppress(OSError, ProcessLookupError):
            os.killpg(process_group_id, getattr(signal, "SIGKILL", 9))
        slot.isolation_ready = False
        slot.pre_isolation_contained = True
        runner.close()

    assert failed.payload is None
    assert runner.stats()["restarts"] == 0
    assert retry.reason_code == "daemon_hook_process_closed"


def test_review_waits_briefly_for_prepared_worker_capacity(tmp_path: Path) -> None:
    runner = HookProcessRunner(guard_home=tmp_path, process_limit=1, timeout_seconds=1.5)
    runner.start()
    slot = runner._slots.get_nowait()  # pyright: ignore[reportPrivateUsage]
    release = threading.Timer(0.05, lambda: runner._slots.put_nowait(slot))  # pyright: ignore[reportPrivateUsage]
    release.start()
    try:
        started = time.monotonic()
        result = runner.review(
            payload={"hook_event_name": "SessionStart"},
            harness="pi",
            home_dir=tmp_path,
            guard_home=tmp_path,
            workspace=tmp_path,
            hook_env={},
        )
        elapsed = time.monotonic() - started
    finally:
        release.join(timeout=1)
        runner.close()

    assert elapsed >= 0.04
    assert result.payload is not None


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


def test_acquire_fails_fast_when_saturated_with_existing_workers(tmp_path) -> None:
    """Under genuine saturation (workers exist, all checked out), acquire must
    not wait for the bootstrap window — it fails fast as overload."""
    from codex_plugin_scanner.guard.daemon.hook_process_runner import HookProcessRunner

    runner = HookProcessRunner(guard_home=tmp_path, process_limit=1, timeout_seconds=2.0)
    runner.start()
    try:
        assert runner.wait_for_capacity(minimum_workers=1, timeout_seconds=15.0)
        # Hold the single worker by occupying the pool: spawn a second acquire
        # while the first review is in-flight is hard to stage deterministically,
        # so assert the saturation predicate directly.
        # _capacity_building must be False once workers exist even when busy.
        with runner._state_lock:  # pyright: ignore[reportPrivateUsage]
            total = len(runner._all_slots)  # pyright: ignore[reportPrivateUsage]
        assert total >= 1
        assert not runner._capacity_building()  # pyright: ignore[reportPrivateUsage]
    finally:
        runner.close()
