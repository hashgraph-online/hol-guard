from __future__ import annotations

import hashlib
import os
import signal
import subprocess
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from pathlib import Path
from typing import ClassVar, Protocol, TextIO, cast, final
from unittest.mock import MagicMock

import pytest

from codex_plugin_scanner.guard import codex_hook_windows_job as windows_job_module
from codex_plugin_scanner.guard import store as guard_store_module
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
from codex_plugin_scanner.guard.daemon import hook_process_spawner as hook_spawner_module
from codex_plugin_scanner.guard.daemon import hook_process_worker as hook_worker_module
from codex_plugin_scanner.guard.daemon import manager as daemon_manager_module
from codex_plugin_scanner.guard.daemon.hook_process_protocol import capture_hook_command
from codex_plugin_scanner.guard.daemon.hook_process_request import (
    build_hook_process_review_request,
    coerce_resident_hook_request,
    compatibility_hook_args,
)
from codex_plugin_scanner.guard.daemon.hook_process_runner import HookProcessRunner
from codex_plugin_scanner.guard.daemon.hook_process_worker import HookProcessReview, HookWorkerSlot
from codex_plugin_scanner.guard.daemon.runtime_hook_scheduler import RuntimeHookScheduler
from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.store import GuardStore


class _MutableUnicodeBuffer(Protocol):
    value: str


def test_native_review_floor_is_bound_to_private_worker_request(tmp_path: Path) -> None:
    request = build_hook_process_review_request(
        payload={"hook_event_name": "PreToolUse"},
        harness="omp",
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "workspace",
        hook_env={},
        claim_saved_approval=True,
        claimed_saved_allow_hash=None,
        claimed_trusted_request_override=False,
        claimed_approval_request_id=None,
        native_minimum_action="review",
    )

    parsed = coerce_resident_hook_request(request)

    assert parsed is not None
    assert parsed.native_minimum_action == "review"
    assert compatibility_hook_args(parsed).policy_action == "review"


def test_private_worker_request_rejects_unknown_native_floor(tmp_path: Path) -> None:
    request = build_hook_process_review_request(
        payload={"hook_event_name": "PreToolUse"},
        harness="omp",
        home_dir=tmp_path / "home",
        guard_home=tmp_path / "guard-home",
        workspace=None,
        hook_env={},
        claim_saved_approval=True,
        claimed_saved_allow_hash=None,
        claimed_trusted_request_override=False,
        claimed_approval_request_id=None,
    )
    request["native_minimum_action"] = "allow"

    assert coerce_resident_hook_request(request) is None


def test_native_review_floor_queues_resolvable_approval(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    request = build_hook_process_review_request(
        payload={
            "hook_event_name": "PreToolUse",
            "tool_call_id": "native-review-1",
            "tool_name": "bash",
            "tool_input": {"command": "gh pr checks 1 --repo example/example"},
        },
        harness="omp",
        home_dir=tmp_path / "home",
        guard_home=guard_home,
        workspace=tmp_path / "workspace",
        hook_env={},
        claim_saved_approval=True,
        claimed_saved_allow_hash=None,
        claimed_trusted_request_override=False,
        claimed_approval_request_id=None,
        native_minimum_action="review",
    )

    result = hook_entrypoint_module._run_resident_hook_request(  # pyright: ignore[reportPrivateUsage]
        request,
        stores={},
        hook_workers={},
        configured_guard_home=str(guard_home),
    )
    payload = result.get("payload")

    assert isinstance(payload, dict)
    assert payload.get("approval_request_id")
    assert payload.get("approval_url")
    assert payload.get("approval_center_url")


def test_default_review_deadline_stays_inside_pi_host_budget() -> None:
    pi_host_timeout_seconds = 4.5
    pi_daemon_timeout_seconds = 3.1
    pi_deadline_reserve_seconds = 0.25

    assert pi_daemon_timeout_seconds > hook_runner_module._HOOK_PROCESS_TIMEOUT_SECONDS  # pyright: ignore[reportPrivateUsage]
    assert (
        pi_host_timeout_seconds - pi_deadline_reserve_seconds > hook_runner_module._HOOK_PROCESS_TIMEOUT_SECONDS  # pyright: ignore[reportPrivateUsage]
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


def test_evaluator_becomes_ready_when_store_prewarm_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = MagicMock()
    connection.recv.return_value = ("stop", None)
    monkeypatch.setattr(
        guard_store_module,
        "GuardStore",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("migration busy")),
    )

    hook_entrypoint_module._hook_evaluator_main(connection, str(tmp_path / "guard-home"))  # pyright: ignore[reportPrivateUsage]

    connection.send.assert_called_once_with(("ready", None))


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
    assert _job_limit_flags(allow_breakaway=False, kill_on_close=False) == 0


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
        stats = runner.stats()
    finally:
        runner.close()
        runner.close()

    assert result.reason_code is None
    assert result.payload is not None
    assert sum(stats["decisions"].values()) == 1
    assert sum(stats["reason_codes"].values()) == 1


def test_prewarmed_runner_does_not_hide_a_second_worker_queue(tmp_path: Path) -> None:
    runner = HookProcessRunner(guard_home=tmp_path, process_limit=4, timeout_seconds=1.8)
    barrier = threading.Barrier(24)

    def review(index: int) -> HookProcessReview:
        barrier.wait(timeout=2)
        return runner.review(
            payload={
                "hook_event_name": "PreToolUse",
                "tool_call_id": f"multi-pi-{index}",
                "tool_name": "Bash",
                "tool_input": {"command": "git status --short"},
            },
            harness="pi",
            home_dir=tmp_path,
            guard_home=tmp_path,
            workspace=tmp_path,
            hook_env={},
        )

    try:
        runner.start()
        started_at = time.monotonic()
        with ThreadPoolExecutor(max_workers=24) as executor:
            results = list(executor.map(review, range(24)))
        elapsed = time.monotonic() - started_at
    finally:
        runner.close()

    assert any(result.reason_code is None for result in results)
    assert {result.reason_code for result in results if result.reason_code is not None} <= {
        "daemon_hook_process_not_ready"
    }
    assert elapsed < 1.0


def _transient_not_ready_test_runner(tmp_path: Path, responses: list[object]) -> tuple[HookProcessRunner, MagicMock]:
    runner = HookProcessRunner(guard_home=tmp_path, process_limit=1, timeout_seconds=1)
    runner._started = True  # pyright: ignore[reportPrivateUsage]
    process = MagicMock()
    process.pid = 4242
    process.is_alive.return_value = True
    connection = MagicMock()
    connection.poll.return_value = True
    connection.recv.side_effect = responses
    slot = HookWorkerSlot(process=process, connection=connection)
    runner._slots.put_nowait(slot)  # pyright: ignore[reportPrivateUsage]
    runner._ready_slot_ids.add(process.pid)  # pyright: ignore[reportPrivateUsage]
    return runner, connection


def test_idempotent_review_retries_transient_evaluator_not_ready(tmp_path: Path) -> None:
    runner, connection = _transient_not_ready_test_runner(
        tmp_path,
        [("result", {"payload": None, "reason_code": "daemon_hook_process_not_ready"})] * 4
        + [("result", {"payload": {"decision": "allow"}, "reason_code": None})],
    )

    result = runner.review(
        payload={
            "hook_event_name": "PreToolUse",
            "tool_call_id": "stable-call",
            "tool_name": "Bash",
            "tool_input": {"command": "git status --short"},
        },
        harness="pi",
        home_dir=tmp_path,
        guard_home=tmp_path,
        workspace=tmp_path,
        hook_env={},
        deadline=time.monotonic() + 1,
    )

    assert result == HookProcessReview({"decision": "allow"}, None)
    assert connection.send.call_count == 5
    assert runner._slots.qsize() == 1  # pyright: ignore[reportPrivateUsage]


def test_non_idempotent_review_does_not_retry_transient_evaluator_not_ready(tmp_path: Path) -> None:
    runner, connection = _transient_not_ready_test_runner(
        tmp_path,
        [("result", {"payload": None, "reason_code": "daemon_hook_process_not_ready"})],
    )

    result = runner.review(
        payload={"hook_event_name": "SessionStart"},
        harness="pi",
        home_dir=tmp_path,
        guard_home=tmp_path,
        workspace=tmp_path,
        hook_env={},
        deadline=time.monotonic() + 1,
    )

    assert result == HookProcessReview(None, "daemon_hook_process_not_ready")
    assert connection.send.call_count == 1


def test_failed_send_does_not_mark_request_as_exposed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = HookProcessRunner(guard_home=tmp_path, process_limit=1, timeout_seconds=1)
    runner._started = True  # pyright: ignore[reportPrivateUsage]
    process = MagicMock()
    process.pid = 4243
    process.is_alive.return_value = False
    connection = MagicMock()
    connection.send.side_effect = BrokenPipeError
    slot = HookWorkerSlot(process=process, connection=connection)
    runner._slots.put_nowait(slot)  # pyright: ignore[reportPrivateUsage]
    runner._ready_slot_ids.add(process.pid)  # pyright: ignore[reportPrivateUsage]
    monkeypatch.setattr(runner, "_replace_slot_async", lambda _slot: None)

    result = runner.review(
        payload={"hook_event_name": "SessionStart"},
        harness="pi",
        home_dir=tmp_path,
        guard_home=tmp_path,
        workspace=tmp_path,
        hook_env={},
    )

    assert result == HookProcessReview(None, "daemon_hook_process_failed")
    assert not slot.request_exposed


def test_idempotent_review_bounds_transient_not_ready_retries(tmp_path: Path) -> None:
    runner, connection = _transient_not_ready_test_runner(
        tmp_path,
        [("result", {"payload": None, "reason_code": "daemon_hook_process_not_ready"})] * 9,
    )

    result = runner.review(
        payload={
            "hook_event_name": "PreToolUse",
            "tool_call_id": "stable-call",
            "tool_name": "Bash",
            "tool_input": {"command": "git status --short"},
        },
        harness="pi",
        home_dir=tmp_path,
        guard_home=tmp_path,
        workspace=tmp_path,
        hook_env={},
        deadline=time.monotonic() + 1,
    )

    assert result == HookProcessReview(None, "daemon_hook_process_not_ready")
    assert connection.send.call_count == 9


def test_scheduler_and_runner_complete_48_routine_reviews_without_capacity_denial(
    tmp_path: Path,
) -> None:
    scheduler = RuntimeHookScheduler(
        active_limit=0,
        queued_limit=64,
        per_harness_queued_limit=64,
        per_client_queued_limit=16,
    )
    runner = HookProcessRunner(
        guard_home=tmp_path,
        process_limit=8,
        timeout_seconds=2.8,
        capacity_listener=scheduler.set_active_limit,
    )
    barrier = threading.Barrier(48)

    def review(index: int) -> HookProcessReview:
        barrier.wait(timeout=3)
        admission = scheduler.acquire(
            harness="pi",
            client_key=f"client-{index % 6}",
            lane="decision",
            payload_bytes=1,
            deadline=time.monotonic() + 10,
        )
        assert admission.permit is not None
        with admission.permit:
            return runner.review(
                payload={
                    "hook_event_name": "PreToolUse",
                    "tool_call_id": f"scheduled-pi-{index}",
                    "tool_name": "Bash",
                    "tool_input": {"command": "git status --short"},
                },
                harness="pi",
                home_dir=tmp_path,
                guard_home=tmp_path,
                workspace=tmp_path,
                hook_env={},
                deadline=time.monotonic() + 4,
            )

    try:
        runner.start()
        with ThreadPoolExecutor(max_workers=48) as executor:
            results = list(executor.map(review, range(48)))
    finally:
        runner.close()

    failures = [result.reason_code for result in results if result.payload is None]
    assert set(failures) <= {"daemon_hook_process_not_ready"}, runner.stats()
    assert scheduler.stats()["completed"] == 48
    assert scheduler.stats()["rejected"] == {}


def test_deferred_runner_serves_startup_floor_before_backfilling(tmp_path: Path) -> None:
    runner = HookProcessRunner(guard_home=tmp_path, process_limit=4, timeout_seconds=2)
    ready_workers = 0
    try:
        runner.start(defer_backfill=True)
        assert runner.stats()["ready"] == 2

        runner.enable_full_capacity(delay_seconds=0)
        assert runner.wait_for_capacity(minimum_workers=4, timeout_seconds=8)
        ready_workers = runner.stats()["ready"]
    finally:
        runner.close()

    assert ready_workers == 4
    assert runner.stats()["workers"] == 0


def test_deferred_runner_does_not_adapt_before_backfill_is_enabled(tmp_path: Path) -> None:
    runner = HookProcessRunner(guard_home=tmp_path)
    adaptive_capacity = runner._adaptive_capacity  # pyright: ignore[reportPrivateUsage]
    assert adaptive_capacity is not None

    try:
        runner.start(defer_backfill=True)
        deferred_target = runner._capacity_target  # pyright: ignore[reportPrivateUsage]
        runner._refresh_capacity_policy()  # pyright: ignore[reportPrivateUsage]

        assert deferred_target == 2
        assert runner._capacity_target == deferred_target  # pyright: ignore[reportPrivateUsage]

        runner.enable_full_capacity(delay_seconds=0)
        assert runner._adaptive_refresh_enabled  # pyright: ignore[reportPrivateUsage]
    finally:
        runner.close()


def test_queued_work_releases_deferred_backfill() -> None:
    runner = HookProcessRunner()
    with runner._state_lock:  # pyright: ignore[reportPrivateUsage]
        runner._backfill_not_before = time.monotonic() + 30  # pyright: ignore[reportPrivateUsage]
        runner._backfill_force_after = time.monotonic() + 35  # pyright: ignore[reportPrivateUsage]

    runner.notify_queued_work()

    assert runner._backfill_not_before == 0.0  # pyright: ignore[reportPrivateUsage]
    assert runner._backfill_force_after == 0.0  # pyright: ignore[reportPrivateUsage]
    assert runner._recovery_event.is_set()  # pyright: ignore[reportPrivateUsage]


def test_deferred_runner_bounds_backfill_deferral_during_active_reviews(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = HookProcessRunner(guard_home=tmp_path, process_limit=3)
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
        assert attempts == 2
        assert runner.wait_for_capacity(minimum_workers=3, timeout_seconds=5)
    finally:
        with runner._state_lock:  # pyright: ignore[reportPrivateUsage]
            runner._active_reviews.clear()  # pyright: ignore[reportPrivateUsage]
        runner.close()


def test_default_worker_budget_stays_below_pi_hook_deadline() -> None:
    runner = HookProcessRunner()

    assert runner._timeout_seconds == 2.8  # pyright: ignore[reportPrivateUsage]
    assert runner._timeout_seconds < 3.1  # pyright: ignore[reportPrivateUsage]
    assert hook_runner_module._HOOK_PROCESS_START_TIMEOUT_SECONDS > (  # pyright: ignore[reportPrivateUsage]
        hook_runner_module._HOOK_PROCESS_READY_TIMEOUT_SECONDS  # pyright: ignore[reportPrivateUsage]
    )


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


def test_idempotent_review_retries_once_after_worker_death(tmp_path: Path) -> None:
    runner = HookProcessRunner(guard_home=tmp_path, process_limit=2, timeout_seconds=2)
    try:
        runner.start()
        first_slot = next(iter(runner._all_slots.values()))  # pyright: ignore[reportPrivateUsage]
        first_slot.process.kill()
        first_slot.process.join(timeout=1)
        queued_slots = [
            runner._slots.get_nowait()  # pyright: ignore[reportPrivateUsage]
            for _index in range(runner._slots.qsize())  # pyright: ignore[reportPrivateUsage]
        ]
        runner._slots.put_nowait(first_slot)  # pyright: ignore[reportPrivateUsage]
        for queued_slot in queued_slots:
            if queued_slot is not first_slot:
                runner._slots.put_nowait(queued_slot)  # pyright: ignore[reportPrivateUsage]

        result = runner.review(
            payload={
                "hook_event_name": "PostToolUse",
                "tool_call_id": "retryable-review",
                "tool_name": "Bash",
                "tool_input": {"command": "echo hello"},
                "tool_response": [{"type": "text", "text": "hello\n"}],
            },
            harness="pi",
            home_dir=tmp_path,
            guard_home=tmp_path,
            workspace=tmp_path,
            hook_env={},
            deadline=time.monotonic() + 2,
        )
    finally:
        runner.close()

    assert result.reason_code is None
    assert result.payload is not None
    assert result.payload["decision"] == "allow"


def test_worker_retry_withdraws_scheduler_capacity_before_reusing_slot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scheduler = RuntimeHookScheduler(active_limit=0, queued_limit=4)
    runner = HookProcessRunner(
        guard_home=tmp_path,
        process_limit=2,
        timeout_seconds=2,
        capacity_listener=scheduler.set_active_limit,
    )
    permits = []
    try:
        runner.start()
        monkeypatch.setattr(
            runner,
            "_replace_slot_async",
            lambda slot: runner._withdraw_slot_capacity(slot),  # pyright: ignore[reportPrivateUsage]
        )
        first_slot = next(iter(runner._all_slots.values()))  # pyright: ignore[reportPrivateUsage]
        first_slot.process.kill()
        first_slot.process.join(timeout=1)
        queued_slots = [
            runner._slots.get_nowait()  # pyright: ignore[reportPrivateUsage]
            for _index in range(runner._slots.qsize())  # pyright: ignore[reportPrivateUsage]
        ]
        runner._slots.put_nowait(first_slot)  # pyright: ignore[reportPrivateUsage]
        for queued_slot in queued_slots:
            if queued_slot is not first_slot:
                runner._slots.put_nowait(queued_slot)  # pyright: ignore[reportPrivateUsage]

        for index in range(2):
            admission = scheduler.acquire(
                harness="pi",
                client_key=f"active-{index}",
                lane="decision",
                payload_bytes=1,
                deadline=time.monotonic() + 2,
            )
            assert admission.permit is not None
            permits.append(admission.permit)

        result = runner.review(
            payload={
                "hook_event_name": "PostToolUse",
                "tool_call_id": "scheduler-retry",
                "tool_name": "Bash",
                "tool_input": {"command": "echo hello"},
                "tool_response": [{"type": "text", "text": "hello\n"}],
            },
            harness="pi",
            home_dir=tmp_path,
            guard_home=tmp_path,
            workspace=tmp_path,
            hook_env={},
            deadline=time.monotonic() + 2,
        )
        assert result.payload is not None
        assert scheduler.stats()["active_limit"] == 1

        with ThreadPoolExecutor(max_workers=1) as executor:
            queued = executor.submit(
                scheduler.acquire,
                harness="pi",
                client_key="queued",
                lane="decision",
                payload_bytes=1,
                deadline=time.monotonic() + 1,
            )
            time.sleep(0.05)
            permits.pop().release()
            time.sleep(0.05)
            assert not queued.done()
            permits.pop().release()
            queued_admission = queued.result(timeout=1)
        assert queued_admission.permit is not None
        queued_admission.permit.release()
    finally:
        for permit in permits:
            permit.release()
        runner.close()


def test_every_async_worker_replacement_withdraws_scheduler_capacity_first(
    tmp_path: Path,
) -> None:
    scheduler = RuntimeHookScheduler(active_limit=0, queued_limit=4)
    runner = HookProcessRunner(
        guard_home=tmp_path,
        process_limit=2,
        capacity_listener=scheduler.set_active_limit,
    )
    permits = []
    try:
        runner.start()
        slot = runner._slots.get_nowait()  # pyright: ignore[reportPrivateUsage]
        for index in range(2):
            admission = scheduler.acquire(
                harness="pi",
                client_key=f"replacement-active-{index}",
                lane="decision",
                payload_bytes=1,
                deadline=time.monotonic() + 2,
            )
            assert admission.permit is not None
            permits.append(admission.permit)

        runner._replace_slot_async(slot)  # pyright: ignore[reportPrivateUsage]
        assert scheduler.stats()["active_limit"] == 1

        with ThreadPoolExecutor(max_workers=1) as executor:
            queued = executor.submit(
                scheduler.acquire,
                harness="pi",
                client_key="replacement-queued",
                lane="decision",
                payload_bytes=1,
                deadline=time.monotonic() + 1,
            )
            time.sleep(0.05)
            permits.pop().release()
            time.sleep(0.05)
            assert not queued.done()
            permits.pop().release()
            queued_admission = queued.result(timeout=1)
        assert queued_admission.permit is not None
        queued_admission.permit.release()
    finally:
        for permit in permits:
            permit.release()
        runner.close()


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
    original_ready = hook_spawner_module.hook_worker_became_ready
    attempts = 0

    def transient_ready(slot: HookWorkerSlot, timeout: float) -> bool:
        nonlocal attempts
        attempts += 1
        ready = original_ready(slot, timeout)
        return attempts > 1 and ready

    monkeypatch.setattr(hook_runner_module, "hook_worker_became_ready", transient_ready)
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


@pytest.mark.parametrize("readiness_result", [False, True])
def test_close_cancels_worker_readiness_from_stale_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    readiness_result: bool,
) -> None:
    published_capacities: list[int] = []
    runner = HookProcessRunner(
        guard_home=tmp_path,
        process_limit=1,
        capacity_listener=published_capacities.append,
    )
    readiness_waiting = threading.Event()
    release_readiness = threading.Event()
    isolation_started = threading.Event()
    process = MagicMock()
    process.pid = 4244
    process.is_alive.return_value = False
    slot = HookWorkerSlot(process=process, connection=MagicMock())

    def start_slot(generation: int) -> HookWorkerSlot:
        assert generation == 1
        with runner._state_lock:  # pyright: ignore[reportPrivateUsage]
            runner._all_slots[process.pid] = slot  # pyright: ignore[reportPrivateUsage]
        return slot

    def wait_for_readiness(candidate: HookWorkerSlot, timeout: float) -> bool:
        assert candidate is slot
        assert timeout > 0
        readiness_waiting.set()
        assert release_readiness.wait(timeout=2)
        return readiness_result

    def finish_isolation(candidate: HookWorkerSlot, timeout: float) -> bool:
        assert candidate is slot
        assert timeout > 0
        candidate.pre_isolation_contained = True
        isolation_started.set()
        return True

    monkeypatch.setattr(runner, "_start_slot_interruptibly", start_slot)
    monkeypatch.setattr(hook_runner_module, "hook_worker_became_ready", wait_for_readiness)
    monkeypatch.setattr(hook_runner_module, "hook_worker_became_isolated", finish_isolation)
    with runner._state_lock:  # pyright: ignore[reportPrivateUsage]
        runner._closed = False  # pyright: ignore[reportPrivateUsage]
        runner._started = True  # pyright: ignore[reportPrivateUsage]
        runner._generation = 1  # pyright: ignore[reportPrivateUsage]

    supervisor = threading.Thread(target=lambda: runner._supervise_capacity(1))  # pyright: ignore[reportPrivateUsage]
    with runner._state_lock:  # pyright: ignore[reportPrivateUsage]
        runner._supervisor_thread = supervisor  # pyright: ignore[reportPrivateUsage]
    close_results: list[bool] = []
    closer = threading.Thread(target=lambda: close_results.append(runner.close_contained()))
    try:
        supervisor.start()
        assert readiness_waiting.wait(timeout=1)
        closer.start()
        assert isolation_started.wait(timeout=1)
        with runner._state_lock:  # pyright: ignore[reportPrivateUsage]
            assert runner._generation == 2  # pyright: ignore[reportPrivateUsage]
    finally:
        release_readiness.set()
        supervisor.join(timeout=2)
        if closer.ident is not None:
            closer.join(timeout=2)

    assert not supervisor.is_alive()
    assert not closer.is_alive()
    assert close_results == [True]
    assert runner.stats()["failures"] == 0
    assert runner.stats()["ready"] == 0
    assert not runner._ready_slot_ids  # pyright: ignore[reportPrivateUsage]
    assert published_capacities == [0]


def test_pre_isolation_worker_death_replenishes_capacity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = HookProcessRunner(guard_home=tmp_path, process_limit=1)
    original_start = runner._start_slot  # pyright: ignore[reportPrivateUsage]
    attempts = 0
    recovered_stats: dict[str, object] = {}

    def transient_start(*, generation: int) -> HookWorkerSlot:
        nonlocal attempts
        attempts += 1
        slot = original_start(generation=generation)
        if attempts == 1:
            slot.process.kill()
            slot.process.join(timeout=1)
        return slot

    monkeypatch.setattr(runner, "_start_slot", transient_start)
    try:
        runner.start()
        assert runner.wait_for_capacity(minimum_workers=1, timeout_seconds=10)
        result = runner.review(
            payload={"hook_event_name": "SessionStart"},
            harness="pi",
            home_dir=tmp_path,
            guard_home=tmp_path,
            workspace=tmp_path,
            hook_env={},
        )
        recovered_stats = dict(runner.stats())
    finally:
        runner.close()

    assert attempts >= 2
    assert result.payload is not None
    assert recovered_stats["workers"] == 1
    assert recovered_stats["ready"] == 1
    assert recovered_stats["failures"] == 1
    assert recovered_stats["restarts"] == 0
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


def test_finished_cancelled_spawn_failure_does_not_increment_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = HookProcessRunner(guard_home=tmp_path, process_limit=1)
    spawned_threads: list[object] = []
    real_thread_type = threading.Thread

    class _FinishedThenClosedThread:
        def __init__(self, *, target: object, name: str, daemon: bool) -> None:
            del name
            self._target = cast(Callable[[], None], target)
            self.daemon = daemon
            self._closed_runner = False
            self._thread: threading.Thread | None = None
            spawned_threads.append(self)

        def start(self) -> None:
            self._thread = real_thread_type(target=self._target)
            self._thread.start()

        def is_alive(self) -> bool:
            assert self._thread is not None
            alive = self._thread.is_alive()
            if not alive and not self._closed_runner:
                self._closed_runner = True
                assert runner.close_contained()
            return alive

    def failed_start(*, generation: int) -> HookWorkerSlot:
        del generation
        raise OSError("injected worker spawn failure")

    with runner._state_lock:  # pyright: ignore[reportPrivateUsage]
        runner._closed = False  # pyright: ignore[reportPrivateUsage]
        runner._started = True  # pyright: ignore[reportPrivateUsage]
        runner._generation = 1  # pyright: ignore[reportPrivateUsage]
    monkeypatch.setattr(runner, "_start_slot", failed_start)
    monkeypatch.setattr(hook_runner_module.threading, "Thread", _FinishedThenClosedThread)
    monkeypatch.setattr(hook_runner_module.threading, "current_thread", lambda: spawned_threads[0])

    assert runner._start_slot_interruptibly(1) is None  # pyright: ignore[reportPrivateUsage]
    assert runner.stats()["failures"] == 0


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
    monkeypatch.setattr(hook_runner_module, "_HOOK_PROCESS_START_TIMEOUT_SECONDS", 0.3)
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
    monkeypatch.setattr(hook_runner_module, "_HOOK_PROCESS_START_TIMEOUT_SECONDS", 0.1)
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
    monkeypatch.setattr(hook_runner_module, "_HOOK_PROCESS_START_TIMEOUT_SECONDS", 10.0)
    with monkeypatch.context() as failed_stale_retirement:
        failed_stale_retirement.setattr(
            runner,
            "_retire_slot",
            lambda _slot, *, graceful=False: False,
        )
        release_spawn.set()
        spawn_thread.join(timeout=10)
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


def test_review_returns_immediately_without_prepared_worker_capacity(tmp_path: Path) -> None:
    runner = HookProcessRunner(guard_home=tmp_path, process_limit=1, timeout_seconds=1.0)
    runner.start()
    slot = runner._slots.get_nowait()  # pyright: ignore[reportPrivateUsage]
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
        runner._slots.put_nowait(slot)  # pyright: ignore[reportPrivateUsage]
        runner.close()

    assert elapsed < 0.04
    assert result.payload is None
    assert result.reason_code == "daemon_hook_process_not_ready"


def test_review_worker_wait_respects_outer_deadline(tmp_path: Path) -> None:
    runner = HookProcessRunner(guard_home=tmp_path, process_limit=1, timeout_seconds=1.0)
    runner.start()
    slot = runner._slots.get_nowait()  # pyright: ignore[reportPrivateUsage]
    try:
        started = time.monotonic()
        result = runner.review(
            payload={"hook_event_name": "SessionStart"},
            harness="pi",
            home_dir=tmp_path,
            guard_home=tmp_path,
            workspace=tmp_path,
            hook_env={},
            deadline=time.monotonic() + 0.02,
        )
        elapsed = time.monotonic() - started
    finally:
        runner._slots.put_nowait(slot)  # pyright: ignore[reportPrivateUsage]
        runner.close()

    assert elapsed < 0.2
    assert result.payload is None
    assert result.reason_code == "daemon_hook_process_not_ready"


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
