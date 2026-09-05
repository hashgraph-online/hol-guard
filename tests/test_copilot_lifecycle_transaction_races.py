"""Deterministic Copilot lifecycle transaction failure and interleaving coverage."""

from __future__ import annotations

import errno
import json
import multiprocessing
import sys
from multiprocessing import Event as ProcessEvent
from multiprocessing import Queue
from pathlib import Path
from threading import Event, Lock, Thread
from types import SimpleNamespace
from typing import BinaryIO

import pytest

from codex_plugin_scanner.guard.adapters import copilot_state_paths
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.adapters.copilot import CopilotHarnessAdapter


def _context(tmp_path: Path) -> HarnessContext:
    return HarnessContext(
        home_dir=tmp_path / "home",
        workspace_dir=None,
        guard_home=tmp_path / "guard-home",
    )


def _target(context: HarnessContext) -> Path:
    return context.home_dir / ".copilot" / "mcp-config.json"


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _attempt_lifecycle_lock_in_process(
    home_dir: str,
    guard_home: str,
    target_path: str,
    timeout_seconds: float,
    started: ProcessEvent,
    result_queue: Queue,
) -> None:
    """Try one lifecycle lock in a child process and report its bounded result."""

    copilot_state_paths._LIFECYCLE_LOCK_TIMEOUT_SECONDS = timeout_seconds  # pyright: ignore[reportPrivateUsage]
    copilot_state_paths._LIFECYCLE_LOCK_POLL_SECONDS = min(timeout_seconds / 5, 0.02)  # pyright: ignore[reportPrivateUsage]
    context = HarnessContext(home_dir=Path(home_dir), workspace_dir=None, guard_home=Path(guard_home))
    started.set()
    try:
        with copilot_state_paths.copilot_lifecycle_lock(context, Path(target_path)):
            result_queue.put(("acquired", ""))
    except BaseException as error:
        result_queue.put((type(error).__name__, str(error)))


class _WindowsLockError(OSError):
    def __init__(self, *, errno_value: int, winerror: int | None) -> None:
        super().__init__(errno_value, "simulated Windows lock failure")
        if winerror is not None:
            self.winerror = winerror


def test_corrupt_authenticated_backup_fails_before_target_mutation(tmp_path: Path) -> None:
    context = _context(tmp_path)
    adapter = CopilotHarnessAdapter()
    target = _target(context)
    original = {"mcpServers": {"user": {"command": "user-command"}}}
    _write_json(target, original)

    install_payload = adapter.install(context)
    backup_path = Path(str(install_payload["backup_path"]))
    state_path = Path(str(install_payload["state_path"]))
    target_before = target.read_bytes()
    state_before = state_path.read_bytes()
    backup_path.write_text("{corrupt\n", encoding="utf-8")

    with pytest.raises(RuntimeError, match="backup"):
        adapter.install(context)

    assert target.read_bytes() == target_before
    assert backup_path.read_text(encoding="utf-8") == "{corrupt\n"
    assert state_path.read_bytes() == state_before


def test_concurrent_installs_preserve_original_backup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context(tmp_path)
    target = _target(context)
    original = {"mcpServers": {"user": {"command": "user-command"}}}
    _write_json(target, original)
    original_text = target.read_text(encoding="utf-8")

    first_state_entered = Event()
    release_first_state = Event()
    counters_lock = Lock()
    state_call_count = 0
    real_write_state = copilot_state_paths.write_copilot_state
    real_try_lock = copilot_state_paths._try_copilot_lifecycle_lock  # pyright: ignore[reportPrivateUsage]

    def pause_first_state(*args: object, **kwargs: object) -> None:
        nonlocal state_call_count
        with counters_lock:
            state_call_count += 1
            call_number = state_call_count
        if call_number == 1:
            first_state_entered.set()
            if not release_first_state.wait(timeout=5):
                raise RuntimeError("timed out waiting to release first Copilot install")
        real_write_state(*args, **kwargs)

    lock_contention_observed = Event()
    lock_attempts = 0

    def observe_lock_attempt(handle: BinaryIO) -> bool:
        nonlocal lock_attempts
        acquired = real_try_lock(handle)
        with counters_lock:
            lock_attempts += 1
            if not acquired:
                lock_contention_observed.set()
        return acquired

    monkeypatch.setattr(copilot_state_paths, "write_copilot_state", pause_first_state)
    monkeypatch.setattr(copilot_state_paths, "_try_copilot_lifecycle_lock", observe_lock_attempt)

    first_errors: list[BaseException] = []
    second_errors: list[BaseException] = []
    second_started = Event()

    def run_install(adapter: CopilotHarnessAdapter, errors: list[BaseException], started: Event | None = None) -> None:
        if started is not None:
            started.set()
        try:
            adapter.install(context)
        except BaseException as exc:  # pragma: no cover - reported by assertions below
            errors.append(exc)

    first_thread = Thread(target=run_install, args=(CopilotHarnessAdapter(), first_errors))
    second_thread = Thread(target=run_install, args=(CopilotHarnessAdapter(), second_errors, second_started))
    first_started = False
    second_started_flag = False
    try:
        first_thread.start()
        first_started = True
        assert first_state_entered.wait(timeout=5)

        second_thread.start()
        second_started_flag = True
        assert second_started.wait(timeout=5)
        # The first install is paused while holding the lifecycle locks. The
        # second install must visibly contend before the first transaction is
        # released; this is stronger than merely waiting for a later outcome.
        assert lock_contention_observed.wait(timeout=2)
        with counters_lock:
            assert lock_attempts >= 1
    finally:
        release_first_state.set()
        if first_started:
            first_thread.join(timeout=10)
        if second_started_flag:
            second_thread.join(timeout=10)

    assert not first_thread.is_alive()
    assert not second_thread.is_alive()
    assert first_errors == []
    assert second_errors == []

    CopilotHarnessAdapter().uninstall(context)

    assert target.read_text(encoding="utf-8") == original_text
    assert not list((context.guard_home / "managed" / "copilot").glob("*.backup.json"))
    assert not list((context.guard_home / "managed" / "copilot").glob("*.state.json"))


def test_competing_target_write_survives_state_failure_with_recovery_backup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context(tmp_path)
    adapter = CopilotHarnessAdapter()
    target = _target(context)
    original = {"mcpServers": {"user": {"command": "user-command"}}}
    competing = {"mcpServers": {"competing": {"command": "competing-command"}}}
    _write_json(target, original)
    original_text = target.read_text(encoding="utf-8")
    competing_text = json.dumps(competing, indent=2) + "\n"
    backup_path = adapter._backup_path(target, context)
    state_path = adapter._state_path(target, context)
    real_write = copilot_state_paths.write_text_at_authorized_path

    def fail_state_persistence(*_args: object, **_kwargs: object) -> None:
        real_write(target, competing_text)
        raise OSError("simulated state persistence failure")

    monkeypatch.setattr(copilot_state_paths, "write_copilot_state", fail_state_persistence)

    with pytest.raises(OSError, match="state persistence"):
        adapter.install(context)

    assert target.read_text(encoding="utf-8") == competing_text
    backup_payload = json.loads(backup_path.read_text(encoding="utf-8"))
    assert backup_payload == {"existed": True, "content": original_text}
    assert state_path.exists() is False


def test_copilot_lifecycle_lock_times_out_across_processes(tmp_path: Path) -> None:
    context = _context(tmp_path)
    target = _target(context)
    target.parent.mkdir(parents=True, exist_ok=True)
    process_context = multiprocessing.get_context("spawn")
    started = process_context.Event()
    results = process_context.Queue()
    child = process_context.Process(
        target=_attempt_lifecycle_lock_in_process,
        args=(
            str(context.home_dir),
            str(context.guard_home),
            str(target),
            0.2,
            started,
            results,
        ),
    )

    with copilot_state_paths.copilot_lifecycle_lock(context, target):
        child.start()
        try:
            assert started.wait(timeout=5)
            child.join(timeout=5)
            assert not child.is_alive()
            assert child.exitcode == 0
            assert results.get(timeout=2) == ("TimeoutError", "Timed out waiting for the Copilot lifecycle lock.")
        finally:
            if child.is_alive():
                child.terminate()
            child.join(timeout=5)


def test_copilot_lifecycle_lock_wraps_acquire_error_and_closes_descriptor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = _context(tmp_path)
    target = _target(context)

    def fail_to_acquire(_handle: BinaryIO) -> bool:
        raise OSError("simulated lock acquisition failure")

    monkeypatch.setattr(copilot_state_paths, "_try_copilot_lifecycle_lock", fail_to_acquire)
    with (
        pytest.raises(OSError, match="Unable to acquire the Copilot lifecycle lock"),
        copilot_state_paths.copilot_lifecycle_lock(context, target),
    ):
        pytest.fail("lock acquisition should fail")

    monkeypatch.setattr(copilot_state_paths, "_try_copilot_lifecycle_lock", lambda _handle: True)
    with copilot_state_paths.copilot_lifecycle_lock(context, target):
        pass


@pytest.mark.parametrize(
    ("winerror", "errno_value", "expected"),
    [
        (None, 0, True),
        (32, errno.EACCES, False),
        (33, errno.EAGAIN, False),
        (None, errno.EACCES, False),
        (None, errno.EDEADLK, False),
        (None, errno.EINVAL, "raise"),
    ],
)
def test_windows_lifecycle_lock_contention_and_errors_are_classified(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    winerror: int | None,
    errno_value: int,
    expected: bool | str,
) -> None:
    lock_path = tmp_path / "lifecycle.lock"
    fake_msvcrt = SimpleNamespace(LK_NBLCK=1)

    def locking(_fd: int, _mode: int, _size: int) -> None:
        if winerror is not None or errno_value != 0:
            raise _WindowsLockError(errno_value=errno_value, winerror=winerror)

    fake_msvcrt.locking = locking
    monkeypatch.setattr(copilot_state_paths.os, "name", "nt")
    monkeypatch.setitem(sys.modules, "msvcrt", fake_msvcrt)

    with lock_path.open("a+b") as handle:
        if expected == "raise":
            with pytest.raises(OSError, match="simulated Windows lock failure"):
                copilot_state_paths._try_copilot_lifecycle_lock(handle)  # pyright: ignore[reportPrivateUsage]
        else:
            assert copilot_state_paths._try_copilot_lifecycle_lock(handle) is expected  # pyright: ignore[reportPrivateUsage]
