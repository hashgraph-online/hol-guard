"""Bounded, single-owner recovery for Guard daemon hook failures."""

from __future__ import annotations

import os
import signal
import subprocess
import time
from contextlib import suppress
from pathlib import Path


def _manager():
    from . import manager

    return manager


def guard_recovery_is_disabled(guard_home: Path) -> bool:
    """Do not restart a daemon when local protection is explicitly off."""

    try:
        from ..config import load_guard_config
        from ..protection_posture import protection_is_off

        config = load_guard_config(guard_home)
    except Exception as error:
        # Invalid or unavailable config must not suppress a valid recovery.
        del error
        return False
    return protection_is_off(posture=config.protection_posture, mode=config.mode)


def recover_guard_daemon_after_hook_failure(
    guard_home: Path,
    *,
    home_dir: Path | None,
    failure_kind: str,
    recovery_lock_timeout_seconds: float | None,
) -> str:
    manager = _manager()
    _validate_failure_kind(failure_kind)
    if manager._guard_recovery_is_disabled(guard_home):
        return _disabled_recovery_url(manager, guard_home)
    with suppress(Exception):
        manager.record_daemon_lifecycle_event(
            guard_home,
            event="recovery_requested",
            reason=failure_kind,
        )
    deadline = _recovery_deadline(recovery_lock_timeout_seconds)
    with _recovery_lock(manager, guard_home, recovery_lock_timeout_seconds):
        current_url = _existing_recovery_url(manager, guard_home, deadline)
        if current_url is not None:
            return current_url
        if manager._guard_recovery_is_disabled(guard_home):
            return _disabled_recovery_url(manager, guard_home)
        return _ensure_recovered(
            manager,
            guard_home,
            home_dir=home_dir,
            deadline=deadline,
        )


def _validate_failure_kind(failure_kind: str) -> None:
    if failure_kind not in {
        "authenticated-control-plane-failure",
        "overload",
        "transport-failure",
    }:
        raise ValueError(f"Unsupported Guard daemon hook failure kind: {failure_kind}")


def _recovery_deadline(timeout_seconds: float | None) -> float | None:
    if timeout_seconds is None:
        return None
    return time.monotonic() + max(0.0, timeout_seconds)


def _recovery_lock(manager, guard_home: Path, timeout_seconds: float | None):
    if timeout_seconds is None:
        return manager._guard_daemon_recovery_lock(guard_home)
    return manager._guard_daemon_recovery_lock(guard_home, timeout_seconds=timeout_seconds)


def _existing_recovery_url(manager, guard_home: Path, deadline: float | None) -> str | None:
    start_lock = (
        manager._guard_daemon_start_lock(guard_home)
        if deadline is None
        else manager._guard_daemon_start_lock(guard_home, deadline=deadline)
    )
    with start_lock:
        state = manager.load_authenticated_daemon_state(guard_home)
        _record_dead_process(manager, guard_home, state)
        current_url = manager.load_guard_daemon_url(guard_home)
        live_process_url = manager._authenticated_live_current_daemon_url(guard_home, state)
        return current_url or live_process_url


def authenticated_live_current_daemon_url(guard_home: Path, state: dict[str, object] | None) -> str | None:
    """Locate an authenticated current process for overload preservation."""

    manager = _manager()
    if not isinstance(state, dict) or not manager._guard_daemon_state_matches_current_runtime(state):
        return None
    pid = state.get("pid")
    port = state.get("port")
    if (
        not isinstance(pid, int)
        or pid <= 0
        or not isinstance(port, int)
        or not 1 <= port <= 65_535
        or not manager._guard_daemon_pid_is_running(pid)
        or not manager._guard_daemon_pid_matches_command(pid, expected_guard_home=guard_home)
    ):
        return None
    return f"http://127.0.0.1:{port}"


def _record_dead_process(manager, guard_home: Path, state: object) -> None:
    if not isinstance(state, dict):
        return
    state_pid = state.get("pid")
    if not isinstance(state_pid, int) or state_pid <= 0 or manager._guard_daemon_pid_is_running(state_pid):
        return
    state_id = state.get("state_id")
    with suppress(Exception):
        manager.record_daemon_lifecycle_event(
            guard_home,
            event="death_observed",
            reason="process_missing",
            pid=state_pid,
            session_id=state_id if isinstance(state_id, str) else None,
        )


def _disabled_recovery_url(manager, guard_home: Path) -> str:
    current_url = manager.load_guard_daemon_url(guard_home)
    if current_url is not None:
        return current_url
    raise RuntimeError("Guard daemon recovery is disabled by local protection posture.")


def _ensure_recovered(
    manager,
    guard_home: Path,
    *,
    home_dir: Path | None,
    deadline: float | None,
) -> str:
    remaining = None if deadline is None else max(0.0, deadline - time.monotonic())
    if remaining is not None and remaining <= 0:
        raise RuntimeError("Guard daemon recovery exceeded its bounded worker lifetime.")
    options: dict[str, object] = {"home_dir": home_dir}
    if os.name == "nt":
        options["allow_windows_job_breakaway"] = True
    if remaining is not None:
        options["start_timeout"] = remaining
    recovered_url = manager.ensure_guard_daemon(guard_home, **options)
    try:
        _ = manager.publish_approval_center_locator(guard_home, recovered_url)
    except (OSError, RuntimeError):
        with suppress(Exception):
            manager.record_daemon_lifecycle_event(
                guard_home,
                event="locator_publish_failed",
                reason="recovery",
            )
    return recovered_url


def schedule_guard_daemon_recovery(
    guard_home: Path,
    *,
    home_dir: Path | None,
    failure_kind: str,
    executable: Path | None,
) -> None:
    manager = _manager()
    _validate_failure_kind(failure_kind)
    if manager._guard_recovery_is_disabled(guard_home):
        return
    try:
        recovery_token = manager._claim_guard_daemon_recovery_reservation(guard_home)
    except (OSError, RuntimeError, ValueError):
        return
    if recovery_token is None:
        return
    try:
        trusted_home = manager._trusted_daemon_home(home_dir)
        command = _recovery_command(manager, guard_home, trusted_home, failure_kind, recovery_token, executable)
        launcher_env = manager._daemon_launcher_env(
            home_dir=trusted_home,
            guard_home=guard_home,
            executable=executable,
        )
        process = _spawn_recovery_worker(manager, command, trusted_home, launcher_env)
        process_pid = getattr(process, "pid", None)
        if type(process_pid) is int and process_pid > 0:
            _bind_or_contain(manager, guard_home, recovery_token, process, process_pid)
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError):
        with suppress(OSError, RuntimeError, ValueError):
            manager.clear_guard_daemon_recovery_reservation(guard_home, token=recovery_token)


def _recovery_command(manager, guard_home, trusted_home, failure_kind, token, executable):
    if bool(getattr(manager.sys, "frozen", False)) or executable is not None:
        from ..frozen_runtime_commands import frozen_daemon_recovery_worker_command

        recovery_executable = executable or manager._trusted_daemon_interpreter()
        return list(
            frozen_daemon_recovery_worker_command(
                guard_home,
                trusted_home,
                failure_kind,
                token,
                executable=str(recovery_executable),
            )
        )
    return manager._isolated_python_module_command(
        "codex_plugin_scanner.guard.daemon.recovery_worker",
        manager._trusted_daemon_import_paths(),
        [str(guard_home), str(trusted_home), failure_kind, token],
    )


def _spawn_recovery_worker(manager, command, trusted_home, launcher_env):
    if os.name == "nt":
        return subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=trusted_home,
            env=launcher_env,
            creationflags=manager._windows_daemon_creation_flags(allow_job_breakaway=True),
        )
    return subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        cwd=trusted_home,
        env=launcher_env,
        start_new_session=True,
    )


def _bind_or_contain(manager, guard_home, token, process, process_pid) -> None:
    process_creation_time = manager.windows_process_creation_time(process_pid) if os.name == "nt" else None
    try:
        bound = manager._bind_guard_daemon_recovery_reservation(
            guard_home,
            token=token,
            pid=process_pid,
            process_creation_time=process_creation_time,
        )
    except Exception:
        # A reservation write/query failure must never leave the detached child running.
        bound = False
    if not bound:
        manager._terminate_recovery_worker(process)
        with suppress(OSError, RuntimeError, ValueError):
            manager.clear_guard_daemon_recovery_reservation(guard_home, token=token)


def terminate_recovery_worker(process: subprocess.Popen[bytes]) -> bool:
    """Contain a recovery worker whose reservation could not be bound."""

    if process.poll() is not None:
        return True
    if os.name != "nt":
        with suppress(OSError, ProcessLookupError):
            os.killpg(process.pid, signal.SIGTERM)
    else:
        with suppress(OSError, ProcessLookupError):
            process.terminate()
    try:
        process.wait(timeout=0.25)
    except subprocess.TimeoutExpired:
        if os.name != "nt":
            with suppress(OSError, ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
        else:
            with suppress(OSError, ProcessLookupError):
                process.kill()
        with suppress(subprocess.TimeoutExpired):
            process.wait(timeout=0.25)
    return process.poll() is not None


__all__ = [
    "authenticated_live_current_daemon_url",
    "guard_recovery_is_disabled",
    "recover_guard_daemon_after_hook_failure",
    "schedule_guard_daemon_recovery",
    "terminate_recovery_worker",
]
