"""Guard daemon retirement helpers; shared dependencies remain on manager."""

from __future__ import annotations

from . import manager as _manager


def _guard_daemon_start_in_progress(guard_home: _manager.Path) -> bool:
    payload = _manager._load_state(guard_home)
    if not isinstance(payload, dict) or not _manager._guard_daemon_state_matches_current_runtime(payload):
        return False
    pid = payload.get("pid")
    return isinstance(pid, int) and pid > 0 and _manager._guard_daemon_pid_is_running(pid)


def _guard_daemon_pid_is_running(pid: int) -> bool:
    if _manager.os.name == "nt":
        return _manager.windows_process_is_running(pid)
    try:
        _manager.os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def _guard_daemon_parent_pid(pid: int) -> int | None:
    """Return the parent PID for a live process, or ``None`` when it cannot be proven."""

    if pid <= 0:
        return None
    if _manager.os.name == "nt":
        return None
    ps_path = _manager._trusted_posix_ps_path()
    if ps_path is None:
        return None
    output = _manager._bounded_process_query_stdout([ps_path, "-p", str(pid), "-o", "ppid="])
    if output is None:
        return None
    try:
        parent_pid = int(output.strip())
    except ValueError:
        return None
    return parent_pid if parent_pid > 0 else None


def _guard_daemon_pid_is_spawned_launch(pid: int, expected_pid: int) -> bool:
    """Match the launched handle, including a PyInstaller one-file child."""

    if expected_pid <= 0:
        return False
    if pid == expected_pid:
        return True
    return _manager._guard_daemon_parent_pid(pid) == expected_pid and _manager._guard_daemon_pid_is_running(
        expected_pid
    )


def _guard_daemon_pid_is_proven_dead(pid: int) -> bool:
    if _manager.os.name == "nt":
        return _manager.windows_process_liveness(pid) is False
    return not _manager._guard_daemon_pid_is_running(pid)


def _wait_for_guard_daemon_pid_death(pid: int, *, timeout: float = 1.0) -> bool:
    deadline = _manager.time.monotonic() + max(0.0, timeout)
    while _manager.time.monotonic() < deadline:
        if _manager._guard_daemon_pid_is_proven_dead(pid):
            return True
        _manager.time.sleep(_manager.GUARD_DAEMON_POLL_INTERVAL_SECONDS)
    return _manager._guard_daemon_pid_is_proven_dead(pid)


def _guard_daemon_pid_matches_command(pid: int, expected_guard_home: _manager.Path | None = None) -> bool:
    return _manager._guard_daemon_pid_command_identity(pid, expected_guard_home=expected_guard_home) is True


def _guard_daemon_pid_command_identity(
    pid: int,
    *,
    expected_guard_home: _manager.Path | None = None,
) -> bool | None:
    """Classify a PID as the expected daemon, another process, or unresolvable."""

    command = _manager._guard_daemon_command_for_pid(pid)
    if command is None:
        return None
    parts = _manager._split_process_command(command)
    if parts is None:
        return None
    if not _manager._guard_daemon_command_parts_match(parts):
        return False
    if expected_guard_home is None:
        return True
    command_guard_home = _manager._guard_home_from_command_parts(parts)
    if command_guard_home is None:
        return None
    try:
        return command_guard_home.resolve() == expected_guard_home.resolve()
    except OSError:
        return command_guard_home == expected_guard_home


def _guard_daemon_command_for_pid(pid: int) -> str | None:
    if _manager.os.name == "nt":
        return _manager.windows_processes.windows_process_command_line(
            pid,
            max_command_line_bytes=_manager._GUARD_DAEMON_PROCESS_QUERY_OUTPUT_LIMIT_BYTES,
        )
    ps_path = _manager._trusted_posix_ps_path()
    if ps_path is None:
        return None
    output = _manager._bounded_process_query_stdout(
        [ps_path, "-p", str(pid), "-o", "command="],
    )
    if output is None:
        return None
    stdout = output.strip()
    return stdout or None


def _retire_guard_daemon_process(payload: dict[str, object]) -> bool:
    pid = payload.get("pid")
    if not isinstance(pid, int) or pid <= 0:
        return False
    guard_home = payload.get("guard_home")
    expected_guard_home = _manager.Path(guard_home) if isinstance(guard_home, str) and guard_home.strip() else None
    return _manager._retire_guard_daemon_pid(pid, expected_guard_home=expected_guard_home)


def _terminate_spawned_guard_daemon(process: _manager.subprocess.Popen[bytes]) -> bool:
    """Terminate and reap the exact child handle after startup fails."""

    process_stdin = getattr(process, "stdin", None)
    if process_stdin is not None:
        with _manager.suppress(OSError, ValueError):
            process_stdin.close()
    if process.poll() is not None:
        return True
    with _manager.suppress(OSError):
        process.terminate()
    try:
        process.wait(timeout=1.0)
    except _manager.subprocess.TimeoutExpired:
        with _manager.suppress(OSError):
            process.kill()
        try:
            process.wait(timeout=1.0)
        except _manager.subprocess.TimeoutExpired:
            return False
    return process.poll() is not None


def _release_guard_daemon_launch_gate(process: _manager.subprocess.Popen[bytes]) -> None:
    if _manager.os.name != "nt":
        return
    if process.stdin is None:
        raise RuntimeError("Guard daemon launch gate is unavailable.")
    try:
        _ = process.stdin.write(b"1")
        process.stdin.flush()
    except (OSError, ValueError) as error:
        raise RuntimeError("Guard daemon launch gate could not be released.") from error
    finally:
        with _manager.suppress(OSError, ValueError):
            process.stdin.close()


def _retire_guard_daemon_pid(
    pid: int,
    *,
    expected_guard_home: _manager.Path | None = None,
    expected_creation_time: int | None = None,
) -> bool:
    if _manager._guard_daemon_pid_is_proven_dead(pid):
        return True
    if _manager.os.name == "nt" and expected_creation_time is not None:
        return _manager.windows_terminate_process_if_creation_time(pid, expected_creation_time)
    observed_creation_time: int | None = None
    if _manager.os.name == "nt":
        observed_creation_time = _manager.windows_process_creation_time(pid)
        if observed_creation_time is None:
            return False
    if not _manager._guard_daemon_pid_matches_command(pid, expected_guard_home):
        identity = _manager._guard_daemon_pid_command_identity(pid, expected_guard_home=expected_guard_home)
        # The pid is running a different command — not our daemon.
        # There is nothing to kill; return True so the caller clears
        # stale daemon-state.json instead of revisiting it forever.  An
        # unresolvable command fails closed instead of being treated as foreign.
        return identity is False
    if _manager.os.name == "nt":
        assert observed_creation_time is not None
        return _manager.windows_terminate_process_if_creation_time(pid, observed_creation_time)
    try:
        _manager.os.kill(pid, _manager.signal.SIGTERM)
    except ProcessLookupError:
        return True
    except OSError:
        return _manager._guard_daemon_pid_is_proven_dead(pid)
    if _manager._wait_for_guard_daemon_pid_death(pid):
        return True
    sigkill = getattr(_manager.signal, "SIGKILL", None)
    if sigkill is None:
        return False
    try:
        _manager.os.kill(pid, sigkill)
    except ProcessLookupError:
        return True
    except OSError:
        return _manager._guard_daemon_pid_is_proven_dead(pid)
    return _manager._wait_for_guard_daemon_pid_death(pid)


def _wait_for_started_guard_daemon_url(
    guard_home: _manager.Path,
    *,
    timeout: float,
    process: _manager.subprocess.Popen[bytes],
    executable: _manager.Path | None,
) -> str | None:
    if executable is None:
        return _manager._wait_for_guard_daemon_url(
            guard_home,
            timeout=timeout,
            process=process,
        )
    return _manager._wait_for_guard_daemon_url(
        guard_home,
        timeout=timeout,
        process=process,
        require_current_runtime=False,
        expected_pid=process.pid,
    )


def _wait_for_guard_daemon_url(
    guard_home: _manager.Path,
    *,
    timeout: float,
    process: _manager.subprocess.Popen[bytes] | None = None,
    require_current_runtime: bool = True,
    expected_pid: int | None = None,
) -> str | None:
    deadline = _manager.time.monotonic() + timeout
    while _manager.time.monotonic() < deadline:
        url = (
            _manager.load_guard_daemon_url(guard_home)
            if require_current_runtime
            else _manager._live_guard_daemon_url(
                guard_home,
                require_current_runtime=False,
                expected_pid=expected_pid,
            )
        )
        if url is not None:
            return url
        if process is not None and process.poll() is not None:
            return None
        _manager.time.sleep(_manager.GUARD_DAEMON_POLL_INTERVAL_SECONDS)
    return None
