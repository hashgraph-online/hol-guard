"""Guard daemon process query helpers; shared dependencies remain on manager."""

from __future__ import annotations

from pathlib import Path

from . import manager as _manager


def _spawn_bounded_process_query(command: list[str]) -> _manager.subprocess.Popen[bytes]:
    child_environment = _manager._process_query_environment(command)
    if _manager.os.name == "nt":
        return _manager.subprocess.Popen(
            command,
            stdin=_manager.subprocess.DEVNULL,
            stdout=_manager.subprocess.PIPE,
            stderr=_manager.subprocess.DEVNULL,
            bufsize=0,
            creationflags=_manager.subprocess.CREATE_NEW_PROCESS_GROUP,
            env=child_environment,
        )
    return _manager.subprocess.Popen(
        command,
        stdin=_manager.subprocess.DEVNULL,
        stdout=_manager.subprocess.PIPE,
        stderr=_manager.subprocess.DEVNULL,
        bufsize=0,
        start_new_session=True,
        env=child_environment,
    )


def _process_query_environment(command: list[str]) -> dict[str, str]:
    """Return an environment that cannot redirect trusted process-query tools."""

    if _manager.os.name != "nt":
        return {"LANG": "C", "LC_ALL": "C"}
    if not command:
        return {}
    system_directory = _manager.ntpath.dirname(_manager.ntpath.dirname(_manager.ntpath.dirname(command[0])))
    windows_directory = _manager.ntpath.dirname(system_directory)
    return {
        "ComSpec": _manager.ntpath.join(system_directory, "cmd.exe"),
        "PATH": system_directory,
        "SystemRoot": windows_directory,
        "WINDIR": windows_directory,
    }


def _trusted_posix_ps_path() -> str | None:
    """Resolve ``ps`` only from fixed operating-system locations."""

    if _manager.os.name == "nt":
        return None
    for raw_path in _manager._GUARD_DAEMON_POSIX_PS_PATHS:
        candidate = _manager.Path(raw_path)
        try:
            resolved = candidate.resolve(strict=True)
            metadata = resolved.stat()
        except (OSError, RuntimeError):
            continue
        if _manager.stat.S_ISREG(metadata.st_mode) and _manager.os.access(resolved, _manager.os.X_OK):
            return str(resolved)
    return None


def _linux_proc_process_entries(proc_root: _manager.Path = Path("/proc")) -> list[tuple[int, str]] | None:
    """Read a bounded process inventory from Linux procfs without requiring procps."""

    entries: list[tuple[int, str]] = []
    remaining_bytes = _manager._GUARD_DAEMON_PROCESS_QUERY_OUTPUT_LIMIT_BYTES
    try:
        process_dirs = proc_root.iterdir()
        for process_dir in process_dirs:
            if not process_dir.name.isdigit():
                continue
            pid = int(process_dir.name)
            if pid <= 0:
                continue
            try:
                with (process_dir / "cmdline").open("rb") as stream:
                    raw_command = stream.read(remaining_bytes + 1)
            except FileNotFoundError:
                continue
            except OSError:
                return None
            if len(raw_command) > remaining_bytes:
                return None
            remaining_bytes -= len(raw_command)
            if not raw_command:
                continue
            command = raw_command.rstrip(b"\0").replace(b"\0", b" ").decode("utf-8", errors="replace").strip()
            if command:
                entries.append((pid, command))
    except OSError:
        return None
    return entries


def _terminate_bounded_process_query(process: _manager.subprocess.Popen[bytes]) -> None:
    if _manager.os.name == "nt":
        with _manager.suppress(OSError):
            process.terminate()
    else:
        with _manager.suppress(OSError):
            _manager.os.killpg(process.pid, _manager.signal.SIGTERM)
    with _manager.suppress(_manager.subprocess.TimeoutExpired):
        _ = process.wait(timeout=_manager._GUARD_DAEMON_PROCESS_QUERY_TERMINATE_GRACE_SECONDS)
    if process.poll() is not None:
        return
    if _manager.os.name == "nt":
        with _manager.suppress(OSError):
            process.kill()
    else:
        with _manager.suppress(OSError):
            _manager.os.killpg(process.pid, _manager.signal.SIGKILL)
    with _manager.suppress(_manager.subprocess.TimeoutExpired):
        _ = process.wait(timeout=_manager._GUARD_DAEMON_PROCESS_QUERY_TERMINATE_GRACE_SECONDS)


def _capture_bounded_process_query_stdout(
    stream: _manager.BinaryIO,
    captured: bytearray,
    output_limit_bytes: int,
    overflow: _manager.threading.Event,
    errors: list[OSError | ValueError],
) -> None:
    try:
        while True:
            remaining = output_limit_bytes - len(captured)
            chunk = stream.read(min(64 * 1024, remaining + 1))
            if not chunk:
                return
            if len(chunk) > remaining:
                captured.extend(chunk[:remaining])
                overflow.set()
                return
            captured.extend(chunk)
    except (OSError, ValueError) as error:
        errors.append(error)
    finally:
        with _manager.suppress(OSError, ValueError):
            stream.close()


def _bounded_process_query_stdout(
    command: list[str],
    *,
    timeout_seconds: float = _manager._GUARD_DAEMON_PROCESS_QUERY_TIMEOUT_SECONDS,
    output_limit_bytes: int = _manager._GUARD_DAEMON_PROCESS_QUERY_OUTPUT_LIMIT_BYTES,
) -> str | None:
    """Return bounded child stdout, or ``None`` after failure, timeout, or overflow."""

    if timeout_seconds <= 0 or output_limit_bytes < 0:
        return None
    try:
        process = _manager._spawn_bounded_process_query(command)
    except (OSError, _manager.subprocess.SubprocessError, ValueError):
        return None
    if process.stdout is None:
        _manager._terminate_bounded_process_query(process)
        return None

    captured = bytearray()
    overflow = _manager.threading.Event()
    errors: list[OSError | ValueError] = []
    reader = _manager.threading.Thread(
        target=_manager._capture_bounded_process_query_stdout,
        args=(process.stdout, captured, output_limit_bytes, overflow, errors),
        name="guard-daemon-process-query",
        daemon=True,
    )
    timed_out = False
    reader_started = False
    deadline = _manager.time.monotonic() + timeout_seconds
    try:
        reader.start()
        reader_started = True
        while process.poll() is None:
            remaining = deadline - _manager.time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            if overflow.wait(min(_manager._GUARD_DAEMON_PROCESS_QUERY_MONITOR_INTERVAL_SECONDS, remaining)):
                break
        if process.poll() is not None and reader.is_alive():
            reader.join(timeout=_manager._GUARD_DAEMON_PROCESS_QUERY_TERMINATE_GRACE_SECONDS)
    except BaseException:
        _manager._terminate_bounded_process_query(process)
        raise
    finally:
        if timed_out or overflow.is_set() or process.poll() is None or reader.is_alive():
            _manager._terminate_bounded_process_query(process)
        if reader_started:
            reader.join(timeout=_manager._GUARD_DAEMON_PROCESS_QUERY_TERMINATE_GRACE_SECONDS)
            if reader.is_alive():
                with _manager.suppress(OSError, ValueError):
                    process.stdout.close()
                reader.join(timeout=_manager._GUARD_DAEMON_PROCESS_QUERY_TERMINATE_GRACE_SECONDS)

    if timed_out or overflow.is_set() or errors or reader.is_alive():
        return None
    try:
        returncode = process.wait(timeout=_manager._GUARD_DAEMON_PROCESS_QUERY_TERMINATE_GRACE_SECONDS)
    except _manager.subprocess.TimeoutExpired:
        _manager._terminate_bounded_process_query(process)
        return None
    if returncode != 0:
        return None
    try:
        return bytes(captured).decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None


def _running_ephemeral_guard_daemon_processes() -> list[tuple[int, _manager.Path, float]]:
    if _manager.os.name == "nt":
        return []
    ps_path = _manager._trusted_posix_ps_path()
    if ps_path is None:
        return []
    output = _manager._bounded_process_query_stdout([ps_path, "-axo", "pid=,etime=,command="])
    if output is None:
        return []
    processes: list[tuple[int, _manager.Path, float]] = []
    for line in output.splitlines():
        match = _manager.re.match(r"^\s*(\d+)\s+(\S+)\s+(.*)$", line)
        if match is None:
            continue
        pid = int(match.group(1))
        elapsed_seconds = _manager._elapsed_seconds_from_ps(match.group(2))
        command = match.group(3).strip()
        if not _manager._guard_daemon_command_matches(command):
            continue
        guard_home = _manager._guard_home_from_command(command)
        if guard_home is None or not _manager._guard_home_is_ephemeral(guard_home):
            continue
        processes.append((pid, guard_home, elapsed_seconds))
    return processes


def _elapsed_seconds_from_ps(value: str) -> float:
    trimmed = value.strip()
    if not trimmed:
        return 0.0
    day_split = trimmed.split("-", 1)
    days = 0
    time_part = trimmed
    if len(day_split) == 2:
        days = int(day_split[0])
        time_part = day_split[1]
    fields = [int(field) for field in time_part.split(":")]
    if len(fields) == 3:
        hours, minutes, seconds = fields
    elif len(fields) == 2:
        hours = 0
        minutes, seconds = fields
    else:
        hours = 0
        minutes = 0
        seconds = fields[0]
    return float((((days * 24) + hours) * 60 + minutes) * 60 + seconds)
