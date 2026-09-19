"""Guard daemon pending launch helpers; shared dependencies remain on manager."""

from __future__ import annotations

from . import manager as _manager


def _pending_launch_path(guard_home: _manager.Path) -> _manager.Path:
    return guard_home / _manager._GUARD_DAEMON_PENDING_LAUNCH_FILE


def _record_guard_daemon_pending_launch(
    guard_home: _manager.Path,
    *,
    process: _manager.subprocess.Popen[bytes],
    port: int,
) -> int | None:
    """Persist a Windows PID identity before a detached daemon may escape its parent."""

    if _manager.os.name != "nt":
        return None
    creation_time = _manager.windows_process_creation_time(process.pid)
    if creation_time is None:
        raise RuntimeError("Guard daemon process identity could not be recorded.")
    _manager._ensure_private_directory(guard_home)
    with _manager._guard_daemon_state_write_lock(guard_home):
        discovery_key = _manager.ensure_daemon_discovery_key(guard_home)
        pending = _manager.authenticate_daemon_state(
            {
                "state_kind": "daemon_launch_pending",
                "guard_home": str(guard_home.resolve()),
                "pid": process.pid,
                "port": port,
                "process_creation_time": creation_time,
            },
            discovery_key=discovery_key,
        )
        _manager._write_private_atomic_text(
            _manager._pending_launch_path(guard_home),
            _manager.json.dumps(pending, sort_keys=True),
        )
    return creation_time


def load_authenticated_guard_daemon_pending_launch(guard_home: _manager.Path) -> dict[str, object] | None:
    """Load one signed pending-launch PID identity from a private regular file."""

    if _manager.os.name != "nt":
        return None
    raw_payload = _manager.read_private_regular_text(
        _manager._pending_launch_path(guard_home),
        max_bytes=_manager._GUARD_DAEMON_PENDING_LAUNCH_MAX_BYTES,
        require_private_parent=True,
    )
    if raw_payload is None:
        return None
    try:
        payload = _manager.json.loads(raw_payload)
    except _manager.json.JSONDecodeError:
        return None
    discovery_key = _manager.load_daemon_discovery_key(guard_home)
    if (
        discovery_key is None
        or not isinstance(payload, dict)
        or not _manager.verify_daemon_state(payload, discovery_key=discovery_key)
        or payload.get("state_kind") != "daemon_launch_pending"
    ):
        return None
    pid = payload.get("pid")
    port = payload.get("port")
    creation_time = payload.get("process_creation_time")
    payload_guard_home = payload.get("guard_home")
    if (
        type(pid) is not int
        or pid <= 0
        or type(port) is not int
        or not 0 < port <= 65535
        or type(creation_time) is not int
        or creation_time <= 0
        or not isinstance(payload_guard_home, str)
    ):
        return None
    try:
        if _manager.Path(payload_guard_home).resolve() != guard_home.resolve():
            return None
    except OSError:
        return None
    return payload


def _clear_guard_daemon_pending_launch_if_current(
    guard_home: _manager.Path,
    *,
    pid: int,
    creation_time: int | None,
) -> bool:
    if _manager.os.name != "nt" or creation_time is None:
        return True
    with _manager._guard_daemon_state_write_lock(guard_home):
        pending = _manager.load_authenticated_guard_daemon_pending_launch(guard_home)
        if pending is None or pending.get("pid") != pid or pending.get("process_creation_time") != creation_time:
            return False
        _manager._write_private_atomic_text(_manager._pending_launch_path(guard_home), "{}")
        return True


def _clear_spawned_guard_daemon_pending_launch(
    guard_home: _manager.Path,
    *,
    process: _manager.subprocess.Popen[bytes],
    creation_time: int | None,
) -> bool:
    if creation_time is None:
        return True
    return _manager._clear_guard_daemon_pending_launch_if_current(
        guard_home,
        pid=process.pid,
        creation_time=creation_time,
    )


def _guard_daemon_pending_launch_is_active(guard_home: _manager.Path) -> bool:
    pending = _manager.load_authenticated_guard_daemon_pending_launch(guard_home)
    if pending is None:
        return False
    pid = pending.get("pid")
    creation_time = pending.get("process_creation_time")
    if type(pid) is not int or type(creation_time) is not int:
        return False
    actual_creation_time = _manager.windows_process_creation_time(pid)
    if actual_creation_time != creation_time:
        if actual_creation_time is not None or not _manager._guard_daemon_pid_is_running(pid):
            _manager._clear_guard_daemon_pending_launch_if_current(
                guard_home,
                pid=pid,
                creation_time=creation_time,
            )
        return False
    return _manager._guard_daemon_pid_is_running(pid)


def _guard_daemon_pending_launch_state_is_resolved(guard_home: _manager.Path) -> bool:
    if _manager.os.name != "nt":
        return True
    path = _manager._pending_launch_path(guard_home)
    if not path.is_file():
        return True
    pending = _manager.load_authenticated_guard_daemon_pending_launch(guard_home)
    if pending is not None:
        if _manager._guard_daemon_pending_launch_is_active(guard_home):
            return False
        pending = _manager.load_authenticated_guard_daemon_pending_launch(guard_home)
        if pending is not None:
            return False
    return _manager._daemon_lifecycle_artifact_is_exact_tombstone(path)


def _auth_token_path(guard_home: _manager.Path) -> _manager.Path:
    return guard_home / "daemon-auth-token"


def _private_daemon_file_is_valid(path: _manager.Path) -> bool:
    return _manager.private_regular_file_is_valid(path, require_private_parent=True)


def _remove_invalid_daemon_discovery_key(guard_home: _manager.Path) -> bool:
    if _manager.load_daemon_discovery_key(guard_home) is not None:
        return False
    key_path = _manager.daemon_discovery_key_path(guard_home)
    try:
        key_path.unlink()
    except FileNotFoundError:
        return False
    return True


def _ensure_private_directory(path: _manager.Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    _manager._set_private_mode(path, _manager._GUARD_DAEMON_PRIVATE_DIR_MODE)


def _write_private_text(path: _manager.Path, text: str) -> None:
    descriptor = _manager.os.open(
        path, _manager.os.O_WRONLY | _manager.os.O_CREAT | _manager.os.O_TRUNC, _manager._GUARD_DAEMON_PRIVATE_FILE_MODE
    )
    if _manager.os.name != "nt" and hasattr(_manager.os, "fchmod"):
        with _manager.suppress(OSError):
            _manager.os.fchmod(descriptor, _manager._GUARD_DAEMON_PRIVATE_FILE_MODE)
    with _manager.os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(text)
    _manager._set_private_mode(path, _manager._GUARD_DAEMON_PRIVATE_FILE_MODE)


def _write_private_atomic_text(path: _manager.Path, text: str) -> None:
    descriptor, temporary_name = _manager.tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = _manager.Path(temporary_name)
    try:
        if _manager.os.name != "nt" and hasattr(_manager.os, "fchmod"):
            _manager.os.fchmod(descriptor, _manager._GUARD_DAEMON_PRIVATE_FILE_MODE)
        with _manager.os.fdopen(descriptor, "w", encoding="utf-8", closefd=False) as handle:
            handle.write(text)
            handle.flush()
            _manager.os.fsync(handle.fileno())
        _manager.os.close(descriptor)
        descriptor = -1
        _manager.os.replace(temporary_path, path)
        _manager._set_private_mode(path, _manager._GUARD_DAEMON_PRIVATE_FILE_MODE)
    finally:
        if descriptor >= 0:
            _manager.os.close(descriptor)
        with _manager.suppress(OSError):
            temporary_path.unlink()


def _set_private_mode(path: _manager.Path, mode: int) -> None:
    if _manager.os.name == "nt":
        return
    try:
        _manager.os.chmod(path, mode)
    except OSError:
        return
