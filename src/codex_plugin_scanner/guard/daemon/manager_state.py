"""Guard daemon state helpers; shared dependencies remain on manager."""

from __future__ import annotations

from . import manager as _manager


def write_guard_daemon_state(
    guard_home: _manager.Path,
    port: int,
    auth_token: str,
    *,
    pid: int | None = None,
    write_auth_token: bool = True,
    host: str = "127.0.0.1",
    state_id: str | None = None,
    started_at: str | None = None,
    trust_status: dict[str, object] | None = None,
) -> None:
    state_path = _manager._state_path(guard_home)
    _manager._ensure_private_directory(state_path.parent)
    with _manager._guard_daemon_state_write_lock(guard_home):
        discovery_key = _manager.ensure_daemon_discovery_key(guard_home)
        state_payload: dict[str, object] = {
            "guard_home": str(guard_home.resolve()),
            "host": host,
            "port": port,
            "compatibility_version": _manager.GUARD_DAEMON_COMPATIBILITY_VERSION,
            "package_version": _manager.__version__,
            "source_root": _manager._current_guard_daemon_source_root(),
            "runtime_fingerprint": _manager._current_guard_daemon_runtime_fingerprint(),
            "pid": pid if isinstance(pid, int) and pid > 0 else _manager.os.getpid(),
            "started_at": started_at or _manager.datetime.now(_manager.timezone.utc).isoformat(),
            "state_id": state_id or _manager.secrets.token_hex(16),
            "auth_token_id": _manager.hashlib.sha256(auth_token.encode("utf-8")).hexdigest(),
        }
        if trust_status is not None:
            state_payload["trust_status"] = trust_status
        daemon_state = _manager.authenticate_daemon_state(
            state_payload,
            discovery_key=discovery_key,
        )
        if write_auth_token:
            _manager._write_private_atomic_text(_manager._auth_token_path(guard_home), auth_token)
        _manager._write_private_atomic_text(
            state_path,
            _manager.json.dumps(daemon_state, indent=2),
        )


def clear_guard_daemon_state(guard_home: _manager.Path) -> None:
    state_path = _manager._state_path(guard_home)
    _manager._ensure_private_directory(state_path.parent)
    with _manager._guard_daemon_state_write_lock(guard_home):
        _manager._write_private_atomic_text(state_path, "{}")


def clear_guard_daemon_state_if_current(guard_home: _manager.Path, *, pid: int, port: int) -> bool:
    with _manager._guard_daemon_start_lock(guard_home):
        return _manager._clear_guard_daemon_state_if_current_unlocked(guard_home, pid=pid, port=port)


def _clear_guard_daemon_state_if_current_unlocked(guard_home: _manager.Path, *, pid: int, port: int) -> bool:
    payload = _manager._load_state(guard_home)
    if not isinstance(payload, dict):
        return False
    if payload.get("pid") != pid or payload.get("port") != port:
        return False
    _manager.clear_guard_daemon_state(guard_home)
    return True


def _clear_authenticated_guard_daemon_state_if_current(
    guard_home: _manager.Path,
    *,
    expected_state: dict[str, object],
) -> bool:
    """Tombstone only the exact signed state snapshot that was classified."""

    with _manager._guard_daemon_state_write_lock(guard_home):
        current_state = _manager.load_authenticated_daemon_state(guard_home)
        if current_state != expected_state:
            return False
        _manager._write_private_atomic_text(_manager._state_path(guard_home), "{}")
        return True


def _daemon_state_points_to(guard_home: _manager.Path, *, pid: int, port: int) -> bool:
    payload = _manager._load_state(guard_home)
    return isinstance(payload, dict) and payload.get("pid") == pid and payload.get("port") == port


def _load_state(guard_home: _manager.Path) -> dict[str, object] | None:
    state_path = _manager._state_path(guard_home)
    if not state_path.is_file():
        return None
    try:
        payload = _manager.json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, _manager.json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _looks_like_guard_daemon_state(payload: dict[str, object], *, guard_home: _manager.Path) -> bool:
    compatibility_version = payload.get("compatibility_version")
    source_root = payload.get("source_root")
    runtime_fingerprint = payload.get("runtime_fingerprint")
    if compatibility_version != _manager.GUARD_DAEMON_COMPATIBILITY_VERSION:
        return False
    if not isinstance(source_root, str) or not source_root.strip():
        return False
    if not isinstance(runtime_fingerprint, str) or not runtime_fingerprint.strip():
        return False
    payload_guard_home = payload.get("guard_home")
    if isinstance(payload_guard_home, str) and payload_guard_home.strip():
        try:
            return _manager.Path(payload_guard_home).resolve() == guard_home.resolve()
        except OSError:
            return _manager.Path(payload_guard_home) == guard_home
    return True


def _state_path(guard_home: _manager.Path) -> _manager.Path:
    return guard_home / "daemon-state.json"


def _daemon_lifecycle_artifact_is_exact_tombstone(path: _manager.Path) -> bool:
    if not _manager._daemon_lifecycle_artifact_is_quarantinable(path):
        return False
    try:
        before = path.stat(follow_symlinks=False)
        if before.st_size != 2:
            return False
        with path.open("rb") as handle:
            raw = handle.read(3)
            opened = _manager.os.fstat(handle.fileno())
        after = path.stat(follow_symlinks=False)
    except OSError:
        return False
    identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    identity_opened = (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
    identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    return raw == b"{}" and identity_before == identity_opened == identity_after


def _reconcile_invalid_daemon_lifecycle_artifacts(guard_home: _manager.Path) -> bool:
    """Quarantine invalid records only after callers prove process inventory empty."""

    with _manager._guard_daemon_state_write_lock(guard_home):
        state_path = _manager._state_path(guard_home)
        if state_path.is_file() and _manager.load_authenticated_daemon_state(guard_home) is None:
            if not _manager._quarantine_daemon_lifecycle_artifact(
                state_path,
                quarantine_path=guard_home / "daemon-state.invalid.json",
                max_preserved_bytes=_manager._GUARD_DAEMON_STATE_MAX_BYTES,
            ):
                return False
            _manager._remove_invalid_daemon_discovery_key(guard_home)
        pending_path = _manager._pending_launch_path(guard_home)
        if (
            _manager.os.name == "nt"
            and pending_path.is_file()
            and _manager.load_authenticated_guard_daemon_pending_launch(guard_home) is None
            and not _manager._quarantine_daemon_lifecycle_artifact(
                pending_path,
                quarantine_path=guard_home / "daemon-launch-pending.invalid.json",
                max_preserved_bytes=_manager._GUARD_DAEMON_PENDING_LAUNCH_MAX_BYTES,
            )
        ):
            return False
    return True


def _quarantine_daemon_lifecycle_artifact(
    path: _manager.Path,
    *,
    quarantine_path: _manager.Path,
    max_preserved_bytes: int,
) -> bool:
    """Atomically replace one unchanged private invalid record with an exact tombstone."""

    if not _manager._daemon_lifecycle_artifact_is_quarantinable(path):
        return False
    try:
        before = path.stat(follow_symlinks=False)
        with path.open("rb") as handle:
            raw = handle.read(max_preserved_bytes + 1)
            opened = _manager.os.fstat(handle.fileno())
        after = path.stat(follow_symlinks=False)
    except OSError:
        return False
    identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    identity_opened = (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
    identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if identity_before != identity_opened or identity_before != identity_after:
        return False
    if raw == b"{}" and before.st_size == 2 and _manager._daemon_lifecycle_artifact_is_exact_tombstone(path):
        return True
    try:
        _manager.os.replace(path, quarantine_path)
        if len(raw) > max_preserved_bytes:
            _manager._write_private_atomic_text(
                quarantine_path,
                _manager.json.dumps(
                    {
                        "quarantined": True,
                        "reason": "oversized_invalid_daemon_lifecycle_artifact",
                        "original_size": before.st_size,
                    },
                    sort_keys=True,
                ),
            )
        _manager._write_private_atomic_text(path, "{}")
    except OSError:
        return False
    return True


def _daemon_lifecycle_artifact_is_quarantinable(path: _manager.Path) -> bool:
    try:
        parent_metadata = path.parent.lstat()
        metadata = path.lstat()
    except OSError:
        return False
    if not _manager.stat.S_ISDIR(parent_metadata.st_mode) or _manager.stat.S_ISLNK(metadata.st_mode):
        return False
    if not _manager.stat.S_ISREG(metadata.st_mode):
        return False
    if _manager.os.name == "nt":
        return True
    return (
        parent_metadata.st_uid == _manager.os.getuid()
        and metadata.st_uid == _manager.os.getuid()
        and not _manager.stat.S_IMODE(parent_metadata.st_mode) & 0o077
    )
