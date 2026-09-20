"""Guard daemon recovery helpers; shared dependencies remain on manager."""

from __future__ import annotations

from . import manager as _manager


def recover_guard_daemon_after_hook_failure(
    guard_home: _manager.Path,
    *,
    home_dir: _manager.Path | None = None,
    failure_kind: _manager.GuardDaemonHookFailureKind = "authenticated-control-plane-failure",
    recovery_lock_timeout_seconds: float | None = None,
) -> str:
    from .recovery_lifecycle import recover_guard_daemon_after_hook_failure as recover

    return recover(
        guard_home,
        home_dir=home_dir,
        failure_kind=failure_kind,
        recovery_lock_timeout_seconds=recovery_lock_timeout_seconds,
    )


def schedule_guard_daemon_recovery(
    guard_home: _manager.Path,
    *,
    home_dir: _manager.Path | None = None,
    failure_kind: _manager.GuardDaemonHookFailureKind = "authenticated-control-plane-failure",
    executable: _manager.Path | None = None,
) -> None:
    from .recovery_lifecycle import schedule_guard_daemon_recovery as schedule

    schedule(
        guard_home,
        home_dir=home_dir,
        failure_kind=failure_kind,
        executable=executable,
    )


def _guard_recovery_is_disabled(guard_home: _manager.Path) -> bool:
    from .recovery_lifecycle import guard_recovery_is_disabled

    return guard_recovery_is_disabled(guard_home)


def _terminate_recovery_worker(process: _manager.subprocess.Popen[bytes]) -> bool:
    from .recovery_lifecycle import terminate_recovery_worker

    return terminate_recovery_worker(process)


def _authenticated_live_current_daemon_url(
    guard_home: _manager.Path,
    state: dict[str, object] | None,
) -> str | None:
    from .recovery_lifecycle import authenticated_live_current_daemon_url

    return authenticated_live_current_daemon_url(guard_home, state)


def _daemon_generation_is_recent(state: dict[str, object] | None) -> bool:
    if not isinstance(state, dict):
        return False
    started_at = state.get("started_at")
    if not isinstance(started_at, str):
        return False
    try:
        started = _manager.datetime.fromisoformat(started_at)
    except ValueError:
        return False
    if started.tzinfo is None:
        return False
    age_seconds = (
        _manager.datetime.now(_manager.timezone.utc) - started.astimezone(_manager.timezone.utc)
    ).total_seconds()
    return 0 <= age_seconds <= _manager.GUARD_DAEMON_HOOK_RECOVERY_COOLDOWN_SECONDS


def _guard_daemon_wake_reservation_path(guard_home: _manager.Path) -> _manager.Path:
    return guard_home / _manager._GUARD_DAEMON_WAKE_RESERVATION_FILE


def _load_guard_daemon_wake_reservation(guard_home: _manager.Path) -> dict[str, object] | None:
    raw_payload = _manager.read_private_regular_text(
        _manager._guard_daemon_wake_reservation_path(guard_home),
        max_bytes=_manager._GUARD_DAEMON_WAKE_RESERVATION_MAX_BYTES,
        require_private_parent=True,
    )
    if raw_payload is None:
        return None
    try:
        payload = _manager.json.loads(raw_payload)
    except _manager.json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def _claim_guard_daemon_wake_reservation(guard_home: _manager.Path) -> str | None:
    token = _manager.secrets.token_hex(16)
    now = _manager.time.time()
    _manager._ensure_private_directory(guard_home)
    with _manager._guard_daemon_state_write_lock(guard_home):
        existing = _manager._load_guard_daemon_wake_reservation(guard_home)
        created_at = existing.get("created_at") if isinstance(existing, dict) else None
        if (
            isinstance(created_at, (int, float))
            and 0.0 <= now - float(created_at) < _manager._GUARD_DAEMON_WAKE_RESERVATION_SECONDS
        ):
            return None
        _manager._write_private_atomic_text(
            _manager._guard_daemon_wake_reservation_path(guard_home),
            _manager.json.dumps({"created_at": now, "token": token}, sort_keys=True),
        )
    return token


def clear_guard_daemon_wake_reservation(guard_home: _manager.Path, *, token: str) -> bool:
    with _manager._guard_daemon_state_write_lock(guard_home):
        reservation = _manager._load_guard_daemon_wake_reservation(guard_home)
        if not isinstance(reservation, dict) or not _manager.secrets.compare_digest(
            str(reservation.get("token", "")),
            token,
        ):
            return False
        _manager._write_private_atomic_text(_manager._guard_daemon_wake_reservation_path(guard_home), "{}")
    return True


def _guard_daemon_recovery_reservation_path(guard_home: _manager.Path) -> _manager.Path:
    return guard_home / _manager._GUARD_DAEMON_RECOVERY_RESERVATION_FILE


def _load_guard_daemon_recovery_reservation(guard_home: _manager.Path) -> dict[str, object] | None:
    raw_payload = _manager.read_private_regular_text(
        _manager._guard_daemon_recovery_reservation_path(guard_home),
        max_bytes=_manager._GUARD_DAEMON_RECOVERY_RESERVATION_MAX_BYTES,
        require_private_parent=True,
    )
    if raw_payload is None:
        return None
    try:
        payload = _manager.json.loads(raw_payload)
    except _manager.json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def _claim_guard_daemon_recovery_reservation(guard_home: _manager.Path) -> str | None:
    token = _manager.secrets.token_hex(16)
    now = _manager.time.time()
    _manager._ensure_private_directory(guard_home)
    with _manager._guard_daemon_state_write_lock(guard_home):
        existing = _manager._load_guard_daemon_recovery_reservation(guard_home)
        owner_state = _manager._guard_daemon_recovery_owner_state(existing)
        if owner_state is True:
            return None
        created_at = existing.get("created_at") if isinstance(existing, dict) else None
        if owner_state is None and (
            isinstance(created_at, (int, float))
            and 0.0 <= now - float(created_at) < _manager._GUARD_DAEMON_RECOVERY_RESERVATION_SECONDS
        ):
            return None
        _manager._write_private_atomic_text(
            _manager._guard_daemon_recovery_reservation_path(guard_home),
            _manager.json.dumps({"created_at": now, "token": token}, sort_keys=True),
        )
    return token


def _guard_daemon_recovery_owner_state(reservation: dict[str, object] | None) -> bool | None:
    """Return whether a claimed recovery worker is still alive."""

    if not isinstance(reservation, dict):
        return None
    pid = reservation.get("pid")
    if type(pid) is not int or pid <= 0:
        return None
    if not _manager._guard_daemon_pid_is_running(pid):
        return False
    process_command_digest = reservation.get("process_command_digest")
    if isinstance(process_command_digest, str) and process_command_digest:
        actual_command = _manager._guard_daemon_command_for_pid(pid)
        if actual_command is None:
            return None
        actual_command_digest = _manager.hashlib.sha256(actual_command.encode("utf-8", errors="replace")).hexdigest()
        if not _manager.secrets.compare_digest(actual_command_digest, process_command_digest):
            return False
    process_start_marker = reservation.get("process_start_marker")
    if isinstance(process_start_marker, str) and process_start_marker:
        actual_start_marker = _manager.process_start_token(pid)
        if actual_start_marker is None:
            return None
        if not _manager.secrets.compare_digest(actual_start_marker, process_start_marker):
            return False
    if _manager.os.name == "nt":
        creation_time = reservation.get("process_creation_time")
        if type(creation_time) is int:
            actual_creation_time = _manager.windows_process_creation_time(pid)
            if actual_creation_time != creation_time:
                return False
        return _manager.windows_process_liveness(pid) is not False
    return True


def _bind_guard_daemon_recovery_reservation(
    guard_home: _manager.Path,
    *,
    token: str,
    pid: int,
    process_creation_time: int | None = None,
) -> bool:
    if pid <= 0:
        return False
    with _manager._guard_daemon_state_write_lock(guard_home):
        reservation = _manager._load_guard_daemon_recovery_reservation(guard_home)
        if not isinstance(reservation, dict) or not _manager.secrets.compare_digest(
            str(reservation.get("token", "")),
            token,
        ):
            return False
        payload = dict(reservation)
        payload["pid"] = pid
        process_command = _manager._guard_daemon_command_for_pid(pid)
        if process_command is not None:
            payload["process_command_digest"] = _manager.hashlib.sha256(
                process_command.encode("utf-8", errors="replace")
            ).hexdigest()
        process_start_marker = _manager.process_start_token(pid)
        if process_start_marker is not None:
            payload["process_start_marker"] = process_start_marker
        if process_creation_time is not None:
            payload["process_creation_time"] = process_creation_time
        _manager._write_private_atomic_text(
            _manager._guard_daemon_recovery_reservation_path(guard_home),
            _manager.json.dumps(payload, sort_keys=True),
        )
    return True


def clear_guard_daemon_recovery_reservation(guard_home: _manager.Path, *, token: str) -> bool:
    with _manager._guard_daemon_state_write_lock(guard_home):
        reservation = _manager._load_guard_daemon_recovery_reservation(guard_home)
        if not isinstance(reservation, dict) or not _manager.secrets.compare_digest(
            str(reservation.get("token", "")),
            token,
        ):
            return False
        _manager._write_private_atomic_text(_manager._guard_daemon_recovery_reservation_path(guard_home), "{}")
    return True


def schedule_guard_daemon_ensure(
    guard_home: _manager.Path,
    *,
    home_dir: _manager.Path | None = None,
) -> str:
    """Reserve one detached daemon ensure without delaying a hook response.

    When a healthy daemon is not ready yet, return the predicted loopback origin
    so approval deep links stay absolute and repairable. Callers must not treat
    that predicted origin as a verified live URL.
    """

    if _manager.desktop_preflight_requested():
        return _manager.load_guard_daemon_url(guard_home) or ""
    existing_url = _manager.load_guard_daemon_url(guard_home)
    if existing_url is not None:
        return existing_url
    predicted_url = _manager.guard_daemon_url_for_home(guard_home)
    try:
        wake_token = _manager._claim_guard_daemon_wake_reservation(guard_home)
    except (OSError, RuntimeError, ValueError):
        return predicted_url
    if wake_token is None:
        return predicted_url
    try:
        trusted_home = _manager._trusted_daemon_home(home_dir)
        command = _manager._isolated_python_module_command(
            "codex_plugin_scanner.cli",
            _manager._trusted_daemon_import_paths(),
            [
                "guard",
                "daemon",
                "ensure",
                "--guard-home",
                str(guard_home),
                "--home",
                str(trusted_home),
                "--wake-token",
                wake_token,
            ],
        )
        launcher_env = _manager._daemon_launcher_env(home_dir=trusted_home, guard_home=guard_home)
        if _manager.os.name == "nt":
            _manager.subprocess.Popen(
                command,
                stdin=_manager.subprocess.DEVNULL,
                stdout=_manager.subprocess.DEVNULL,
                stderr=_manager.subprocess.DEVNULL,
                cwd=trusted_home,
                env=launcher_env,
                creationflags=_manager._windows_daemon_creation_flags(allow_job_breakaway=False),
            )
        else:
            _manager.subprocess.Popen(
                command,
                stdin=_manager.subprocess.DEVNULL,
                stdout=_manager.subprocess.DEVNULL,
                stderr=_manager.subprocess.DEVNULL,
                cwd=trusted_home,
                env=launcher_env,
                start_new_session=True,
            )
    except (OSError, RuntimeError, _manager.subprocess.SubprocessError, ValueError):
        with _manager.suppress(OSError, RuntimeError, ValueError):
            _manager.clear_guard_daemon_wake_reservation(guard_home, token=wake_token)
    return predicted_url
