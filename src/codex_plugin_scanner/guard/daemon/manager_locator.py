"""Guard daemon locator helpers; shared dependencies remain on manager."""

from __future__ import annotations

from . import manager as _manager


def repair_approval_center_locator(guard_home: _manager.Path) -> dict[str, object]:
    """Repair stale locator and authenticated daemon-discovery state.

    A healthy live daemon is preserved.  A live daemon with an invalid identity
    bundle is retired before its state is cleared, and an invalid discovery key
    is removed so the next daemon start can regenerate it.  Raises OSError if a
    required write fails so callers can detect incomplete repair.

    Safe to call while the database is live.  Returns a dict describing what was cleared.
    """
    cleared: list[str] = []
    locator = _manager._locator_path(guard_home)
    if locator.is_file():
        locator.unlink()
        cleared.append("locator")
    state = _manager._state_path(guard_home)
    state_payload = _manager._load_state(guard_home) if state.is_file() else None
    identity_is_invalid = _manager._load_authenticated_daemon_identity(guard_home) is None
    discovery_key_path = _manager.daemon_discovery_key_path(guard_home)
    invalid_discovery_key_existed = (
        discovery_key_path.is_file() and _manager.load_daemon_discovery_key(guard_home) is None
    )
    if state.is_file():
        identity_payload = state_payload if isinstance(state_payload, dict) else {}
        pid = identity_payload.get("pid")
        pid_is_live = type(pid) is int and pid > 0 and _manager._guard_daemon_pid_is_running(pid)
        command_identity: bool | None = False
        if type(pid) is int and pid_is_live:
            command_identity = _manager._guard_daemon_pid_command_identity(pid, expected_guard_home=guard_home)
        if pid_is_live and command_identity is None:
            raise RuntimeError("Live Guard daemon process identity could not be resolved safely.")
        daemon_is_live = pid_is_live and command_identity is True
        if identity_is_invalid:
            _manager.retire_all_guard_daemons_for_home(guard_home)
            if not _manager._daemon_lifecycle_artifact_is_exact_tombstone(state):
                raise RuntimeError("Untrusted Guard daemon state could not be retired safely.")
            if daemon_is_live:
                cleared.append("daemon_process")
            daemon_is_live = False
        if not daemon_is_live:
            _manager.clear_guard_daemon_state(guard_home)
            cleared.append("daemon_state")
    if identity_is_invalid:
        discovery_key_removed = _manager._remove_invalid_daemon_discovery_key(guard_home)
        if discovery_key_removed or (invalid_discovery_key_existed and not discovery_key_path.exists()):
            cleared.append("daemon_discovery_key")
    return {"repaired": True, "cleared": cleared}


def _locator_path(guard_home: _manager.Path) -> _manager.Path:
    return guard_home / _manager._APPROVAL_CENTER_LOCATOR_FILE


def write_approval_center_locator(guard_home: _manager.Path, locator: _manager.ApprovalCenterLocator) -> None:
    locator_path = _manager._locator_path(guard_home)
    _manager._ensure_private_directory(locator_path.parent)
    payload = {
        "guard_home": str(locator.guard_home),
        "daemon_url": locator.daemon_url,
        "approval_url_base": locator.approval_url_base,
        "pid": locator.pid,
        "started_at": locator.started_at,
        "state_path": str(locator.state_path),
    }
    _manager._write_private_text(locator_path, _manager.json.dumps(payload, indent=2))


def read_approval_center_locator(guard_home: _manager.Path) -> _manager.ApprovalCenterLocator | None:
    locator_path = _manager._locator_path(guard_home)
    if not locator_path.is_file():
        return None
    try:
        payload = _manager.json.loads(locator_path.read_text(encoding="utf-8"))
    except (OSError, _manager.json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    pid = payload.get("pid")
    if not isinstance(pid, int) or pid <= 0:
        return None
    if not _manager._guard_daemon_pid_is_running(pid):
        return None
    daemon_url = payload.get("daemon_url")
    approval_url_base = payload.get("approval_url_base")
    started_at = payload.get("started_at")
    state_path_str = payload.get("state_path")
    guard_home_str = payload.get("guard_home")
    if not isinstance(daemon_url, str):
        return None
    if not isinstance(approval_url_base, str):
        return None
    if not isinstance(started_at, str):
        return None
    if not isinstance(state_path_str, str):
        return None
    if not isinstance(guard_home_str, str):
        return None
    if not _manager._guard_daemon_pid_matches_command(pid, expected_guard_home=guard_home):
        state = _manager.load_authenticated_daemon_state(guard_home)
        state_pid = state.get("pid") if isinstance(state, dict) else None
        state_port = state.get("port") if isinstance(state, dict) else None
        if state_pid != pid or not isinstance(state_port, int) or daemon_url != f"http://127.0.0.1:{state_port}":
            return None
    return _manager.ApprovalCenterLocator(
        guard_home=_manager.Path(guard_home_str),
        daemon_url=daemon_url,
        approval_url_base=approval_url_base,
        pid=pid,
        started_at=started_at,
        state_path=_manager.Path(state_path_str),
    )


def _approval_center_daemon_is_healthy(daemon_url: str) -> bool:
    try:
        with _manager.urllib.request.urlopen(f"{daemon_url}/healthz", timeout=1) as response:
            if response.status != 200:
                return False
            return _manager._healthz_payload_is_current(response.read().decode("utf-8"))
    except (OSError, ValueError, _manager.urllib.error.URLError):
        return False


def _daemon_state_pid_matches_locator(guard_home: _manager.Path, locator_pid: int) -> bool:
    state = _manager._load_state(guard_home)
    if not isinstance(state, dict):
        return False
    state_pid = state.get("pid")
    return isinstance(state_pid, int) and state_pid == locator_pid


def _daemon_identity_matches_locator(
    guard_home: _manager.Path,
    *,
    pid: int,
    daemon_url: str,
) -> bool:
    if not _manager._guard_daemon_pid_is_running(pid):
        return False
    if _manager._guard_daemon_pid_matches_command(pid, expected_guard_home=guard_home):
        return True
    auth_token = _manager.load_guard_daemon_auth_token(guard_home)
    if auth_token is None:
        return False
    details = _manager._daemon_healthz_details_payload(daemon_url, auth_token)
    return bool(
        isinstance(details, dict)
        and details.get("pid") == pid
        and _manager._healthz_payload_matches_guard_home(_manager.json.dumps(details), guard_home)
        and _manager._daemon_healthz_details_match_current_runtime(details)
    )


def publish_approval_center_locator(
    guard_home: _manager.Path,
    daemon_url: str,
) -> _manager.ApprovalCenterLocator:
    """Publish browser discovery for an already authenticated live daemon."""

    state = _manager.load_authenticated_daemon_state(guard_home)
    if not isinstance(state, dict):
        raise RuntimeError("Guard daemon identity is unavailable.")
    pid = state.get("pid")
    port = state.get("port")
    if (
        not isinstance(pid, int)
        or pid <= 0
        or not isinstance(port, int)
        or daemon_url != f"http://127.0.0.1:{port}"
        or not _manager._daemon_identity_matches_locator(guard_home, pid=pid, daemon_url=daemon_url)
    ):
        raise RuntimeError("Guard daemon identity does not match the active local service.")
    started_at = state.get("started_at")
    if not isinstance(started_at, str) or not started_at:
        started_at = _manager.datetime.now(tz=_manager.timezone.utc).isoformat()
    locator = _manager.ApprovalCenterLocator(
        guard_home=guard_home,
        daemon_url=daemon_url,
        approval_url_base=daemon_url,
        pid=pid,
        started_at=started_at,
        state_path=_manager._state_path(guard_home),
    )
    _manager.write_approval_center_locator(guard_home, locator)
    return locator


def ensure_approval_center(guard_home: _manager.Path) -> _manager.ApprovalCenterLocator:
    existing = _manager.read_approval_center_locator(guard_home)
    if (
        existing is not None
        and _manager._approval_center_daemon_is_healthy(existing.daemon_url)
        and _manager._daemon_state_pid_matches_locator(guard_home, existing.pid)
    ):
        return existing
    daemon_url = _manager.ensure_guard_daemon(guard_home)
    now = _manager.datetime.now(tz=_manager.timezone.utc).isoformat()
    state = _manager._load_state(guard_home)
    pid = state.get("pid") if isinstance(state, dict) else None
    if not isinstance(pid, int) or pid <= 0:
        pid = _manager.os.getpid()
    locator = _manager.ApprovalCenterLocator(
        guard_home=guard_home,
        daemon_url=daemon_url,
        approval_url_base=daemon_url,
        pid=pid,
        started_at=now,
        state_path=_manager._state_path(guard_home),
    )
    _manager.write_approval_center_locator(guard_home, locator)
    return locator
