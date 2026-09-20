"""Guard daemon ephemeral helpers; shared dependencies remain on manager."""

from __future__ import annotations

from . import manager as _manager


def _schedule_stale_ephemeral_guard_daemon_reap(*, exclude_guard_home: _manager.Path | None = None) -> None:
    with _manager._EPHEMERAL_REAP_SCHEDULE_LOCK:
        if _manager.__dict__.get("_EPHEMERAL_REAP_IN_FLIGHT") is True:
            return
        now = _manager.time.monotonic()
        last_reap_at = _manager.__dict__.get("_LAST_EPHEMERAL_REAP_AT", 0.0)
        if not isinstance(last_reap_at, (int, float)):
            last_reap_at = 0.0
        if now - float(last_reap_at) < _manager._EPHEMERAL_GUARD_DAEMON_REAP_INTERVAL_SECONDS:
            return
        previous_reap_at = float(last_reap_at)
        _manager.__dict__["_EPHEMERAL_REAP_IN_FLIGHT"] = True
        _manager.__dict__["_LAST_EPHEMERAL_REAP_AT"] = now

    reaper = _manager._reap_stale_ephemeral_guard_daemons

    def reap() -> None:
        try:
            reaper(
                exclude_guard_home=exclude_guard_home,
                force=True,
            )
        except Exception:
            # A later interval can retry this best-effort cleanup.
            pass
        finally:
            with _manager._EPHEMERAL_REAP_SCHEDULE_LOCK:
                _manager.__dict__["_EPHEMERAL_REAP_IN_FLIGHT"] = False

    thread = _manager.threading.Thread(
        target=reap,
        name="guard-daemon-stale-reaper",
        daemon=True,
    )
    try:
        thread.start()
    except RuntimeError:
        with _manager._EPHEMERAL_REAP_SCHEDULE_LOCK:
            _manager.__dict__["_EPHEMERAL_REAP_IN_FLIGHT"] = False
            _manager.__dict__["_LAST_EPHEMERAL_REAP_AT"] = previous_reap_at


def _reap_stale_ephemeral_guard_daemons(
    *,
    exclude_guard_home: _manager.Path | None = None,
    force: bool = False,
) -> None:
    now = _manager.time.monotonic()
    last_reap_at = _manager.__dict__.get("_LAST_EPHEMERAL_REAP_AT", 0.0)
    if not isinstance(last_reap_at, (int, float)):
        last_reap_at = 0.0
    if not force and now - float(last_reap_at) < _manager._EPHEMERAL_GUARD_DAEMON_REAP_INTERVAL_SECONDS:
        return
    if not force:
        _manager.__dict__["_LAST_EPHEMERAL_REAP_AT"] = now
    temp_root = _manager.Path(_manager.tempfile.gettempdir())
    candidate_paths = list(_manager._ephemeral_guard_daemon_state_paths(temp_root))
    exclude_resolved = exclude_guard_home.resolve() if exclude_guard_home is not None else None
    for state_path in candidate_paths[: _manager._EPHEMERAL_GUARD_DAEMON_MAX_STATES]:
        guard_home = state_path.parent
        try:
            resolved_guard_home = guard_home.resolve()
        except OSError:
            continue
        if exclude_resolved is not None and resolved_guard_home == exclude_resolved:
            continue
        if not _manager._guard_home_is_ephemeral(resolved_guard_home):
            continue
        state_age_seconds = _manager._state_path_age_seconds(state_path)
        if state_age_seconds < _manager._EPHEMERAL_GUARD_DAEMON_STALE_SECONDS:
            continue
        payload = _manager._load_state(guard_home)
        if not _manager._ephemeral_guard_home_is_inactive(
            guard_home,
            fallback_age_seconds=state_age_seconds,
            state_payload=payload,
        ):
            continue
        if not isinstance(payload, dict) or not _manager._looks_like_guard_daemon_state(payload, guard_home=guard_home):
            continue
        pid = payload.get("pid")
        if not isinstance(pid, int) or pid <= 0:
            continue
        # Live daemons are handled by the single bounded process inventory below.
        # Probing every stale state independently creates an unbounded process
        # query fan-out when a temp root contains many prior test runs.
        if not _manager._guard_daemon_pid_is_running(pid):
            _manager.clear_guard_daemon_state(guard_home)
    for pid, guard_home, elapsed_seconds in _manager._running_ephemeral_guard_daemon_processes():
        if elapsed_seconds < _manager._EPHEMERAL_GUARD_DAEMON_STALE_SECONDS:
            continue
        try:
            resolved_guard_home = guard_home.resolve()
        except OSError:
            continue
        if exclude_resolved is not None and resolved_guard_home == exclude_resolved:
            continue
        if not _manager._ephemeral_guard_home_is_inactive(guard_home, fallback_age_seconds=elapsed_seconds):
            continue
        if _manager._retire_guard_daemon_pid(pid, expected_guard_home=guard_home):
            _manager.clear_guard_daemon_state(guard_home)


def _ephemeral_guard_daemon_state_paths(temp_root: _manager.Path) -> list[_manager.Path]:
    results: list[_manager.Path] = []
    for root in _manager._pytest_temp_roots(temp_root):
        _manager._collect_daemon_state_paths(root, results, limit=_manager._EPHEMERAL_GUARD_DAEMON_MAX_STATES)
        if len(results) >= _manager._EPHEMERAL_GUARD_DAEMON_MAX_STATES:
            break
    return sorted(results)


def _pytest_temp_roots(temp_root: _manager.Path) -> list[_manager.Path]:
    roots: list[_manager.Path] = []
    try:
        if _manager._path_name_looks_like_pytest_temp_root(temp_root.name):
            roots.append(temp_root)
        with _manager.os.scandir(temp_root) as entries:
            for entry in entries:
                if not entry.is_dir(follow_symlinks=False):
                    continue
                if _manager._path_name_looks_like_pytest_temp_root(entry.name):
                    roots.append(_manager.Path(entry.path))
    except OSError:
        return []
    return sorted(roots)


def _path_name_looks_like_pytest_temp_root(name: str) -> bool:
    return name.startswith("pytest-") or "pytest-of-" in name


def _collect_daemon_state_paths(root: _manager.Path, results: list[_manager.Path], *, limit: int) -> None:
    pending: list[_manager.Path] = [root]
    while pending and len(results) < limit:
        current = pending.pop()
        try:
            with _manager.os.scandir(current) as entries:
                directories: list[_manager.Path] = []
                files: list[_manager.Path] = []
                for entry in entries:
                    if entry.is_dir(follow_symlinks=False):
                        directories.append(_manager.Path(entry.path))
                    elif entry.is_file(follow_symlinks=False) and entry.name == "daemon-state.json":
                        files.append(_manager.Path(entry.path))
        except OSError:
            continue
        for path in sorted(files):
            results.append(path)
            if len(results) >= limit:
                return
        pending.extend(reversed(sorted(directories)))


def _state_path_age_seconds(state_path: _manager.Path) -> float:
    try:
        return max(0.0, _manager.time.time() - state_path.stat().st_mtime)
    except OSError:
        return 0.0


def _guard_home_is_ephemeral(guard_home: _manager.Path) -> bool:
    return any(part.startswith("pytest-") or "pytest-of-" in part for part in guard_home.parts)


def _ephemeral_guard_home_is_inactive(
    guard_home: _manager.Path,
    *,
    fallback_age_seconds: float,
    state_payload: dict[str, object] | None = None,
) -> bool:
    payload = state_payload if isinstance(state_payload, dict) else _manager._load_state(guard_home)
    if isinstance(payload, dict):
        pid = payload.get("pid")
        if not isinstance(pid, int) or pid <= 0:
            return fallback_age_seconds >= _manager._EPHEMERAL_GUARD_DAEMON_STALE_SECONDS
        if not _manager._guard_daemon_pid_is_running(pid):
            return fallback_age_seconds >= _manager._EPHEMERAL_GUARD_DAEMON_STALE_SECONDS
        if not _manager._guard_daemon_pid_matches_command(pid, expected_guard_home=guard_home):
            return fallback_age_seconds >= _manager._EPHEMERAL_GUARD_DAEMON_STALE_SECONDS
    heartbeat_age_seconds = _manager._runtime_state_age_seconds(guard_home)
    if heartbeat_age_seconds is None:
        return fallback_age_seconds >= _manager._EPHEMERAL_GUARD_DAEMON_STALE_SECONDS
    return heartbeat_age_seconds >= _manager._EPHEMERAL_GUARD_DAEMON_STALE_SECONDS


def _runtime_state_age_seconds(guard_home: _manager.Path) -> float | None:
    try:
        from ..store import GuardStore

        runtime_state = GuardStore(guard_home, prime_policy_integrity=False).get_runtime_state()
    except Exception:
        return None
    if not isinstance(runtime_state, dict):
        return None
    last_heartbeat_at = runtime_state.get("last_heartbeat_at")
    if not isinstance(last_heartbeat_at, str) or not last_heartbeat_at.strip():
        return None
    try:
        heartbeat = _manager.datetime.fromisoformat(last_heartbeat_at)
    except ValueError:
        return None
    if heartbeat.tzinfo is None:
        heartbeat = heartbeat.replace(tzinfo=_manager.timezone.utc)
    return max(0.0, (_manager.datetime.now(_manager.timezone.utc) - heartbeat).total_seconds())
