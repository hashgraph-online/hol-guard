"""Guard daemon lifecycle helpers; shared dependencies remain on manager."""

from __future__ import annotations

from . import manager as _manager


def ensure_guard_daemon(
    guard_home: _manager.Path,
    *,
    home_dir: _manager.Path | None = None,
    start_timeout: float | None = None,
    preferred_port: int | None = None,
    allow_windows_job_breakaway: bool = False,
    executable: _manager.Path | None = None,
) -> str:
    if _manager.desktop_preflight_requested():
        raise RuntimeError("Guard daemon start is disabled during Desktop preflight.")
    timeout = _manager._default_guard_daemon_start_timeout() if start_timeout is None else start_timeout
    start_deadline = _manager.time.monotonic() + max(0.0, timeout)
    launch_cwd = _manager._trusted_daemon_home(home_dir)
    _manager._schedule_stale_ephemeral_guard_daemon_reap(exclude_guard_home=guard_home)
    state_path = _manager._state_path(guard_home)
    existing_url = _manager._live_or_newer_daemon_url(guard_home, executable=executable, preferred_port=preferred_port)
    if existing_url is not None:
        _manager._schedule_duplicate_guard_daemon_retirement(guard_home)
        return existing_url
    with _manager._guard_daemon_start_lock(guard_home, deadline=start_deadline):
        if executable is not None:
            existing_url = _manager._live_or_newer_daemon_url(
                guard_home, executable=executable, preferred_port=preferred_port
            )
            if existing_url is not None:
                _manager._schedule_duplicate_guard_daemon_retirement(guard_home)
                return existing_url
        else:
            existing_url = _manager.load_guard_daemon_url(guard_home)
            if existing_url is not None and (
                preferred_port is None or _manager._guard_daemon_url_port(existing_url) == preferred_port
            ):
                _manager._schedule_duplicate_guard_daemon_retirement(guard_home)
                return existing_url
            if existing_url is not None:
                _manager.retire_all_guard_daemons_for_home(guard_home)
                if not _manager.guard_daemon_retirement_is_complete(guard_home):
                    raise RuntimeError("Existing Guard daemon could not be retired safely.")
                _manager.clear_guard_daemon_state(guard_home)
        if state_path.is_file() and _manager._load_authenticated_daemon_identity(guard_home) is None:
            _manager.retire_all_guard_daemons_for_home(guard_home)
            if not _manager._daemon_lifecycle_artifact_is_exact_tombstone(state_path):
                raise RuntimeError("Untrusted Guard daemon state could not be retired safely.")
            _manager._remove_invalid_daemon_discovery_key(guard_home)
        adopted_url = (
            None
            if executable is not None
            else _manager._adopt_existing_guard_daemon(guard_home, preferred_port=preferred_port)
        )
        if adopted_url is not None:
            _manager._schedule_duplicate_guard_daemon_retirement(guard_home)
            return adopted_url
        stale_state = _manager._load_state(guard_home)
        if isinstance(stale_state, dict) and not _manager._guard_daemon_state_matches_current_runtime(stale_state):
            stale_pid = stale_state.get("pid")
            if (
                type(stale_pid) is int
                and stale_pid > 0
                and not _manager._retire_guard_daemon_process({**stale_state, "guard_home": str(guard_home)})
            ):
                raise RuntimeError("Stale Guard daemon could not be retired safely.")
        if _manager._guard_daemon_start_in_progress(guard_home):
            inflight_url = _manager._wait_for_guard_daemon_url(
                guard_home, timeout=max(0.0, start_deadline - _manager.time.monotonic())
            )
            if inflight_url is not None:
                _manager._schedule_duplicate_guard_daemon_retirement(guard_home)
                return inflight_url
            _manager.retire_all_guard_daemons_for_home(guard_home)
            if not _manager.guard_daemon_retirement_is_complete(guard_home):
                raise RuntimeError("In-progress Guard daemon launch could not be retired safely.")
        if _manager.os.name == "nt" and (
            _manager._pending_launch_path(guard_home).is_file()
            or _manager.load_authenticated_guard_daemon_pending_launch(guard_home) is not None
        ):
            _manager.retire_all_guard_daemons_for_home(guard_home)
            if not _manager._guard_daemon_pending_launch_state_is_resolved(guard_home):
                raise RuntimeError("A previous Guard daemon launch could not be retired safely.")
        _manager.clear_guard_daemon_state(guard_home)
        for candidate_port in _manager._candidate_ports(guard_home, preferred_port=preferred_port):
            remaining_start_time = start_deadline - _manager.time.monotonic()
            if remaining_start_time <= 0:
                break
            if executable is None:
                command = _manager._guard_daemon_launch_command(
                    guard_home,
                    candidate_port,
                    home_dir=home_dir,
                    gate_on_stdin=_manager.os.name == "nt",
                )
                launcher_env = _manager._daemon_launcher_env(home_dir=home_dir, guard_home=guard_home)
            else:
                command = _manager._guard_daemon_launch_command(
                    guard_home,
                    candidate_port,
                    home_dir=home_dir,
                    gate_on_stdin=False,
                    executable=executable,
                )
                launcher_env = _manager._daemon_launcher_env(
                    home_dir=home_dir,
                    guard_home=guard_home,
                    executable=executable,
                )
            if _manager.os.name == "nt":
                process = _manager.subprocess.Popen(
                    command,
                    stdin=_manager.subprocess.PIPE,
                    stdout=_manager.subprocess.DEVNULL,
                    stderr=_manager.subprocess.DEVNULL,
                    cwd=launch_cwd,
                    env=launcher_env,
                    creationflags=_manager._windows_daemon_creation_flags(
                        allow_job_breakaway=allow_windows_job_breakaway,
                    ),
                )
            else:
                process = _manager.subprocess.Popen(
                    command,
                    stdin=_manager.subprocess.DEVNULL,
                    stdout=_manager.subprocess.DEVNULL,
                    stderr=_manager.subprocess.DEVNULL,
                    cwd=launch_cwd,
                    env=launcher_env,
                    start_new_session=True,
                )
            pending_creation_time: int | None = None
            try:
                pending_creation_time = _manager._record_guard_daemon_pending_launch(
                    guard_home,
                    process=process,
                    port=candidate_port,
                )
                _manager._release_guard_daemon_launch_gate(process)
                remaining_start_time = max(0.0, start_deadline - _manager.time.monotonic())
                url = _manager._wait_for_started_guard_daemon_url(
                    guard_home,
                    timeout=remaining_start_time,
                    process=process,
                    executable=executable,
                )
                if url is not None:
                    if not _manager._clear_spawned_guard_daemon_pending_launch(
                        guard_home, process=process, creation_time=pending_creation_time
                    ):
                        raise RuntimeError("Guard daemon pending launch state could not be cleared safely.")
                    _manager._schedule_duplicate_guard_daemon_retirement(guard_home)
                    return url
                if not _manager._terminate_spawned_guard_daemon(process):
                    raise RuntimeError("Guard daemon startup process could not be retired safely.")
                if not _manager._clear_spawned_guard_daemon_pending_launch(
                    guard_home, process=process, creation_time=pending_creation_time
                ):
                    raise RuntimeError("Guard daemon pending launch state could not be cleared safely.")
            except BaseException:
                if _manager._terminate_spawned_guard_daemon(process):
                    _manager._clear_spawned_guard_daemon_pending_launch(
                        guard_home, process=process, creation_time=pending_creation_time
                    )
                raise
    raise RuntimeError(f"Guard approval center did not start. Expected state file at {state_path}.")


def ensure_guard_daemon_after_update(
    guard_home: _manager.Path,
    *,
    home_dir: _manager.Path,
    preferred_port: int | None = None,
    allow_windows_job_breakaway: bool = False,
    executable: _manager.Path | None = None,
) -> str:
    """Restart the local daemon after a package update with a longer startup window."""
    if executable is None:
        return _manager.ensure_guard_daemon(
            guard_home,
            home_dir=home_dir,
            start_timeout=_manager.GUARD_DAEMON_POST_UPDATE_START_TIMEOUT_SECONDS,
            preferred_port=preferred_port,
            allow_windows_job_breakaway=allow_windows_job_breakaway,
        )
    return _manager.ensure_guard_daemon(
        guard_home,
        home_dir=home_dir,
        start_timeout=_manager.GUARD_DAEMON_POST_UPDATE_START_TIMEOUT_SECONDS,
        preferred_port=preferred_port,
        allow_windows_job_breakaway=allow_windows_job_breakaway,
        executable=executable,
    )


def retire_all_guard_daemons_for_home(
    guard_home: _manager.Path,
    *,
    keep_port: int | None = None,
) -> list[int]:
    """Stop Guard daemon processes for one guard home, optionally keeping one port alive."""
    retired: list[int] = []
    handled_pids: set[int] = set()
    pending_launch = _manager.load_authenticated_guard_daemon_pending_launch(guard_home)
    if isinstance(pending_launch, dict):
        pending_pid = pending_launch.get("pid")
        pending_port = pending_launch.get("port")
        pending_creation_time = pending_launch.get("process_creation_time")
        if type(pending_pid) is int and type(pending_creation_time) is int:
            if keep_port is not None and pending_port == keep_port:
                handled_pids.add(pending_pid)
            else:
                actual_creation_time = _manager.windows_process_creation_time(pending_pid)
                if actual_creation_time == pending_creation_time:
                    handled_pids.add(pending_pid)
                    if _manager._retire_guard_daemon_pid(
                        pending_pid,
                        expected_guard_home=guard_home,
                        expected_creation_time=pending_creation_time,
                    ) and _manager._guard_daemon_pid_is_proven_dead(pending_pid):
                        retired.append(pending_pid)
                        _manager._clear_guard_daemon_pending_launch_if_current(
                            guard_home,
                            pid=pending_pid,
                            creation_time=pending_creation_time,
                        )
                elif actual_creation_time is not None or _manager._guard_daemon_pid_is_proven_dead(pending_pid):
                    _manager._clear_guard_daemon_pending_launch_if_current(
                        guard_home,
                        pid=pending_pid,
                        creation_time=pending_creation_time,
                    )
                else:
                    handled_pids.add(pending_pid)

    authenticated_state = _manager.load_authenticated_daemon_state(guard_home)
    if isinstance(authenticated_state, dict):
        state_pid = authenticated_state.get("pid")
        state_port = authenticated_state.get("port")
        if type(state_pid) is int and state_pid > 0 and type(state_port) is int:
            if keep_port is not None and state_port == keep_port:
                handled_pids.add(state_pid)
            elif state_pid in handled_pids and _manager._guard_daemon_pid_is_proven_dead(state_pid):
                _manager._clear_authenticated_guard_daemon_state_if_current(
                    guard_home,
                    expected_state=authenticated_state,
                )
            elif state_pid not in handled_pids:
                handled_pids.add(state_pid)
                state_id = authenticated_state.get("state_id")
                with _manager.suppress(Exception):
                    _manager.record_daemon_lifecycle_event(
                        guard_home,
                        event="retirement_requested",
                        reason="managed_retirement",
                        pid=state_pid,
                        session_id=state_id if isinstance(state_id, str) else None,
                    )
                retirement_succeeded = _manager._retire_guard_daemon_pid(
                    state_pid,
                    expected_guard_home=guard_home,
                )
                if retirement_succeeded:
                    if _manager._guard_daemon_pid_is_proven_dead(state_pid):
                        _manager._clear_authenticated_guard_daemon_state_if_current(
                            guard_home,
                            expected_state=authenticated_state,
                        )
                        if state_pid not in retired:
                            retired.append(state_pid)
                    elif (
                        _manager._guard_daemon_pid_command_identity(
                            state_pid,
                            expected_guard_home=guard_home,
                        )
                        is False
                    ):
                        _manager._clear_authenticated_guard_daemon_state_if_current(
                            guard_home,
                            expected_state=authenticated_state,
                        )

    inventory = _manager._guard_daemon_process_inventory_for_guard_home(guard_home)
    if inventory is not None:
        for pid, port in inventory:
            if pid in handled_pids or (keep_port is not None and port == keep_port):
                continue
            if _manager._retire_guard_daemon_pid(
                pid, expected_guard_home=guard_home
            ) and _manager._guard_daemon_pid_is_proven_dead(pid):
                handled_pids.add(pid)
                if pid not in retired:
                    retired.append(pid)
        remaining = _manager._guard_daemon_process_inventory_for_guard_home(guard_home)
        empty_inventory_confirmed = inventory == [] and remaining == []
        if inventory != [] and remaining == []:
            empty_inventory_confirmed = _manager._guard_daemon_process_inventory_for_guard_home(guard_home) == []
        if empty_inventory_confirmed and keep_port is None:
            _manager._reconcile_invalid_daemon_lifecycle_artifacts(guard_home)
    return retired


def guard_daemon_retirement_is_complete(guard_home: _manager.Path) -> bool:
    """Prove no authenticated, pending, or enumerable daemon remains for a home."""

    authenticated_state = _manager.load_authenticated_daemon_state(guard_home)
    if isinstance(authenticated_state, dict):
        state_pid = authenticated_state.get("pid")
        if type(state_pid) is not int or state_pid <= 0:
            return False
        if not _manager._guard_daemon_pid_is_proven_dead(state_pid):
            return False
    elif _manager._state_path(guard_home).is_file():
        if not _manager._daemon_lifecycle_artifact_is_exact_tombstone(_manager._state_path(guard_home)):
            return False
    if not _manager._guard_daemon_pending_launch_state_is_resolved(guard_home):
        return False
    inventory = _manager._guard_daemon_process_inventory_for_guard_home(guard_home)
    return inventory == []


def guard_daemon_process_count(guard_home: _manager.Path) -> int | None:
    """Return the number of enumerable daemon processes for one Guard home."""

    inventory = _manager._guard_daemon_process_inventory_for_guard_home(guard_home)
    return None if inventory is None else len(inventory)


def guard_daemon_url_for_home(guard_home: _manager.Path) -> str:
    return f"http://127.0.0.1:{_manager._configured_port(guard_home)}"
