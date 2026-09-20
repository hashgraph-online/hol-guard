"""Guard daemon live helpers; shared dependencies remain on manager."""

from __future__ import annotations

from . import manager as _manager


def load_guard_daemon_url(guard_home: _manager.Path) -> str | None:
    return _manager._live_guard_daemon_url(guard_home, require_current_runtime=True)


def load_running_guard_daemon_identity(
    guard_home: _manager.Path, *, health_timeout: float = 1.0
) -> tuple[str, str] | None:
    return _manager._live_guard_daemon_identity(guard_home, require_current_runtime=True, health_timeout=health_timeout)


def _live_guard_daemon_url(
    guard_home: _manager.Path,
    *,
    require_current_runtime: bool = True,
    expected_pid: int | None = None,
) -> str | None:
    identity = _manager._live_guard_daemon_identity(
        guard_home,
        require_current_runtime=require_current_runtime,
        expected_pid=expected_pid,
    )
    return identity[0] if identity is not None else None


def _live_guard_daemon_identity(
    guard_home: _manager.Path,
    *,
    require_current_runtime: bool = True,
    expected_pid: int | None = None,
    health_timeout: float = 1.0,
) -> tuple[str, str] | None:
    identity = _manager._load_authenticated_daemon_identity(guard_home)
    if identity is None:
        return None
    payload, auth_token = identity
    if require_current_runtime and not _manager._guard_daemon_state_matches_current_runtime(payload):
        return None
    compatibility_version = payload.get("compatibility_version")
    if compatibility_version != _manager.GUARD_DAEMON_COMPATIBILITY_VERSION:
        return None
    port = payload.get("port")
    if not isinstance(port, int):
        return None
    pid = payload.get("pid")
    if not isinstance(pid, int) or pid <= 0 or not _manager._guard_daemon_pid_is_running(pid):
        return None
    if expected_pid is not None and not _manager._guard_daemon_pid_is_spawned_launch(pid, expected_pid):
        return None
    url = f"http://127.0.0.1:{port}"
    try:
        with _manager.urllib.request.urlopen(
            _manager._daemon_health_request(f"{url}/healthz"), timeout=health_timeout
        ) as response:
            raw_payload = response.read().decode("utf-8")
            if response.status != 200 or not _manager._healthz_payload_is_current(raw_payload):
                return None
    except (OSError, ValueError, _manager.urllib.error.URLError):
        return None
    if _manager._guard_daemon_pid_matches_command(pid, expected_guard_home=guard_home):
        return url, auth_token
    # Wrapped daemons may require authenticated detailed health for binding.
    if _manager._daemon_healthz_details_match_guard_home(
        url, guard_home, auth_token=auth_token, timeout=health_timeout
    ):
        return url, auth_token
    return None


def _load_authenticated_daemon_identity(guard_home: _manager.Path) -> tuple[dict[str, object], str] | None:
    payload = _manager.load_authenticated_daemon_state(guard_home)
    if payload is None:
        return None
    auth_token = _manager.load_guard_daemon_auth_token(guard_home)
    expected_token_id = payload.get("auth_token_id")
    if (
        auth_token is None
        or not isinstance(expected_token_id, str)
        or not _manager.secrets.compare_digest(
            _manager.hashlib.sha256(auth_token.encode("utf-8")).hexdigest(),
            expected_token_id,
        )
    ):
        return None
    return payload, auth_token


def load_guard_daemon_auth_token(guard_home: _manager.Path) -> str | None:
    token = _manager.read_private_regular_text(
        _manager._auth_token_path(guard_home),
        max_bytes=4096,
        require_private_parent=True,
    )
    return token or None


def _daemon_health_request(url: str, auth_token: str | None = None) -> _manager.urllib.request.Request:
    headers: dict[str, str] = {}
    if isinstance(auth_token, str) and auth_token.strip():
        headers["X-Guard-Token"] = auth_token
    return _manager.urllib.request.Request(url, headers=headers, method="GET")


def _daemon_healthz_details_payload(url: str, auth_token: str, *, timeout: float = 1.0) -> dict[str, object] | None:
    try:
        request = _manager._daemon_health_request(f"{url}/v1/healthz/details", auth_token)
        with _manager.urllib.request.urlopen(request, timeout=timeout) as response:
            if response.status != 200:
                return None
            payload = _manager.json.loads(response.read().decode("utf-8"))
    except (OSError, ValueError, _manager.json.JSONDecodeError, _manager.urllib.error.URLError):
        return None
    return payload if isinstance(payload, dict) else None


def _daemon_healthz_details_match_guard_home(
    url: str, guard_home: _manager.Path, *, auth_token: str, timeout: float = 1.0
) -> bool:
    payload = _manager._daemon_healthz_details_payload(url, auth_token, timeout=timeout)
    if payload is None:
        return False
    return _manager._healthz_payload_matches_guard_home(_manager.json.dumps(payload), guard_home)


def _daemon_healthz_details_match_current_runtime(payload: dict[str, object]) -> bool:
    """Match live daemon identity including protocol compatibility."""

    # Same-release peers still require a current compatibility version.
    return _manager._guard_daemon_state_matches_current_runtime(payload)


def _guard_daemon_url_port(url: str) -> int | None:
    try:
        parsed = _manager.urllib.parse.urlparse(url)
        return parsed.port
    except ValueError:
        return None


def _adopt_existing_guard_daemon(
    guard_home: _manager.Path,
    *,
    preferred_port: int | None = None,
) -> str | None:
    if _manager.os.name == "nt":
        return None
    if isinstance(preferred_port, int) and preferred_port > 0:
        adopted = _manager._initialize_existing_guard_daemon(guard_home, preferred_port)
        if adopted is not None:
            _manager.write_guard_daemon_state(guard_home, preferred_port, adopted["auth_token"], pid=adopted["pid"])
            return adopted["url"]
    candidate_ports = _manager._adoptable_guard_daemon_ports(guard_home)
    if isinstance(preferred_port, int) and preferred_port > 0:
        candidate_ports = _manager._prepend_preferred_port(candidate_ports, preferred_port)
    for port in candidate_ports:
        adopted = _manager._initialize_existing_guard_daemon(guard_home, port)
        if adopted is None:
            continue
        _manager.write_guard_daemon_state(guard_home, port, adopted["auth_token"], pid=adopted["pid"])
        return adopted["url"]
    return None


def _adoptable_guard_daemon_ports(guard_home: _manager.Path) -> list[int]:
    preferred_ports: list[int] = []
    state = _manager._load_state(guard_home)
    state_port = state.get("port") if isinstance(state, dict) else None
    if isinstance(state_port, int) and state_port > 0:
        preferred_ports.append(state_port)
    configured_port = _manager._configured_port(guard_home)
    if isinstance(configured_port, int) and configured_port > 0:
        preferred_ports.append(configured_port)
    for _pid, port in _manager._running_guard_daemon_processes_for_guard_home(guard_home):
        preferred_ports.append(port)
    seen: set[int] = set()
    ordered: list[int] = []
    for port in preferred_ports:
        if port in seen:
            continue
        seen.add(port)
        ordered.append(port)
    return ordered


def _initialize_existing_guard_daemon(guard_home: _manager.Path, port: int) -> _manager._ExistingGuardDaemon | None:
    url = f"http://127.0.0.1:{port}"
    try:
        with _manager.urllib.request.urlopen(_manager._daemon_health_request(f"{url}/healthz"), timeout=1) as response:
            raw_payload = response.read().decode("utf-8")
            if response.status != 200 or not _manager._healthz_payload_is_current(raw_payload):
                return None
    except (OSError, ValueError, _manager.json.JSONDecodeError, _manager.urllib.error.URLError):
        return None
    auth_token = _manager.load_guard_daemon_auth_token(guard_home)
    if not isinstance(auth_token, str) or not auth_token.strip():
        return None
    details_payload = _manager._daemon_healthz_details_payload(url, auth_token)
    if (
        details_payload is None
        or not _manager._healthz_payload_matches_guard_home(_manager.json.dumps(details_payload), guard_home)
        or not _manager._daemon_healthz_details_match_current_runtime(details_payload)
    ):
        return None
    pid = details_payload.get("pid")
    if not isinstance(pid, int) or pid <= 0:
        return None
    return {"url": url, "auth_token": auth_token, "pid": pid}


def _retire_duplicate_guard_daemons(
    guard_home: _manager.Path,
    *,
    keep_port: int | None,
    start_lock_held: bool = False,
) -> None:
    if keep_port is None:
        return
    if start_lock_held:
        _manager._retire_duplicate_guard_daemons_unlocked(guard_home, keep_port=keep_port)
        return
    with _manager._guard_daemon_start_lock(guard_home):
        _manager._retire_duplicate_guard_daemons_unlocked(guard_home, keep_port=keep_port)


def _schedule_duplicate_guard_daemon_retirement(guard_home: _manager.Path) -> None:
    lock_key = str(guard_home.resolve())
    with _manager._DUPLICATE_RETIRE_SCHEDULE_LOCK:
        if _manager._DUPLICATE_RETIRE_IN_FLIGHT:
            return
        _manager._DUPLICATE_RETIRE_IN_FLIGHT.add(lock_key)
    retirement = _manager._retire_current_duplicate_guard_daemons

    def retire() -> None:
        try:
            retirement(guard_home)
        except Exception:
            # A later lifecycle call can retry this best-effort cleanup.
            pass
        finally:
            with _manager._DUPLICATE_RETIRE_SCHEDULE_LOCK:
                _manager._DUPLICATE_RETIRE_IN_FLIGHT.discard(lock_key)

    thread = _manager.threading.Thread(
        target=retire,
        name="guard-daemon-duplicate-retirement",
        daemon=True,
    )
    try:
        thread.start()
    except RuntimeError:
        with _manager._DUPLICATE_RETIRE_SCHEDULE_LOCK:
            _manager._DUPLICATE_RETIRE_IN_FLIGHT.discard(lock_key)


def _retire_current_duplicate_guard_daemons(guard_home: _manager.Path) -> None:
    with _manager._guard_daemon_start_lock(guard_home):
        current_url = _manager.load_guard_daemon_url(guard_home)
        keep_port = _manager._guard_daemon_url_port(current_url) if current_url is not None else None
        if keep_port is None:
            return
        _manager._retire_duplicate_guard_daemons_unlocked(guard_home, keep_port=keep_port)


def _retire_duplicate_guard_daemons_unlocked(guard_home: _manager.Path, *, keep_port: int) -> None:
    saw_duplicate = False
    for pid, port in _manager._running_guard_daemon_processes_for_guard_home(guard_home):
        if port == keep_port:
            continue
        saw_duplicate = True
        if not _manager._retire_guard_daemon_pid(pid, expected_guard_home=guard_home):
            return
    if not saw_duplicate:
        return
    if any(port != keep_port for _pid, port in _manager._running_guard_daemon_processes_for_guard_home(guard_home)):
        return
    _manager._rewrite_kept_daemon_state_if_missing(guard_home, keep_port=keep_port)


def _rewrite_kept_daemon_state_if_missing(guard_home: _manager.Path, *, keep_port: int) -> None:
    kept_pid = _manager._guard_daemon_pid_for_guard_home_port(guard_home, keep_port)
    if kept_pid is None or _manager._daemon_state_points_to(guard_home, pid=kept_pid, port=keep_port):
        return
    auth_token = _manager.load_guard_daemon_auth_token(guard_home)
    if auth_token is None:
        return
    daemon_url = f"http://127.0.0.1:{keep_port}"
    details = _manager._daemon_healthz_details_payload(daemon_url, auth_token)
    if details is None or not _manager._healthz_payload_matches_guard_home(_manager.json.dumps(details), guard_home):
        return
    if details.get("pid") != kept_pid:
        return
    _manager.write_guard_daemon_state(guard_home, keep_port, auth_token, pid=kept_pid, write_auth_token=False)


def _guard_daemon_pid_for_guard_home_port(guard_home: _manager.Path, port: int) -> int | None:
    for pid, candidate_port in _manager._running_guard_daemon_processes_for_guard_home(guard_home):
        if candidate_port == port:
            return pid
    return None
