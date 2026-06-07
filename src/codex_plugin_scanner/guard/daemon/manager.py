"""Guard daemon lifecycle helpers."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import re
import shlex
import signal
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from contextlib import contextmanager, suppress
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO

from ...version import __version__

DEFAULT_GUARD_DAEMON_PORT = 4781
GUARD_DAEMON_PORT_RANGE = 1000
REQUIRED_DAEMON_TABLES = frozenset({"guard_connect_states"})
GUARD_DAEMON_COMPATIBILITY_VERSION = 2
GUARD_DAEMON_START_TIMEOUT_SECONDS = 5.0
GUARD_DAEMON_POST_UPDATE_START_TIMEOUT_SECONDS = 30.0
GUARD_DAEMON_POLL_INTERVAL_SECONDS = 0.1
_EPHEMERAL_GUARD_DAEMON_REAP_INTERVAL_SECONDS = 30.0
_EPHEMERAL_GUARD_DAEMON_STALE_SECONDS = 30.0
_EPHEMERAL_GUARD_DAEMON_MAX_STATES = 512
_GUARD_DAEMON_PRIVATE_FILE_MODE = 0o600
_GUARD_DAEMON_PRIVATE_DIR_MODE = 0o700
_APPROVAL_CENTER_LOCATOR_FILE = "approval-center-locator.json"

_START_LOCKS: dict[str, threading.Lock] = {}
_START_LOCKS_GUARD = threading.Lock()
_LAST_EPHEMERAL_REAP_AT = 0.0
_RUNTIME_FINGERPRINT_CACHE: str | None = None


@dataclasses.dataclass(frozen=True, slots=True)
class ApprovalCenterLocator:
    """Structured snapshot of where the Guard approval-center daemon is running."""

    guard_home: Path
    daemon_url: str
    approval_url_base: str
    pid: int
    started_at: str
    state_path: Path


def _daemon_launcher_env() -> dict[str, str]:
    env = dict(os.environ)
    pythonpath_entries: list[str] = []
    for raw_value in (str(Path(__file__).resolve().parents[3]), env.get("PYTHONPATH", "")):
        for entry in raw_value.split(os.pathsep):
            normalized = entry.strip()
            if normalized and normalized not in pythonpath_entries:
                pythonpath_entries.append(normalized)
    if pythonpath_entries:
        env["PYTHONPATH"] = os.pathsep.join(pythonpath_entries)
    return env


def ensure_guard_daemon(guard_home: Path, *, start_timeout: float | None = None) -> str:
    timeout = (
        GUARD_DAEMON_START_TIMEOUT_SECONDS
        if start_timeout is None
        else start_timeout
    )
    _reap_stale_ephemeral_guard_daemons(exclude_guard_home=guard_home)
    state_path = _state_path(guard_home)
    existing_url = load_guard_daemon_url(guard_home)
    if existing_url is not None:
        _retire_duplicate_guard_daemons(guard_home, keep_port=_guard_daemon_url_port(existing_url))
        return existing_url
    with _guard_daemon_start_lock(guard_home):
        existing_url = load_guard_daemon_url(guard_home)
        if existing_url is not None:
            _retire_duplicate_guard_daemons(guard_home, keep_port=_guard_daemon_url_port(existing_url))
            return existing_url
        adopted_url = _adopt_existing_guard_daemon(guard_home)
        if adopted_url is not None:
            _retire_duplicate_guard_daemons(guard_home, keep_port=_guard_daemon_url_port(adopted_url))
            return adopted_url
        stale_state = _load_state(guard_home)
        if isinstance(stale_state, dict) and not _guard_daemon_state_matches_current_runtime(stale_state):
            _retire_guard_daemon_process({**stale_state, "guard_home": str(guard_home)})
        if _guard_daemon_start_in_progress(guard_home):
            inflight_url = _wait_for_guard_daemon_url(guard_home, timeout=timeout)
            if inflight_url is not None:
                _retire_duplicate_guard_daemons(guard_home, keep_port=_guard_daemon_url_port(inflight_url))
                return inflight_url
        clear_guard_daemon_state(guard_home)
        for candidate_port in _candidate_ports(guard_home):
            command = [
                sys.executable,
                "-m",
                "codex_plugin_scanner.cli",
                "guard",
                "daemon",
                "--serve",
                "--guard-home",
                str(guard_home),
                "--port",
                str(candidate_port),
            ]
            kwargs: dict[str, object] = {
                "stdin": subprocess.DEVNULL,
                "stdout": subprocess.DEVNULL,
                "stderr": subprocess.DEVNULL,
                "env": _daemon_launcher_env(),
            }
            if os.name == "nt":
                kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS
            else:
                kwargs["start_new_session"] = True
            process = subprocess.Popen(command, **kwargs)
            url = _wait_for_guard_daemon_url(
                guard_home,
                timeout=timeout,
                process=process,
            )
            if url is not None:
                _retire_duplicate_guard_daemons(guard_home, keep_port=_guard_daemon_url_port(url))
                return url
    raise RuntimeError(f"Guard approval center did not start. Expected state file at {state_path}.")


def ensure_guard_daemon_after_update(guard_home: Path) -> str:
    """Restart the local daemon after a package update with a longer startup window."""
    return ensure_guard_daemon(
        guard_home,
        start_timeout=GUARD_DAEMON_POST_UPDATE_START_TIMEOUT_SECONDS,
    )


def retire_all_guard_daemons_for_home(
    guard_home: Path,
    *,
    keep_port: int | None = None,
) -> list[int]:
    """Stop Guard daemon processes for one guard home, optionally keeping one port alive."""
    retired: list[int] = []
    for pid, port in _running_guard_daemon_processes_for_guard_home(guard_home):
        if keep_port is not None and port == keep_port:
            continue
        if _retire_guard_daemon_pid(pid, expected_guard_home=guard_home):
            retired.append(pid)
    return retired


def guard_daemon_url_for_home(guard_home: Path) -> str:
    return f"http://127.0.0.1:{_configured_port(guard_home)}"


def load_guard_daemon_url(guard_home: Path) -> str | None:
    payload = _load_state(guard_home)
    if payload is None:
        return None
    if not _guard_daemon_state_matches_current_runtime(payload):
        return None
    port = payload.get("port")
    if not isinstance(port, int):
        return None
    pid = payload.get("pid")
    if not isinstance(pid, int) or pid <= 0 or not _guard_daemon_pid_is_running(pid):
        return None
    url = f"http://127.0.0.1:{port}"
    try:
        with urllib.request.urlopen(_daemon_health_request(f"{url}/healthz"), timeout=1) as response:
            raw_payload = response.read().decode("utf-8")
            if response.status != 200 or not _healthz_payload_is_current(raw_payload):
                return None
    except (OSError, ValueError, urllib.error.URLError):
        return None
    if _guard_daemon_pid_matches_command(pid, expected_guard_home=guard_home):
        return url
    # In-process or wrapped daemons may not expose a command line we can bind
    # back to guard_home, so fall back to authenticated detailed health.
    auth_token = load_guard_daemon_auth_token(guard_home)
    if auth_token and _daemon_healthz_details_match_guard_home(url, guard_home, auth_token=auth_token):
        return url
    compatibility_version = payload.get("compatibility_version")
    if compatibility_version != GUARD_DAEMON_COMPATIBILITY_VERSION:
        return None
    return None


def load_guard_daemon_auth_token(guard_home: Path) -> str | None:
    token_path = _auth_token_path(guard_home)
    try:
        token = token_path.read_text(encoding="utf-8").strip()
    except OSError:
        token = ""
    if token:
        return token
    payload = _load_state(guard_home)
    if payload is None:
        return None
    token = payload.get("auth_token")
    return token if isinstance(token, str) and token.strip() else None


def _daemon_health_request(url: str, auth_token: str | None = None) -> urllib.request.Request:
    headers: dict[str, str] = {}
    if isinstance(auth_token, str) and auth_token.strip():
        headers["X-Guard-Token"] = auth_token
    return urllib.request.Request(url, headers=headers, method="GET")


def _daemon_healthz_details_payload(url: str, auth_token: str) -> dict[str, object] | None:
    try:
        request = _daemon_health_request(f"{url}/v1/healthz/details", auth_token)
        with urllib.request.urlopen(request, timeout=1) as response:
            if response.status != 200:
                return None
            payload = json.loads(response.read().decode("utf-8"))
    except (OSError, ValueError, json.JSONDecodeError, urllib.error.URLError):
        return None
    return payload if isinstance(payload, dict) else None


def _daemon_healthz_details_match_guard_home(url: str, guard_home: Path, *, auth_token: str) -> bool:
    payload = _daemon_healthz_details_payload(url, auth_token)
    if payload is None:
        return False
    return _healthz_payload_matches_guard_home(json.dumps(payload), guard_home)


def _guard_daemon_url_port(url: str) -> int | None:
    try:
        parsed = urllib.parse.urlparse(url)
        return parsed.port
    except ValueError:
        return None


def _adopt_existing_guard_daemon(guard_home: Path) -> str | None:
    if os.name == "nt":
        return None
    candidate_ports = _adoptable_guard_daemon_ports(guard_home)
    for port in candidate_ports:
        adopted = _initialize_existing_guard_daemon(guard_home, port)
        if adopted is None:
            continue
        write_guard_daemon_state(guard_home, port, adopted["auth_token"], pid=adopted["pid"])
        return adopted["url"]
    return None


def _adoptable_guard_daemon_ports(guard_home: Path) -> list[int]:
    preferred_ports: list[int] = []
    state = _load_state(guard_home)
    state_port = state.get("port") if isinstance(state, dict) else None
    if isinstance(state_port, int) and state_port > 0:
        preferred_ports.append(state_port)
    configured_port = _configured_port(guard_home)
    if isinstance(configured_port, int) and configured_port > 0:
        preferred_ports.append(configured_port)
    for _pid, port in _running_guard_daemon_processes_for_guard_home(guard_home):
        preferred_ports.append(port)
    seen: set[int] = set()
    ordered: list[int] = []
    for port in preferred_ports:
        if port in seen:
            continue
        seen.add(port)
        ordered.append(port)
    return ordered


def _initialize_existing_guard_daemon(guard_home: Path, port: int) -> dict[str, str | int] | None:
    url = f"http://127.0.0.1:{port}"
    try:
        with urllib.request.urlopen(_daemon_health_request(f"{url}/healthz"), timeout=1) as response:
            raw_payload = response.read().decode("utf-8")
            if response.status != 200 or not _healthz_payload_is_current(raw_payload):
                return None
    except (OSError, ValueError, json.JSONDecodeError, urllib.error.URLError):
        return None
    auth_token = load_guard_daemon_auth_token(guard_home)
    if not isinstance(auth_token, str) or not auth_token.strip():
        return None
    details_payload = _daemon_healthz_details_payload(url, auth_token)
    if details_payload is None or not _healthz_payload_matches_guard_home(json.dumps(details_payload), guard_home):
        return None
    pid = details_payload.get("pid")
    if not isinstance(pid, int) or pid <= 0:
        return None
    return {"url": url, "auth_token": auth_token, "pid": pid}


def _retire_duplicate_guard_daemons(guard_home: Path, *, keep_port: int | None) -> None:
    if keep_port is None:
        return
    for pid, port in _running_guard_daemon_processes_for_guard_home(guard_home):
        if port == keep_port:
            continue
        _retire_guard_daemon_pid(pid, expected_guard_home=guard_home)


def _guard_daemon_pid_for_guard_home_port(guard_home: Path, port: int) -> int | None:
    for pid, candidate_port in _running_guard_daemon_processes_for_guard_home(guard_home):
        if candidate_port == port:
            return pid
    return None


def write_guard_daemon_state(guard_home: Path, port: int, auth_token: str, *, pid: int | None = None) -> None:
    state_path = _state_path(guard_home)
    _ensure_private_directory(state_path.parent)
    _write_private_text(
        state_path,
        json.dumps(
            {
                "guard_home": str(guard_home),
                "port": port,
                "compatibility_version": GUARD_DAEMON_COMPATIBILITY_VERSION,
                "package_version": __version__,
                "source_root": _current_guard_daemon_source_root(),
                "runtime_fingerprint": _current_guard_daemon_runtime_fingerprint(),
                "pid": pid if isinstance(pid, int) and pid > 0 else os.getpid(),
                "started_at": datetime.now(timezone.utc).isoformat(),
            },
            indent=2,
        ),
    )
    _write_private_text(_auth_token_path(guard_home), auth_token)


def clear_guard_daemon_state(guard_home: Path) -> None:
    state_path = _state_path(guard_home)
    _ensure_private_directory(state_path.parent)
    _write_private_text(state_path, "{}")


def repair_approval_center_locator(guard_home: Path) -> dict[str, object]:
    """Remove a stale approval center locator and optionally clear dead daemon state.

    Only clears daemon-state.json when the recorded PID is no longer running,
    so a live daemon's state is not disturbed.  Raises OSError if a required
    write fails so callers can detect incomplete repair.

    Safe to call while the database is live.  Returns a dict describing what was cleared.
    """
    cleared: list[str] = []
    locator = _locator_path(guard_home)
    if locator.is_file():
        locator.unlink()
        cleared.append("locator")
    state = _state_path(guard_home)
    if state.is_file():
        state_payload = _load_state(guard_home)
        pid = state_payload.get("pid") if isinstance(state_payload, dict) else None
        daemon_is_live = (
            isinstance(pid, int)
            and pid > 0
            and _guard_daemon_pid_is_running(pid)
            and _guard_daemon_pid_matches_command(pid, expected_guard_home=guard_home)
        )
        if not daemon_is_live:
            _write_private_text(state, "{}")
            cleared.append("daemon_state")
    return {"repaired": True, "cleared": cleared}


def _locator_path(guard_home: Path) -> Path:
    return guard_home / _APPROVAL_CENTER_LOCATOR_FILE


def write_approval_center_locator(guard_home: Path, locator: ApprovalCenterLocator) -> None:
    locator_path = _locator_path(guard_home)
    _ensure_private_directory(locator_path.parent)
    payload = {
        "guard_home": str(locator.guard_home),
        "daemon_url": locator.daemon_url,
        "approval_url_base": locator.approval_url_base,
        "pid": locator.pid,
        "started_at": locator.started_at,
        "state_path": str(locator.state_path),
    }
    _write_private_text(locator_path, json.dumps(payload, indent=2))


def read_approval_center_locator(guard_home: Path) -> ApprovalCenterLocator | None:
    locator_path = _locator_path(guard_home)
    if not locator_path.is_file():
        return None
    try:
        payload = json.loads(locator_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    pid = payload.get("pid")
    if not isinstance(pid, int) or pid <= 0:
        return None
    if not _guard_daemon_pid_is_running(pid):
        return None
    if not _guard_daemon_pid_matches_command(pid, expected_guard_home=guard_home):
        return None
    daemon_url = payload.get("daemon_url")
    approval_url_base = payload.get("approval_url_base")
    started_at = payload.get("started_at")
    state_path_str = payload.get("state_path")
    guard_home_str = payload.get("guard_home")
    if not all(isinstance(v, str) for v in (daemon_url, approval_url_base, started_at, state_path_str, guard_home_str)):
        return None
    return ApprovalCenterLocator(
        guard_home=Path(guard_home_str),
        daemon_url=daemon_url,
        approval_url_base=approval_url_base,
        pid=pid,
        started_at=started_at,
        state_path=Path(state_path_str),
    )


def _approval_center_daemon_is_healthy(daemon_url: str) -> bool:
    try:
        with urllib.request.urlopen(f"{daemon_url}/healthz", timeout=1) as response:
            if response.status != 200:
                return False
            return _healthz_payload_is_current(response.read().decode("utf-8"))
    except (OSError, ValueError, urllib.error.URLError):
        return False


def _daemon_state_pid_matches_locator(guard_home: Path, locator_pid: int) -> bool:
    state = _load_state(guard_home)
    if not isinstance(state, dict):
        return False
    state_pid = state.get("pid")
    return isinstance(state_pid, int) and state_pid == locator_pid


def ensure_approval_center(guard_home: Path) -> ApprovalCenterLocator:
    existing = read_approval_center_locator(guard_home)
    if (
        existing is not None
        and _approval_center_daemon_is_healthy(existing.daemon_url)
        and _daemon_state_pid_matches_locator(guard_home, existing.pid)
    ):
        return existing
    daemon_url = ensure_guard_daemon(guard_home)
    now = datetime.now(tz=timezone.utc).isoformat()
    state = _load_state(guard_home)
    pid = state.get("pid") if isinstance(state, dict) else None
    if not isinstance(pid, int) or pid <= 0:
        pid = os.getpid()
    locator = ApprovalCenterLocator(
        guard_home=guard_home,
        daemon_url=daemon_url,
        approval_url_base=daemon_url,
        pid=pid,
        started_at=now,
        state_path=_state_path(guard_home),
    )
    write_approval_center_locator(guard_home, locator)
    return locator


def _load_state(guard_home: Path) -> dict[str, object] | None:
    state_path = _state_path(guard_home)
    if not state_path.is_file():
        return None
    try:
        payload = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _looks_like_guard_daemon_state(payload: dict[str, object], *, guard_home: Path) -> bool:
    compatibility_version = payload.get("compatibility_version")
    source_root = payload.get("source_root")
    runtime_fingerprint = payload.get("runtime_fingerprint")
    if compatibility_version != GUARD_DAEMON_COMPATIBILITY_VERSION:
        return False
    if not isinstance(source_root, str) or not source_root.strip():
        return False
    if not isinstance(runtime_fingerprint, str) or not runtime_fingerprint.strip():
        return False
    payload_guard_home = payload.get("guard_home")
    if isinstance(payload_guard_home, str) and payload_guard_home.strip():
        try:
            return Path(payload_guard_home).resolve() == guard_home.resolve()
        except OSError:
            return Path(payload_guard_home) == guard_home
    return True


def _state_path(guard_home: Path) -> Path:
    return guard_home / "daemon-state.json"


def _auth_token_path(guard_home: Path) -> Path:
    return guard_home / "daemon-auth-token"


def _ensure_private_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    _set_private_mode(path, _GUARD_DAEMON_PRIVATE_DIR_MODE)


def _write_private_text(path: Path, text: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, _GUARD_DAEMON_PRIVATE_FILE_MODE)
    if os.name != "nt" and hasattr(os, "fchmod"):
        with suppress(OSError):
            os.fchmod(descriptor, _GUARD_DAEMON_PRIVATE_FILE_MODE)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(text)
    _set_private_mode(path, _GUARD_DAEMON_PRIVATE_FILE_MODE)


def _set_private_mode(path: Path, mode: int) -> None:
    if os.name == "nt":
        return
    try:
        os.chmod(path, mode)
    except OSError:
        return


def _reap_stale_ephemeral_guard_daemons(*, exclude_guard_home: Path | None = None) -> None:
    global _LAST_EPHEMERAL_REAP_AT
    now = time.monotonic()
    if now - _LAST_EPHEMERAL_REAP_AT < _EPHEMERAL_GUARD_DAEMON_REAP_INTERVAL_SECONDS:
        return
    _LAST_EPHEMERAL_REAP_AT = now
    temp_root = Path(tempfile.gettempdir())
    candidate_paths = list(_ephemeral_guard_daemon_state_paths(temp_root))
    exclude_resolved = exclude_guard_home.resolve() if exclude_guard_home is not None else None
    for state_path in candidate_paths[:_EPHEMERAL_GUARD_DAEMON_MAX_STATES]:
        guard_home = state_path.parent
        try:
            resolved_guard_home = guard_home.resolve()
        except OSError:
            continue
        if exclude_resolved is not None and resolved_guard_home == exclude_resolved:
            continue
        if not _guard_home_is_ephemeral(resolved_guard_home):
            continue
        if _state_path_age_seconds(state_path) < _EPHEMERAL_GUARD_DAEMON_STALE_SECONDS:
            continue
        if not _ephemeral_guard_home_is_inactive(guard_home, fallback_age_seconds=_state_path_age_seconds(state_path)):
            continue
        payload = _load_state(guard_home)
        if not isinstance(payload, dict) or not _looks_like_guard_daemon_state(payload, guard_home=guard_home):
            continue
        payload = {**payload, "guard_home": str(guard_home)}
        if _retire_guard_daemon_process(payload):
            clear_guard_daemon_state(guard_home)
    for pid, guard_home, elapsed_seconds in _running_ephemeral_guard_daemon_processes():
        if elapsed_seconds < _EPHEMERAL_GUARD_DAEMON_STALE_SECONDS:
            continue
        try:
            resolved_guard_home = guard_home.resolve()
        except OSError:
            continue
        if exclude_resolved is not None and resolved_guard_home == exclude_resolved:
            continue
        if not _ephemeral_guard_home_is_inactive(guard_home, fallback_age_seconds=elapsed_seconds):
            continue
        if _retire_guard_daemon_pid(pid, expected_guard_home=guard_home):
            clear_guard_daemon_state(guard_home)


def _ephemeral_guard_daemon_state_paths(temp_root: Path) -> list[Path]:
    results: list[Path] = []
    for root in _pytest_temp_roots(temp_root):
        _collect_daemon_state_paths(root, results, limit=_EPHEMERAL_GUARD_DAEMON_MAX_STATES)
        if len(results) >= _EPHEMERAL_GUARD_DAEMON_MAX_STATES:
            break
    return sorted(results)


def _pytest_temp_roots(temp_root: Path) -> list[Path]:
    roots: list[Path] = []
    try:
        if _path_name_looks_like_pytest_temp_root(temp_root.name):
            roots.append(temp_root)
        with os.scandir(temp_root) as entries:
            for entry in entries:
                if not entry.is_dir(follow_symlinks=False):
                    continue
                if _path_name_looks_like_pytest_temp_root(entry.name):
                    roots.append(Path(entry.path))
    except OSError:
        return []
    return sorted(roots)


def _path_name_looks_like_pytest_temp_root(name: str) -> bool:
    return name.startswith("pytest-") or "pytest-of-" in name


def _collect_daemon_state_paths(root: Path, results: list[Path], *, limit: int) -> None:
    pending: list[Path] = [root]
    while pending and len(results) < limit:
        current = pending.pop()
        try:
            with os.scandir(current) as entries:
                directories: list[Path] = []
                files: list[Path] = []
                for entry in entries:
                    if entry.is_dir(follow_symlinks=False):
                        directories.append(Path(entry.path))
                    elif entry.is_file(follow_symlinks=False) and entry.name == "daemon-state.json":
                        files.append(Path(entry.path))
        except OSError:
            continue
        for path in sorted(files):
            results.append(path)
            if len(results) >= limit:
                return
        pending.extend(reversed(sorted(directories)))


def _state_path_age_seconds(state_path: Path) -> float:
    try:
        return max(0.0, time.time() - state_path.stat().st_mtime)
    except OSError:
        return 0.0


def _guard_home_is_ephemeral(guard_home: Path) -> bool:
    return any(part.startswith("pytest-") or "pytest-of-" in part for part in guard_home.parts)


def _ephemeral_guard_home_is_inactive(guard_home: Path, *, fallback_age_seconds: float) -> bool:
    heartbeat_age_seconds = _runtime_state_age_seconds(guard_home)
    if heartbeat_age_seconds is None:
        return fallback_age_seconds >= _EPHEMERAL_GUARD_DAEMON_STALE_SECONDS
    return heartbeat_age_seconds >= _EPHEMERAL_GUARD_DAEMON_STALE_SECONDS


def _runtime_state_age_seconds(guard_home: Path) -> float | None:
    try:
        from ..store import GuardStore

        runtime_state = GuardStore(guard_home).get_runtime_state()
    except Exception:
        return None
    if not isinstance(runtime_state, dict):
        return None
    last_heartbeat_at = runtime_state.get("last_heartbeat_at")
    if not isinstance(last_heartbeat_at, str) or not last_heartbeat_at.strip():
        return None
    try:
        heartbeat = datetime.fromisoformat(last_heartbeat_at)
    except ValueError:
        return None
    if heartbeat.tzinfo is None:
        heartbeat = heartbeat.replace(tzinfo=timezone.utc)
    return max(0.0, (datetime.now(timezone.utc) - heartbeat).total_seconds())


def _running_ephemeral_guard_daemon_processes() -> list[tuple[int, Path, float]]:
    if os.name == "nt":
        return []
    try:
        result = subprocess.run(
            ["ps", "-axo", "pid=,etime=,command="],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return []
    processes: list[tuple[int, Path, float]] = []
    for line in result.stdout.splitlines():
        match = re.match(r"^\s*(\d+)\s+(\S+)\s+(.*)$", line)
        if match is None:
            continue
        pid = int(match.group(1))
        elapsed_seconds = _elapsed_seconds_from_ps(match.group(2))
        command = match.group(3).strip()
        if "codex_plugin_scanner.cli guard daemon --serve" not in command:
            continue
        guard_home = _guard_home_from_command(command)
        if guard_home is None or not _guard_home_is_ephemeral(guard_home):
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


def _guard_home_from_command(command: str) -> Path | None:
    try:
        parts = shlex.split(command)
    except ValueError:
        return None
    for index, part in enumerate(parts):
        if part == "--guard-home" and index + 1 < len(parts):
            return Path(parts[index + 1])
    return None


def _guard_daemon_port_from_command(command: str) -> int | None:
    try:
        parts = shlex.split(command)
    except ValueError:
        return None
    for index, part in enumerate(parts):
        if part.startswith("--port="):
            try:
                port = int(part.split("=", 1)[1])
            except ValueError:
                return None
            return port if port > 0 else None
        if part != "--port" or index + 1 >= len(parts):
            continue
        try:
            port = int(parts[index + 1])
        except ValueError:
            return None
        return port if port > 0 else None
    return None


def _running_guard_daemon_processes_for_guard_home(guard_home: Path) -> list[tuple[int, int]]:
    if os.name == "nt":
        return []
    try:
        result = subprocess.run(
            ["ps", "-axo", "pid=,command="],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    processes: list[tuple[int, int]] = []
    for line in result.stdout.splitlines():
        match = re.match(r"^\s*(\d+)\s+(.*)$", line)
        if match is None:
            continue
        pid = int(match.group(1))
        command = match.group(2).strip()
        if "codex_plugin_scanner.cli" not in command or "guard daemon --serve" not in command:
            continue
        command_guard_home = _guard_home_from_command(command)
        port = _guard_daemon_port_from_command(command)
        if command_guard_home is None or port is None:
            continue
        try:
            matches_home = command_guard_home.resolve() == guard_home.resolve()
        except OSError:
            matches_home = command_guard_home == guard_home
        if matches_home:
            processes.append((pid, port))
    return sorted(processes, key=lambda item: item[1])


def _guard_daemon_state_matches_current_runtime(payload: dict[str, object]) -> bool:
    compatibility_version = payload.get("compatibility_version")
    if compatibility_version != GUARD_DAEMON_COMPATIBILITY_VERSION:
        return False
    source_root = payload.get("source_root")
    if not isinstance(source_root, str) or source_root != _current_guard_daemon_source_root():
        return False
    runtime_fingerprint = payload.get("runtime_fingerprint")
    return isinstance(runtime_fingerprint, str) and runtime_fingerprint == _current_guard_daemon_runtime_fingerprint()


def _current_guard_daemon_source_root() -> str:
    return str(Path(__file__).resolve().parents[3])


def _current_guard_daemon_runtime_fingerprint() -> str:
    global _RUNTIME_FINGERPRINT_CACHE
    if _RUNTIME_FINGERPRINT_CACHE is not None:
        return _RUNTIME_FINGERPRINT_CACHE
    source_root = Path(_current_guard_daemon_source_root())
    package_root = source_root / "codex_plugin_scanner"
    static_root = package_root / "guard" / "daemon" / "static"
    digest = hashlib.sha256()
    digest.update(__version__.encode("utf-8"))
    paths = [*package_root.rglob("*.py")]
    if static_root.is_dir():
        paths.extend(path for path in static_root.rglob("*") if path.is_file())
    for path in sorted(paths):
        try:
            stat_result = path.stat()
        except OSError:
            continue
        digest.update(str(path.relative_to(source_root)).encode("utf-8"))
        digest.update(str(stat_result.st_mtime_ns).encode("utf-8"))
        digest.update(str(stat_result.st_size).encode("utf-8"))
    _RUNTIME_FINGERPRINT_CACHE = digest.hexdigest()
    return _RUNTIME_FINGERPRINT_CACHE


def _guard_daemon_start_in_progress(guard_home: Path) -> bool:
    payload = _load_state(guard_home)
    if not isinstance(payload, dict):
        return False
    compatibility_version = payload.get("compatibility_version")
    if compatibility_version != GUARD_DAEMON_COMPATIBILITY_VERSION:
        return False
    pid = payload.get("pid")
    return isinstance(pid, int) and pid > 0 and _guard_daemon_pid_is_running(pid)


def _guard_daemon_pid_is_running(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def _guard_daemon_pid_matches_command(pid: int, expected_guard_home: Path | None = None) -> bool:
    command = _guard_daemon_command_for_pid(pid)
    if command is None:
        return False
    if "codex_plugin_scanner.cli" not in command or "guard daemon --serve" not in command:
        return False
    if expected_guard_home is None:
        return True
    command_guard_home = _guard_home_from_command(command)
    if command_guard_home is None:
        return False
    try:
        return command_guard_home.resolve() == expected_guard_home.resolve()
    except OSError:
        return command_guard_home == expected_guard_home


def _guard_daemon_command_for_pid(pid: int) -> str | None:
    if os.name == "nt":
        command = [
            "powershell",
            "-NoProfile",
            "-Command",
            f'(Get-CimInstance Win32_Process -Filter "ProcessId = {pid}").CommandLine',
        ]
    else:
        command = ["ps", "-p", str(pid), "-o", "command="]
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return None
    stdout = result.stdout.strip()
    return stdout or None


def _retire_guard_daemon_process(payload: dict[str, object]) -> bool:
    pid = payload.get("pid")
    if not isinstance(pid, int) or pid <= 0:
        return False
    guard_home = payload.get("guard_home")
    expected_guard_home = Path(guard_home) if isinstance(guard_home, str) and guard_home.strip() else None
    return _retire_guard_daemon_pid(pid, expected_guard_home=expected_guard_home)


def _retire_guard_daemon_pid(pid: int, *, expected_guard_home: Path | None = None) -> bool:
    if not _guard_daemon_pid_is_running(pid):
        return True
    if not _guard_daemon_pid_matches_command(pid, expected_guard_home):
        return False
    try:
        os.kill(pid, signal.SIGTERM)
    except OSError:
        return True
    deadline = time.monotonic() + 1.0
    while time.monotonic() < deadline:
        if not _guard_daemon_pid_is_running(pid):
            return True
        time.sleep(GUARD_DAEMON_POLL_INTERVAL_SECONDS)
    sigkill = getattr(signal, "SIGKILL", None)
    if sigkill is None:
        return False
    try:
        os.kill(pid, sigkill)
    except OSError:
        return True
    return not _guard_daemon_pid_is_running(pid)


def _wait_for_guard_daemon_url(
    guard_home: Path,
    *,
    timeout: float,
    process: subprocess.Popen[bytes] | None = None,
) -> str | None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        url = load_guard_daemon_url(guard_home)
        if url is not None:
            return url
        if process is not None and process.poll() is not None:
            return None
        time.sleep(GUARD_DAEMON_POLL_INTERVAL_SECONDS)
    return None


@contextmanager
def _guard_daemon_start_lock(guard_home: Path):
    lock_key = str(guard_home.resolve())
    with _START_LOCKS_GUARD:
        thread_lock = _START_LOCKS.setdefault(lock_key, threading.Lock())
    with thread_lock:
        lock_path = guard_home / "daemon-start.lock"
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        with lock_path.open("a+b") as handle:
            _lock_daemon_start_file(handle)
            try:
                yield
            finally:
                _unlock_daemon_start_file(handle)


def _lock_daemon_start_file(handle: BinaryIO) -> None:
    if os.name == "nt":
        import msvcrt

        handle.seek(0)
        if os.fstat(handle.fileno()).st_size == 0:
            handle.write(b"0")
            handle.flush()
        handle.seek(0)
        while True:
            try:
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                return
            except OSError:
                time.sleep(GUARD_DAEMON_POLL_INTERVAL_SECONDS)
        return
    import fcntl

    fcntl.flock(handle.fileno(), fcntl.LOCK_EX)


def _unlock_daemon_start_file(handle: BinaryIO) -> None:
    if os.name == "nt":
        import msvcrt

        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        return
    import fcntl

    fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def _configured_port(guard_home: Path) -> int | None:
    raw_port = os.environ.get("GUARD_DAEMON_PORT")
    if raw_port is None or not raw_port.strip():
        return _stable_port_for_guard_home(guard_home)
    try:
        port = int(raw_port)
    except ValueError:
        return _stable_port_for_guard_home(guard_home)
    return port if port > 0 else _stable_port_for_guard_home(guard_home)


def _stable_port_for_guard_home(guard_home: Path) -> int:
    encoded_path = str(guard_home.resolve()).encode("utf-8")
    digest = hashlib.sha256(encoded_path).hexdigest()
    offset = int(digest[:8], 16) % GUARD_DAEMON_PORT_RANGE
    return DEFAULT_GUARD_DAEMON_PORT + offset


def _candidate_ports(guard_home: Path) -> list[int]:
    configured_port = _configured_port(guard_home)
    if configured_port is None:
        return []
    raw_port = os.environ.get("GUARD_DAEMON_PORT")
    if raw_port is not None and raw_port.strip():
        return [configured_port]
    offset = configured_port - DEFAULT_GUARD_DAEMON_PORT
    ports: list[int] = []
    for step in range(min(25, GUARD_DAEMON_PORT_RANGE)):
        candidate_offset = (offset + step) % GUARD_DAEMON_PORT_RANGE
        ports.append(DEFAULT_GUARD_DAEMON_PORT + candidate_offset)
    return ports


def _healthz_payload_is_current(raw_payload: str) -> bool:
    payload = json.loads(raw_payload)
    if not isinstance(payload, dict):
        return False
    compatibility_version = payload.get("compatibility_version")
    if compatibility_version != GUARD_DAEMON_COMPATIBILITY_VERSION:
        return False
    tables = payload.get("tables")
    if tables is None:
        return True
    if not isinstance(tables, list):
        return False
    table_names = {table for table in tables if isinstance(table, str)}
    return REQUIRED_DAEMON_TABLES.issubset(table_names)


def _healthz_payload_matches_guard_home(raw_payload: str, guard_home: Path) -> bool:
    payload = json.loads(raw_payload)
    if not isinstance(payload, dict):
        return False
    payload_guard_home = payload.get("guard_home")
    if not isinstance(payload_guard_home, str) or not payload_guard_home.strip():
        return False
    try:
        return Path(payload_guard_home).resolve() == guard_home.resolve()
    except OSError:
        return Path(payload_guard_home) == guard_home
