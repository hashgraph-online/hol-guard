"""Guard daemon lifecycle helpers."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO

from ...version import __version__

DEFAULT_GUARD_DAEMON_PORT = 4781
GUARD_DAEMON_PORT_RANGE = 1000
REQUIRED_DAEMON_TABLES = frozenset({"guard_connect_states"})
GUARD_DAEMON_COMPATIBILITY_VERSION = 2
GUARD_DAEMON_START_TIMEOUT_SECONDS = 5.0
GUARD_DAEMON_POLL_INTERVAL_SECONDS = 0.1

_START_LOCKS: dict[str, threading.Lock] = {}
_START_LOCKS_GUARD = threading.Lock()


def ensure_guard_daemon(guard_home: Path) -> str:
    state_path = _state_path(guard_home)
    existing_url = load_guard_daemon_url(guard_home)
    if existing_url is not None:
        return existing_url
    with _guard_daemon_start_lock(guard_home):
        existing_url = load_guard_daemon_url(guard_home)
        if existing_url is not None:
            return existing_url
        if _guard_daemon_start_in_progress(guard_home):
            inflight_url = _wait_for_guard_daemon_url(guard_home, timeout=GUARD_DAEMON_START_TIMEOUT_SECONDS)
            if inflight_url is not None:
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
            }
            if os.name == "nt":
                kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS
            else:
                kwargs["start_new_session"] = True
            process = subprocess.Popen(command, **kwargs)
            url = _wait_for_guard_daemon_url(
                guard_home,
                timeout=GUARD_DAEMON_START_TIMEOUT_SECONDS,
                process=process,
            )
            if url is not None:
                return url
    raise RuntimeError(f"Guard approval center did not start. Expected state file at {state_path}.")


def load_guard_daemon_url(guard_home: Path) -> str | None:
    payload = _load_state(guard_home)
    if payload is None:
        return None
    port = payload.get("port")
    if not isinstance(port, int):
        return None
    url = f"http://127.0.0.1:{port}"
    try:
        with urllib.request.urlopen(f"{url}/healthz", timeout=1) as response:
            if response.status == 200 and _healthz_payload_is_current(response.read().decode("utf-8")):
                return url
    except (OSError, ValueError, urllib.error.URLError):
        return None
    compatibility_version = payload.get("compatibility_version")
    if compatibility_version != GUARD_DAEMON_COMPATIBILITY_VERSION:
        return None
    return None


def load_guard_daemon_auth_token(guard_home: Path) -> str | None:
    payload = _load_state(guard_home)
    if payload is None:
        return None
    token = payload.get("auth_token")
    return token if isinstance(token, str) and token.strip() else None


def write_guard_daemon_state(guard_home: Path, port: int, auth_token: str) -> None:
    state_path = _state_path(guard_home)
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(
        json.dumps(
            {
                "port": port,
                "auth_token": auth_token,
                "compatibility_version": GUARD_DAEMON_COMPATIBILITY_VERSION,
                "package_version": __version__,
                "pid": os.getpid(),
            },
            indent=2,
        ),
        encoding="utf-8",
    )


def clear_guard_daemon_state(guard_home: Path) -> None:
    state_path = _state_path(guard_home)
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text("{}", encoding="utf-8")


def _load_state(guard_home: Path) -> dict[str, object] | None:
    state_path = _state_path(guard_home)
    if not state_path.is_file():
        return None
    try:
        payload = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _state_path(guard_home: Path) -> Path:
    return guard_home / "daemon-state.json"


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
    if not isinstance(tables, list):
        return False
    table_names = {table for table in tables if isinstance(table, str)}
    return REQUIRED_DAEMON_TABLES.issubset(table_names)
