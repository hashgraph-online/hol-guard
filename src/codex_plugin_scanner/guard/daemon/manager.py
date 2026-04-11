"""Guard daemon lifecycle helpers."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


def ensure_guard_daemon(guard_home: Path) -> str:
    state_path = _state_path(guard_home)
    existing_url = load_guard_daemon_url(guard_home)
    if existing_url is not None:
        return existing_url
    command = [
        sys.executable,
        "-m",
        "codex_plugin_scanner.cli",
        "guard",
        "daemon",
        "--serve",
        "--guard-home",
        str(guard_home),
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
    subprocess.Popen(command, **kwargs)
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        url = load_guard_daemon_url(guard_home)
        if url is not None:
            return url
        time.sleep(0.1)
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
            if response.status == 200:
                return url
    except (OSError, urllib.error.URLError):
        return None
    return None


def write_guard_daemon_state(guard_home: Path, port: int) -> None:
    state_path = _state_path(guard_home)
    state_path.write_text(json.dumps({"port": port}, indent=2), encoding="utf-8")


def clear_guard_daemon_state(guard_home: Path) -> None:
    state_path = _state_path(guard_home)
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
