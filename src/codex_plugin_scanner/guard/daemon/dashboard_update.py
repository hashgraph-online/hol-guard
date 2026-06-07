"""Schedule in-dashboard Guard package updates from the local daemon."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

_DASHBOARD_UPDATE_LOCK = "dashboard-update.lock"
_DASHBOARD_UPDATE_STALE_SECONDS = 15 * 60


def dashboard_update_lock_path(guard_home: Path) -> Path:
    return guard_home / _DASHBOARD_UPDATE_LOCK


def dashboard_update_in_progress(guard_home: Path) -> bool:
    lock_path = dashboard_update_lock_path(guard_home)
    if not lock_path.is_file():
        return False
    payload = _read_update_lock(lock_path)
    if payload is None:
        lock_path.unlink(missing_ok=True)
        return False
    started_at = payload.get("started_at")
    if isinstance(started_at, str):
        try:
            started = datetime.fromisoformat(started_at)
            if started.tzinfo is None:
                started = started.replace(tzinfo=timezone.utc)
            age_seconds = max(0.0, (datetime.now(timezone.utc) - started).total_seconds())
            if age_seconds >= _DASHBOARD_UPDATE_STALE_SECONDS:
                lock_path.unlink(missing_ok=True)
                return False
        except ValueError:
            pass
    runner_pid = payload.get("runner_pid")
    if isinstance(runner_pid, int) and runner_pid > 0 and not _pid_is_running(runner_pid):
        lock_path.unlink(missing_ok=True)
        return False
    return True


def dashboard_update_runner_script() -> Path:
    """Return the installed runner script path (never resolve via cwd or -m imports)."""
    return Path(__file__).resolve().with_name("dashboard_update_runner.py")


def build_dashboard_update_runner_command(
    guard_home: Path,
    *,
    daemon_pid: int,
    daemon_port: int,
) -> list[str]:
    runner_script = dashboard_update_runner_script()
    command = [sys.executable]
    if sys.version_info >= (3, 11):
        command.append("-P")
    command.extend(
        [
            str(runner_script),
            "--guard-home",
            str(guard_home),
            "--daemon-pid",
            str(daemon_pid),
            "--daemon-port",
            str(daemon_port),
        ]
    )
    return command


def build_dashboard_update_runner_popen_kwargs(guard_home: Path) -> dict[str, object]:
    resolved_home = guard_home.expanduser().resolve()
    return {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "cwd": str(resolved_home),
        "env": _runner_env(),
    }


def schedule_guard_dashboard_update(
    guard_home: Path,
    daemon_pid: int,
    daemon_port: int,
) -> dict[str, object]:
    guard_home = guard_home.expanduser().resolve()
    if dashboard_update_in_progress(guard_home):
        return {
            "scheduled": False,
            "error": "update_in_progress",
            "message": "Guard is already updating on this machine.",
        }
    lock_path = dashboard_update_lock_path(guard_home)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    command = build_dashboard_update_runner_command(
        guard_home,
        daemon_pid=daemon_pid,
        daemon_port=daemon_port,
    )
    kwargs = build_dashboard_update_runner_popen_kwargs(guard_home)
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS
    else:
        kwargs["start_new_session"] = True
    process = subprocess.Popen(command, **kwargs)
    _write_update_lock(
        lock_path,
        {
            "guard_home": str(guard_home),
            "daemon_pid": daemon_pid,
            "daemon_port": daemon_port,
            "runner_pid": process.pid,
            "started_at": datetime.now(timezone.utc).isoformat(),
        },
    )
    return {
        "scheduled": True,
        "message": "Guard will update, restart briefly, and reload this dashboard.",
        "runner_pid": process.pid,
    }


def clear_dashboard_update_lock(guard_home: Path) -> None:
    dashboard_update_lock_path(guard_home).unlink(missing_ok=True)


def _runner_env() -> dict[str, str]:
    env = dict(os.environ)
    source_root = str(Path(__file__).resolve().parents[3])
    env["PYTHONPATH"] = source_root
    if sys.version_info >= (3, 11):
        env["PYTHONSAFEPATH"] = "1"
    return env


def _read_update_lock(lock_path: Path) -> dict[str, object] | None:
    try:
        payload = json.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _write_update_lock(lock_path: Path, payload: dict[str, object]) -> None:
    lock_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _pid_is_running(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True
