"""Schedule in-dashboard Guard package updates from the local daemon."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import TextIO, TypedDict

from ..cli.update_commands import build_guard_update_status_payload

_DASHBOARD_UPDATE_LOCK = "dashboard-update.lock"
_DASHBOARD_UPDATE_OUTCOME = "dashboard-update-outcome.json"
_DASHBOARD_UPDATE_STALE_SECONDS = 15 * 60


class DashboardUpdateRunnerPopenKwargs(TypedDict):
    cwd: str
    env: dict[str, str]
    log_handle: TextIO


def dashboard_update_lock_path(guard_home: Path) -> Path:
    return guard_home / _DASHBOARD_UPDATE_LOCK


def read_dashboard_update_lock(guard_home: Path) -> dict[str, object] | None:
    lock_path = dashboard_update_lock_path(guard_home)
    if not lock_path.is_file():
        return None
    return _read_update_lock(lock_path)


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


def dashboard_update_outcome_path(guard_home: Path) -> Path:
    return guard_home.expanduser().resolve() / _DASHBOARD_UPDATE_OUTCOME


def read_dashboard_update_outcome(guard_home: Path) -> dict[str, object] | None:
    outcome_path = dashboard_update_outcome_path(guard_home)
    if not outcome_path.is_file():
        return None
    try:
        payload = json.loads(outcome_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def write_dashboard_update_outcome(guard_home: Path, update_payload: dict[str, object]) -> None:
    status = str(update_payload.get("status") or "")
    if status not in {"stale", "failed"}:
        clear_dashboard_update_outcome(guard_home)
        return
    version_check = update_payload.get("version_check")
    latest_version = update_payload.get("latest_version")
    if not isinstance(latest_version, str) and isinstance(version_check, dict):
        candidate = version_check.get("latest_version")
        latest_version = candidate if isinstance(candidate, str) else None
    current_version = update_payload.get("resulting_version") or update_payload.get("current_version")
    retry_command = update_payload.get("retry_command")
    outcome = {
        "status": status,
        "attempted_at": datetime.now(timezone.utc).isoformat(),
        "current_version": current_version,
        "target_version": latest_version,
        "retry_command": retry_command if isinstance(retry_command, str) else None,
        "message": update_payload.get("message"),
    }
    outcome_path = dashboard_update_outcome_path(guard_home)
    outcome_path.parent.mkdir(parents=True, exist_ok=True)
    outcome_path.write_text(json.dumps(outcome, indent=2), encoding="utf-8")


def clear_dashboard_update_outcome(guard_home: Path) -> None:
    dashboard_update_outcome_path(guard_home).unlink(missing_ok=True)


def merge_dashboard_update_outcome(
    guard_home: Path,
    status_payload: dict[str, object],
) -> dict[str, object]:
    payload = dict(status_payload)
    if payload.get("update_available") is not True:
        clear_dashboard_update_outcome(guard_home)
        return payload
    outcome = read_dashboard_update_outcome(guard_home)
    if outcome is None:
        return payload
    current_version = payload.get("current_version")
    latest_version = payload.get("latest_version")
    if (
        outcome.get("status") not in {"stale", "failed"}
        or outcome.get("current_version") != current_version
        or outcome.get("target_version") != latest_version
    ):
        clear_dashboard_update_outcome(guard_home)
        return payload
    payload["update_suppressed"] = True
    retry_command = outcome.get("retry_command")
    if isinstance(retry_command, str) and retry_command.strip():
        payload["retry_command"] = retry_command.strip()
    message = outcome.get("message")
    if isinstance(message, str) and message.strip():
        payload["update_attempt_message"] = message.strip()
    return payload


def merge_dashboard_update_progress(
    guard_home: Path,
    status_payload: dict[str, object],
) -> dict[str, object]:
    payload = merge_dashboard_update_outcome(guard_home, status_payload)
    if not dashboard_update_in_progress(guard_home):
        payload["update_in_progress"] = False
        return payload
    lock_payload = read_dashboard_update_lock(guard_home)
    if lock_payload is None:
        payload["update_in_progress"] = False
        return payload
    payload["update_in_progress"] = True
    for key in ("previous_version", "target_version", "daemon_port", "started_at"):
        value = lock_payload.get(key)
        if value is not None:
            payload[key] = value
    return payload


def dashboard_update_runner_script() -> Path:
    """Return the installed runner script path (never resolve via cwd or -m imports)."""
    return Path(__file__).resolve().with_name("dashboard_update_runner.py")


def build_dashboard_update_runner_command(
    guard_home: Path,
    *,
    daemon_pid: int,
    daemon_port: int,
    force_pypi_reinstall: bool = False,
) -> list[str]:
    resolved_home = guard_home.expanduser().resolve()
    runner_script = dashboard_update_runner_script()
    command = [sys.executable]
    if sys.version_info >= (3, 11):
        command.append("-P")
    command.extend(
        [
            str(runner_script),
            "--guard-home",
            str(resolved_home),
            "--daemon-pid",
            str(daemon_pid),
            "--daemon-port",
            str(daemon_port),
        ]
    )
    if force_pypi_reinstall:
        command.append("--force-pypi-reinstall")
    return command


def build_dashboard_update_runner_popen_kwargs(guard_home: Path) -> DashboardUpdateRunnerPopenKwargs:
    resolved_home = guard_home.expanduser().resolve()
    resolved_home.mkdir(parents=True, exist_ok=True)
    log_path = resolved_home / "dashboard-update.log"
    log_handle = log_path.open("a", encoding="utf-8")
    return {
        "cwd": str(resolved_home),
        "env": _runner_env(),
        "log_handle": log_handle,
    }


def schedule_guard_dashboard_update(
    guard_home: Path,
    daemon_pid: int,
    daemon_port: int,
    *,
    force_pypi_reinstall: bool = False,
) -> dict[str, object]:
    guard_home = guard_home.expanduser().resolve()
    if dashboard_update_in_progress(guard_home):
        return {
            "scheduled": False,
            "error": "update_in_progress",
            "message": "Guard is already updating on this machine.",
        }
    status_payload = build_guard_update_status_payload()
    lock_path = dashboard_update_lock_path(guard_home)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    command = build_dashboard_update_runner_command(
        guard_home,
        daemon_pid=daemon_pid,
        daemon_port=daemon_port,
        force_pypi_reinstall=force_pypi_reinstall,
    )
    popen_kwargs = build_dashboard_update_runner_popen_kwargs(guard_home)
    working_directory = popen_kwargs["cwd"]
    env = popen_kwargs["env"]
    log_handle = popen_kwargs["log_handle"]
    try:
        if os.name == "nt":
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=log_handle,
                cwd=working_directory,
                env=env,
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS,
            )
        else:
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=log_handle,
                cwd=working_directory,
                env=env,
                start_new_session=True,
            )
    finally:
        log_handle.close()
    _write_update_lock(
        lock_path,
        {
            "guard_home": str(guard_home),
            "daemon_pid": daemon_pid,
            "daemon_port": daemon_port,
            "runner_pid": process.pid,
            "previous_version": status_payload.get("current_version"),
            "target_version": status_payload.get("latest_version"),
            "started_at": datetime.now(timezone.utc).isoformat(),
        },
    )
    return {
        "scheduled": True,
        "message": "Guard will update, restart briefly, and reload this dashboard.",
        "runner_pid": process.pid,
        "previous_version": status_payload.get("current_version"),
        "target_version": status_payload.get("latest_version"),
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
