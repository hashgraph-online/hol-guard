"""Schedule in-dashboard Guard package updates from the local daemon."""

from __future__ import annotations

import json
import os
import secrets
import stat
import subprocess
import sys
import sysconfig
from contextlib import suppress
from datetime import datetime, timezone
from pathlib import Path
from typing import NamedTuple, TextIO, TypedDict

from ..cli.update_commands import build_guard_update_status_payload
from ..windows_paths import windows_process_is_running

_DASHBOARD_UPDATE_LOCK = "dashboard-update.lock"
_DASHBOARD_UPDATE_OUTCOME = "dashboard-update-outcome.json"
# A trusted update may make two independent ten-minute installer attempts before
# it reaches its daemon refresh. Keep a live reservation beyond that entire
# window so a slow update can never overlap a second installer.
_DASHBOARD_UPDATE_STALE_SECONDS = 30 * 60
_DASHBOARD_UPDATE_LOCK_MAX_BYTES = 64 * 1024
_DASHBOARD_UPDATE_RUNNER_BOOTSTRAP = (
    "import json, sys; "
    "trusted_prefix = sys.argv.pop(1); "
    "trusted_exec_prefix = sys.argv.pop(1); "
    "trusted_paths = json.loads(sys.argv.pop(1)); "
    "runner_script = sys.argv.pop(1); "
    "sys.prefix = trusted_prefix; "
    "sys.exec_prefix = trusted_exec_prefix; "
    "sys.path[:0] = trusted_paths; "
    "import runpy; "
    "sys.argv[0] = runner_script; "
    "runpy.run_path(runner_script, run_name='__main__')"
)
_DASHBOARD_UPDATE_RUNNER_ENV_KEYS = frozenset(
    {
        "APPDATA",
        "COMSPEC",
        "HOME",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "LOCALAPPDATA",
        "LOGNAME",
        "PATH",
        "PATHEXT",
        "SHELL",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "TZ",
        "USER",
        "USERNAME",
        "USERPROFILE",
        "WINDIR",
    }
)


class DashboardUpdateRunnerPopenKwargs(TypedDict):
    cwd: str
    env: dict[str, str]
    log_handle: TextIO


class _UpdateLockSnapshot(NamedTuple):
    payload: dict[str, object] | None
    identity: tuple[int, int] | None
    modified_at: float | None


def dashboard_update_lock_path(guard_home: Path) -> Path:
    return guard_home / _DASHBOARD_UPDATE_LOCK


def read_dashboard_update_lock(guard_home: Path) -> dict[str, object] | None:
    snapshot = _read_update_lock_snapshot(dashboard_update_lock_path(guard_home))
    return snapshot.payload if snapshot is not None else None


def dashboard_update_in_progress(guard_home: Path) -> bool:
    lock_path = dashboard_update_lock_path(guard_home)
    snapshot = _read_update_lock_snapshot(lock_path)
    if snapshot is None:
        return False
    payload = snapshot.payload
    age_seconds = _update_lock_age_seconds(snapshot)
    if payload is None:
        # Treat a new unreadable/partially-written reservation as active. An
        # invalid file is only reclaimed after the full installer window.
        if age_seconds is None or age_seconds < _DASHBOARD_UPDATE_STALE_SECONDS:
            return True
        return not _unlink_update_lock_snapshot(lock_path, snapshot)
    token = payload.get("token")
    if not isinstance(token, str) or not token:
        legacy_runner_pid = payload.get("runner_pid")
        if type(legacy_runner_pid) is int and legacy_runner_pid > 0 and not _pid_is_running(legacy_runner_pid):
            return not _unlink_update_lock_snapshot(lock_path, snapshot)
        if age_seconds is None or age_seconds < _DASHBOARD_UPDATE_STALE_SECONDS:
            return True
        return not _unlink_update_lock_snapshot(lock_path, snapshot)
    if age_seconds is not None and age_seconds >= _DASHBOARD_UPDATE_STALE_SECONDS:
        return not clear_dashboard_update_lock(guard_home, token=token)
    runner_pid = payload.get("runner_pid")
    if type(runner_pid) is int and runner_pid > 0 and not _pid_is_running(runner_pid):
        return not clear_dashboard_update_lock(guard_home, token=token)
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
    payload["update_in_progress"] = True
    lock_payload = read_dashboard_update_lock(guard_home)
    if lock_payload is None:
        return payload
    for key in ("previous_version", "target_version", "daemon_port", "started_at"):
        value = lock_payload.get(key)
        if value is not None:
            payload[key] = value
    return payload


def dashboard_update_runner_script() -> Path:
    """Return the installed runner script path (never resolve via cwd or -m imports)."""
    return Path(__file__).resolve(strict=True).with_name("dashboard_update_runner.py").resolve(strict=True)


def _dashboard_update_runner_interpreter() -> Path:
    """Return the active environment's absolute interpreter without dereferencing its venv shim."""

    interpreter = Path(sys.executable).expanduser()
    if not interpreter.is_absolute() or not interpreter.is_file():
        raise RuntimeError("Guard dashboard update requires an absolute active Python interpreter.")
    return interpreter


def build_dashboard_update_runner_command(
    guard_home: Path,
    *,
    daemon_pid: int,
    daemon_port: int,
    update_token: str,
    force_pypi_reinstall: bool = False,
) -> list[str]:
    if not update_token:
        raise ValueError("Guard dashboard update requires a non-empty reservation token.")
    resolved_home = guard_home.expanduser().resolve()
    runner_script = dashboard_update_runner_script()
    trusted_prefix = _trusted_runner_prefix(sys.prefix)
    trusted_exec_prefix = _trusted_runner_prefix(sys.exec_prefix)
    trusted_import_paths = _trusted_runner_import_paths(runner_script)
    command = [
        str(_dashboard_update_runner_interpreter()),
        "-I",
        "-S",
        "-c",
        _DASHBOARD_UPDATE_RUNNER_BOOTSTRAP,
        str(trusted_prefix),
        str(trusted_exec_prefix),
        json.dumps([str(path) for path in trusted_import_paths], separators=(",", ":")),
        str(runner_script),
    ]
    command.extend(
        [
            "--guard-home",
            str(resolved_home),
            "--daemon-pid",
            str(daemon_pid),
            "--daemon-port",
            str(daemon_port),
            "--update-token",
            update_token,
        ]
    )
    if force_pypi_reinstall:
        command.append("--force-pypi-reinstall")
    return command


def _trusted_runner_prefix(value: str) -> Path:
    prefix = Path(value).expanduser()
    if not prefix.is_absolute():
        raise RuntimeError("Guard dashboard update requires an absolute active Python prefix.")
    try:
        resolved = prefix.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise RuntimeError("Guard dashboard update requires an available active Python prefix.") from error
    if not resolved.is_dir():
        raise RuntimeError("Guard dashboard update requires a directory-valued active Python prefix.")
    return resolved


def _trusted_runner_import_paths(runner_script: Path) -> tuple[Path, ...]:
    candidates = [runner_script.parents[3]]
    try:
        configured_paths = sysconfig.get_paths()
    except (AttributeError, KeyError, OSError, TypeError, ValueError) as error:
        raise RuntimeError("Guard dashboard update could not resolve active Python import paths.") from error
    for key in ("purelib", "platlib"):
        value = configured_paths.get(key)
        if isinstance(value, str) and value:
            candidates.append(Path(value).expanduser())

    trusted_paths: list[Path] = []
    seen: set[Path] = set()
    for index, candidate in enumerate(candidates):
        required = index == 0
        if not candidate.is_absolute():
            if required:
                raise RuntimeError("Guard dashboard update requires absolute trusted import paths.")
            continue
        try:
            resolved = candidate.resolve(strict=True)
        except (OSError, RuntimeError) as error:
            if required:
                raise RuntimeError("Guard dashboard update requires available trusted import paths.") from error
            continue
        if not resolved.is_dir():
            if required:
                raise RuntimeError("Guard dashboard update requires directory-valued trusted import paths.")
            continue
        if resolved not in seen:
            seen.add(resolved)
            trusted_paths.append(resolved)
    return tuple(trusted_paths)


def build_dashboard_update_runner_popen_kwargs(guard_home: Path) -> DashboardUpdateRunnerPopenKwargs:
    resolved_home = guard_home.expanduser().resolve()
    resolved_home.mkdir(parents=True, exist_ok=True)
    log_path = resolved_home / "dashboard-update.log"
    log_handle = _open_private_runner_log(log_path)
    return {
        "cwd": str(resolved_home),
        "env": _runner_env(),
        "log_handle": log_handle,
    }


def _open_private_runner_log(log_path: Path) -> TextIO:
    """Open one private per-attempt log without retaining unbounded prior output."""

    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    file_descriptor = os.open(log_path, flags, 0o600)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(file_descriptor, 0o600)
        else:  # pragma: no cover - fchmod is unavailable on Windows.
            os.chmod(log_path, 0o600)
        return os.fdopen(file_descriptor, "w", encoding="utf-8")
    except BaseException:
        os.close(file_descriptor)
        raise


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
    lock_path = dashboard_update_lock_path(guard_home)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    status_payload = build_guard_update_status_payload()
    update_token = secrets.token_hex(32)
    reservation = {
        "token": update_token,
        "state": "reserved",
        "guard_home": str(guard_home),
        "daemon_pid": daemon_pid,
        "daemon_port": daemon_port,
        "previous_version": status_payload.get("current_version"),
        "target_version": status_payload.get("latest_version"),
        "started_at": datetime.now(timezone.utc).isoformat(),
    }
    for _attempt in range(3):
        if _reserve_dashboard_update_lock(lock_path, reservation):
            break
        if dashboard_update_in_progress(guard_home):
            return {
                "scheduled": False,
                "error": "update_in_progress",
                "message": "Guard is already updating on this machine.",
            }
    else:
        return {
            "scheduled": False,
            "error": "update_in_progress",
            "message": "Guard is already updating on this machine.",
        }

    process: subprocess.Popen[bytes] | subprocess.Popen[str] | None = None
    try:
        command = build_dashboard_update_runner_command(
            guard_home,
            daemon_pid=daemon_pid,
            daemon_port=daemon_port,
            update_token=update_token,
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
            with suppress(OSError):
                log_handle.close()
        if not isinstance(process.pid, int) or process.pid <= 0:
            raise RuntimeError("Guard dashboard update runner did not return a valid process ID.")
    except BaseException:
        clear_dashboard_update_lock(guard_home, token=update_token)
        raise
    return {
        "scheduled": True,
        "message": "Guard will update, restart briefly, and reload this dashboard.",
        "runner_pid": process.pid,
        "previous_version": status_payload.get("current_version"),
        "target_version": status_payload.get("latest_version"),
    }


def claim_dashboard_update_lock(guard_home: Path, *, token: str) -> bool:
    """Attach this runner's PID to the reservation owned by ``token``."""

    if not token:
        return False
    lock_path = dashboard_update_lock_path(guard_home)
    snapshot = _read_update_lock_snapshot(lock_path)
    if snapshot is None or snapshot.payload is None:
        return False
    payload = snapshot.payload
    if not _update_lock_token_matches(payload, token):
        return False
    runner_pid = payload.get("runner_pid")
    if runner_pid is not None:
        return runner_pid == os.getpid()
    updated_payload = {**payload, "state": "running", "runner_pid": os.getpid()}
    return _replace_update_lock_snapshot(lock_path, snapshot, updated_payload)


def clear_dashboard_update_lock(guard_home: Path, *, token: str) -> bool:
    """Clear only the dashboard update reservation owned by ``token``."""

    if not token:
        return False
    lock_path = dashboard_update_lock_path(guard_home)
    snapshot = _read_update_lock_snapshot(lock_path)
    if snapshot is None or snapshot.payload is None:
        return False
    if not _update_lock_token_matches(snapshot.payload, token):
        return False
    return _unlink_update_lock_snapshot(lock_path, snapshot)


def _runner_env() -> dict[str, str]:
    """Build the detached runner's minimal OS environment.

    The updater receives its Guard home explicitly. Python import controls,
    package-installer configuration, virtual-environment selectors, and
    dynamic-loader hooks are intentionally absent from this allowlist.
    """

    return {key: value for key, value in os.environ.items() if key.upper() in _DASHBOARD_UPDATE_RUNNER_ENV_KEYS}


def _read_update_lock_snapshot(lock_path: Path) -> _UpdateLockSnapshot | None:
    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    try:
        file_descriptor = os.open(lock_path, flags)
    except FileNotFoundError:
        return None
    except OSError:
        return _UpdateLockSnapshot(None, None, None)
    try:
        before = os.fstat(file_descriptor)
        identity = (before.st_dev, before.st_ino)
        modified_at = before.st_mtime
        if not stat.S_ISREG(before.st_mode) or before.st_size > _DASHBOARD_UPDATE_LOCK_MAX_BYTES:
            return _UpdateLockSnapshot(None, identity, modified_at)
        raw = b""
        while len(raw) <= _DASHBOARD_UPDATE_LOCK_MAX_BYTES:
            chunk = os.read(file_descriptor, min(8192, _DASHBOARD_UPDATE_LOCK_MAX_BYTES + 1 - len(raw)))
            if not chunk:
                break
            raw += chunk
        after = os.fstat(file_descriptor)
        if (
            (after.st_dev, after.st_ino) != identity
            or after.st_size != before.st_size
            or after.st_mtime_ns != before.st_mtime_ns
            or len(raw) > _DASHBOARD_UPDATE_LOCK_MAX_BYTES
        ):
            return _UpdateLockSnapshot(None, identity, modified_at)
    except OSError:
        return _UpdateLockSnapshot(None, None, None)
    finally:
        os.close(file_descriptor)
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        payload = None
    return _UpdateLockSnapshot(payload if isinstance(payload, dict) else None, identity, modified_at)


def _reserve_dashboard_update_lock(lock_path: Path, payload: dict[str, object]) -> bool:
    return _write_private_json_exclusive(lock_path, payload) is not None


def _write_private_json_exclusive(lock_path: Path, payload: dict[str, object]) -> tuple[int, int] | None:
    encoded = json.dumps(payload, indent=2).encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        file_descriptor = os.open(lock_path, flags, 0o600)
    except FileExistsError:
        return None
    identity: tuple[int, int] | None = None
    try:
        file_status = os.fstat(file_descriptor)
        identity = (file_status.st_dev, file_status.st_ino)
        if hasattr(os, "fchmod"):
            os.fchmod(file_descriptor, 0o600)
        else:  # pragma: no cover - fchmod is unavailable on Windows.
            os.chmod(lock_path, 0o600)
        offset = 0
        while offset < len(encoded):
            written = os.write(file_descriptor, encoded[offset:])
            if written <= 0:
                raise OSError("Could not write dashboard update reservation.")
            offset += written
        os.fsync(file_descriptor)
    except BaseException:
        if identity is not None:
            _unlink_path_identity(lock_path, identity)
        raise
    finally:
        os.close(file_descriptor)
    return identity


def _replace_update_lock_snapshot(
    lock_path: Path,
    snapshot: _UpdateLockSnapshot,
    payload: dict[str, object],
) -> bool:
    token = payload.get("token")
    if not isinstance(token, str) or not token:
        return False
    temp_path = lock_path.with_name(f".{lock_path.name}.{secrets.token_hex(16)}.tmp")
    try:
        temp_identity = _write_private_json_exclusive(temp_path, payload)
    except OSError:
        return False
    if temp_identity is None:  # pragma: no cover - a random 128-bit collision is not practical.
        return False
    try:
        current = _read_update_lock_snapshot(lock_path)
        if (
            current is None
            or current.identity != snapshot.identity
            or current.payload is None
            or current.payload != snapshot.payload
            or not _update_lock_token_matches(current.payload, token)
        ):
            return False
        os.replace(temp_path, lock_path)
        return True
    except OSError:
        return False
    finally:
        _unlink_path_identity(temp_path, temp_identity)


def _update_lock_token_matches(payload: dict[str, object], token: str) -> bool:
    candidate = payload.get("token")
    return isinstance(candidate, str) and secrets.compare_digest(candidate, token)


def _update_lock_age_seconds(snapshot: _UpdateLockSnapshot) -> float | None:
    now = datetime.now(timezone.utc)
    payload = snapshot.payload
    if payload is not None:
        started_at = payload.get("started_at")
        if isinstance(started_at, str):
            try:
                started = datetime.fromisoformat(started_at)
            except ValueError:
                pass
            else:
                if started.tzinfo is None:
                    started = started.replace(tzinfo=timezone.utc)
                timestamp_age = (now - started).total_seconds()
                if timestamp_age >= 0:
                    return timestamp_age
    if snapshot.modified_at is None:
        return None
    return max(0.0, now.timestamp() - snapshot.modified_at)


def _unlink_update_lock_snapshot(lock_path: Path, snapshot: _UpdateLockSnapshot) -> bool:
    if snapshot.identity is None:
        return False
    current = _read_update_lock_snapshot(lock_path)
    if current is None or current.identity != snapshot.identity or current.payload != snapshot.payload:
        return False
    return _unlink_path_identity(lock_path, snapshot.identity)


def _unlink_path_identity(path: Path, identity: tuple[int, int]) -> bool:
    try:
        path_status = path.stat(follow_symlinks=False)
    except (FileNotFoundError, OSError):
        return False
    if (path_status.st_dev, path_status.st_ino) != identity:
        return False
    try:
        path.unlink()
    except (FileNotFoundError, OSError):
        return False
    return True


def _pid_is_running(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        return windows_process_is_running(pid)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True
