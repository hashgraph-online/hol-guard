"""Thin client of the native daemon manager (`daemon-manage --stdin`).

The native runtime owns the daemon lifecycle: start, adoption, recovery,
retirement, the signed state and pending-launch records, the wake
reservation, the approval-center locator and the background maintenance.
Every function here builds one request and returns the runtime's answer.
"""

from __future__ import annotations

import dataclasses
import ntpath
import os
import sys
import threading
import time
from collections.abc import Generator, Mapping
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import BinaryIO, Literal, cast

from ..version import __version__
from .fork_safety import forget_in_child
from .live_process_identity import process_start_token as _process_start_marker
from .mdm.file_lock import release_file_lock
from .private_file_io import read_private_regular_text

GUARD_DAEMON_COMPATIBILITY_VERSION = 2
GUARD_DAEMON_POLL_INTERVAL_SECONDS = 0.1

GuardDaemonHookFailureKind = Literal[
    "authenticated-control-plane-failure",
    "overload",
    "transport-failure",
]

_AUTH_FILE = "daemon-auth-token"
_STATE_FILE = "daemon-state.json"
_START_LOCK_FILE = "daemon-start.lock"
_RECOVERY_LOCK_FILE = "daemon-recovery.lock"
_START_TIMEOUT_FLOOR_SECONDS = 14.0
_RECOVERY_WORKER_TIMEOUT_SECONDS = 30.0
_MANAGE_DEFAULT_SECONDS = 30.0
_MANAGE_OUTPUT_LIMIT = 64 * 1024
_EPHEMERAL_REAP_INTERVAL_SECONDS = 30.0
_LAUNCH_NONCE_ENV = "HOL_GUARD_DAEMON_LAUNCH_NONCE"
_SHIM_TOOL_DIRS_ENV = "HOL_GUARD_SHIM_TOOL_DIRS"
_DESKTOP_ENV_KEYS = ("HOL_GUARD_DESKTOP", "HOL_GUARD_DESKTOP_RUNTIME_OWNER", "HOL_GUARD_DESKTOP_VERSION")
_LAUNCHER_ENV_KEYS = frozenset(
    {
        "APPDATA",
        "COMSPEC",
        "GUARD_DAEMON_IDLE_TIMEOUT_SECONDS",
        "HOME",
        *_DESKTOP_ENV_KEYS,
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "LOCALAPPDATA",
        "LOGNAME",
        "PATH",
        "PATHEXT",
        "SHELL",
        "SYSTEMDRIVE",
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
_ORPHAN_REAP_TIMEOUT_SECONDS = 15.0
_ORPHAN_REAP_LAUNCH_RESERVE_SECONDS = 0.25
_ORPHAN_REAP_MAX_BUDGET_MS = 60_000

_runtime_fingerprint_cache: str | None = None
_MAINTENANCE_LOCK = threading.Lock()
_MAINTENANCE_IN_FLIGHT: set[str] = set()
_last_ephemeral_reap_at = 0.0
_LOCKS_GUARD = threading.Lock()
_START_LOCKS: dict[str, threading.Lock] = {}
_START_DEPTHS: dict[tuple[int, str], int] = {}
_RECOVERY_LOCKS: dict[str, threading.Lock] = {}
forget_in_child(_START_LOCKS)
forget_in_child(_START_DEPTHS)
forget_in_child(_RECOVERY_LOCKS)
forget_in_child(_MAINTENANCE_IN_FLIGHT)


@dataclasses.dataclass(frozen=True, slots=True)
class ApprovalCenterLocator:
    """Structured snapshot of where the Guard approval-center daemon is running."""

    guard_home: Path
    daemon_url: str
    approval_url_base: str
    pid: int
    started_at: str
    state_path: Path


# --- the request ---------------------------------------------------------------------------------


def _daemon_manage(
    op: str,
    guard_home: Path,
    *,
    keep_port: int | None = None,
    deadline: float | None = None,
    allow_windows_breakaway: bool = False,
    extra: Mapping[str, object] | None = None,
    args: Mapping[str, object] | None = None,
    frozen_check: bool = True,
) -> dict[str, object] | None:
    """One `daemon-manage` answer from the native runtime, or `None`."""

    from .mdm.runtime_request import runtime_answer

    manage_deadline = time.monotonic() + _MANAGE_DEFAULT_SECONDS if deadline is None else deadline
    frozen = bool(getattr(sys, "frozen", False))
    parent_trusted = frozen and frozen_check and _trusted_frozen_bootloader_parent_pid(guard_home) == os.getppid()

    def request() -> dict[str, object] | None:
        budget = manage_deadline - time.monotonic()
        if budget <= 0:
            return None
        payload: dict[str, object] = {
            "schema": "daemon-manage.v1",
            "op": op,
            "guard_home": str(Path(guard_home).absolute()),
            "implicit_home": str(_implicit_daemon_guard_home()),
            "caller_pid": os.getpid(),
            "caller_parent_pid": os.getppid(),
            "frozen_runtime": frozen,
            "frozen_parent_trusted": parent_trusted,
            "executable_name": ntpath.basename(sys.executable).strip().lower() or None,
            "budget_ms": min(int(budget * 1000), 600_000),
        }
        if keep_port is not None:
            payload["keep_port"] = keep_port
        if extra:
            payload.update({key: value for key, value in extra.items() if value is not None})
        if args:
            payload["args"] = {key: value for key, value in args.items() if value is not None}
        return payload

    return runtime_answer(
        "daemon-manage-v1",
        "daemon-manage",
        request,
        output_limit=_MANAGE_OUTPUT_LIMIT,
        deadline=manage_deadline + 1.0,
        allow_windows_breakaway=allow_windows_breakaway,
    )


def _ask(op: str, guard_home: Path, **args: object) -> dict[str, object]:
    """A state op's answer; a missing runtime or a bad argument raises."""

    answer = _daemon_manage(op, guard_home, args=args)
    if answer is None:
        raise RuntimeError("Guard daemon management requires the native runtime.")
    if "error" in answer:
        message = str(answer.get("error"))
        if answer.get("kind") == "value":
            raise ValueError(message)
        if answer.get("kind") == "os":
            raise OSError(message)
        raise RuntimeError(message)
    return answer


def _lifecycle(check: str, query: Mapping[str, object], *, home: Path | None = None) -> dict[str, object]:
    verdict = _ask("lifecycle", home or _implicit_daemon_guard_home(), query={"check": check, **query}).get("verdict")
    if not isinstance(verdict, dict):
        raise RuntimeError("Guard daemon lifecycle verdict is unavailable.")
    return cast("dict[str, object]", verdict)


def _implicit_daemon_guard_home() -> Path:
    from .config import resolve_guard_home

    return resolve_guard_home(None)


# --- the current runtime -------------------------------------------------------------------------


def _daemon_state_executable() -> str:
    try:
        return str(Path(sys.executable).resolve(strict=True))
    except OSError:
        return sys.executable


def _current_guard_daemon_source_root() -> str:
    if getattr(sys, "frozen", False):
        from .frozen_daemon_runtime import _frozen_runtime_source_root

        return _frozen_runtime_source_root()
    return str(Path(__file__).resolve().parents[2])


def _is_sha256_hex(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and not set(value) - set("0123456789abcdef")


def _current_guard_daemon_runtime_fingerprint() -> str:
    global _runtime_fingerprint_cache
    if _runtime_fingerprint_cache is not None:
        return _runtime_fingerprint_cache
    if getattr(sys, "frozen", False):
        from .frozen_daemon_runtime import _frozen_runtime_fingerprint

        _runtime_fingerprint_cache = _frozen_runtime_fingerprint()
        return _runtime_fingerprint_cache
    from .mdm.runtime_request import runtime_answer
    from .native_daemon_lifecycle import await_native_runtime

    request = {
        "schema": "runtime-fingerprint.v1",
        "source_root": _current_guard_daemon_source_root(),
        "version": __version__,
        "cache_dir": str(Path.home() / ".hol-guard" / "runtime-fingerprint-cache"),
    }

    def ask() -> dict[str, object] | None:
        return runtime_answer(
            "native-runtime-fingerprint-v1", "runtime-fingerprint", request, output_limit=4096, timeout_seconds=60.0
        )

    answer = ask()
    # A freshly installed runtime can miss its first capability probe.
    if answer is None and await_native_runtime(60.0) > 0.0:
        answer = ask()
    fingerprint = None if answer is None else answer.get("fingerprint")
    if not _is_sha256_hex(fingerprint):
        raise RuntimeError("Guard daemon runtime identity requires the native runtime.")
    _runtime_fingerprint_cache = cast("str", fingerprint)
    return _runtime_fingerprint_cache


def current_guard_daemon_runtime_fingerprint() -> str:
    """Return the installed runtime identity used for daemon compatibility."""

    return _current_guard_daemon_runtime_fingerprint()


def _current_state() -> dict[str, object]:
    return {
        "compatibility_version": GUARD_DAEMON_COMPATIBILITY_VERSION,
        "package_version": __version__,
        "executable": _daemon_state_executable(),
        "source_root": _current_guard_daemon_source_root(),
        "runtime_fingerprint": _current_guard_daemon_runtime_fingerprint(),
    }


def _guard_daemon_state_matches_current_runtime(
    payload: dict[str, object],
    guard_home: Path | None = None,
    *,
    current_version: str | None = None,
) -> bool:
    current = _current_state()
    if current_version is not None:
        current["package_version"] = current_version
    answer = _daemon_manage(
        "state_matches",
        guard_home or _implicit_daemon_guard_home(),
        args={"current": current, "state": payload},
    )
    if answer is not None and answer.get("matches") is True:
        return True
    if getattr(sys, "frozen", False):
        from .frozen_daemon_runtime import _trusted_frozen_peer_state

        return _trusted_frozen_peer_state(payload)
    return False


# --- launch configuration ------------------------------------------------------------------------


def desktop_preflight_requested() -> bool:
    return os.environ.get("HOL_GUARD_DESKTOP_PREFLIGHT", "").strip().lower() in {"1", "true", "yes"}


def _start_timeouts() -> dict[str, object]:
    query = {
        "desktop": os.environ.get("HOL_GUARD_DESKTOP", "").strip() == "1",
        "worker_ready_floor": _START_TIMEOUT_FLOOR_SECONDS,
    }
    return _lifecycle("start_timeouts", query)


def _default_guard_daemon_start_timeout() -> float:
    return float(cast("float", _start_timeouts()["default"]))


def _post_update_guard_daemon_start_timeout() -> float:
    return float(cast("float", _start_timeouts()["post_update"]))


def _trusted_daemon_home(home_dir: Path | None) -> Path:
    candidate = Path.home() if home_dir is None else Path(home_dir)
    if not candidate.is_absolute():
        raise RuntimeError("Guard daemon requires an absolute user home directory.")
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise RuntimeError("Guard daemon requires an available user home directory.") from error
    if not resolved.is_dir():
        raise RuntimeError("Guard daemon requires a directory-valued user home.")
    return resolved


def _guard_home_is_ephemeral(guard_home: Path) -> bool:
    return bool(_lifecycle("ephemeral_home", {"guard_home": str(guard_home)})["ephemeral"])


def _daemon_launcher_env(
    *,
    home_dir: Path | None = None,
    guard_home: Path | None = None,
    executable: Path | None = None,
) -> dict[str, str]:
    """A minimal detached-daemon environment without Python startup hooks."""

    env = {key: value for key, value in os.environ.items() if key.upper() in _LAUNCHER_ENV_KEYS}
    trusted_home = _trusted_daemon_home(home_dir)
    # Package-manager detection must find what the user's shell reaches even
    # when a desktop launcher reduced PATH, so it searches well-known dirs too.
    env.update({"HOME": str(trusted_home), "PYTHONNOUSERSITE": "1", "PYTHONSAFEPATH": "1", _SHIM_TOOL_DIRS_ENV: "1"})
    if getattr(sys, "frozen", False) is True or executable is not None:
        env["PYINSTALLER_RESET_ENVIRONMENT"] = "1"
        for key in _DESKTOP_ENV_KEYS:
            if value := os.environ.get(key):
                env[key] = value
            else:
                env.pop(key, None)
    else:
        env.pop("PYINSTALLER_RESET_ENVIRONMENT", None)
        for key in _DESKTOP_ENV_KEYS:
            env.pop(key, None)
    if os.name == "nt":
        env["USERPROFILE"] = str(trusted_home)
    if guard_home is not None and not _guard_home_is_ephemeral(guard_home):
        env["GUARD_DAEMON_IDLE_TIMEOUT_SECONDS"] = "0"
    _bind_native_runtime_override(env)
    return env


def _bind_native_runtime_override(env: dict[str, str]) -> None:
    """Hand the daemon the caller's pinned native runtime.

    ``off`` and ``auto`` are never forwarded, so an ambient value can name a
    runtime but cannot switch the native path off for the daemon.
    """

    from .native_runtime import native_mode

    binary = os.environ.get("HOL_GUARD_NATIVE_BINARY")
    mode = native_mode()
    if binary and Path(binary).is_absolute() and mode in {"shadow", "force"}:
        env["HOL_GUARD_NATIVE"] = mode
        env["HOL_GUARD_NATIVE_BINARY"] = binary
    for key in ("HOL_GUARD_NATIVE_SOURCE_COMPILER", "HOL_GUARD_NATIVE_TEST_SOURCE_COMPILER"):
        if (compiler := os.environ.get(key)) and Path(compiler).is_absolute():
            env[key] = compiler


def _start_lock_held(guard_home: Path) -> bool:
    key = str(guard_home.resolve())
    with _LOCKS_GUARD:
        return any(lock_key == key and depth > 0 for (_thread, lock_key), depth in _START_DEPTHS.items())


def _ensure_request_extra(
    guard_home: Path,
    *,
    home_dir: Path | None,
    recovery: bool = False,
    preferred_port: int | None = None,
    allow_windows_job_breakaway: bool = False,
    executable: Path | None = None,
    background_maintenance: bool = True,
) -> dict[str, object]:
    """The launch configuration and environment `daemon-manage` starts a daemon with."""

    from .daemon.native_serve import launch_configuration, native_serve_executable

    serve_executable = native_serve_executable(guard_home) if executable is None else None
    if executable is None and serve_executable is None:
        raise RuntimeError("Guard daemon requires the native runtime.")
    if executable is not None:
        launch_executable = Path(executable)
        if not launch_executable.is_absolute() or not launch_executable.is_file():
            raise RuntimeError("Frozen Guard daemon requires the signed Guard executable.")
        executable = launch_executable.resolve(strict=True)
    trusted_home = _trusted_daemon_home(home_dir)
    launch = launch_configuration(guard_home, 0, user_home=trusted_home)
    launch.pop("launch_nonce", None)
    return {
        "launch": launch,
        "serve_executable": str(serve_executable) if serve_executable is not None else None,
        "executable": str(executable) if executable is not None else None,
        "home_dir": str(trusted_home),
        "launch_cwd": str(trusted_home),
        "preferred_port": preferred_port if isinstance(preferred_port, int) and preferred_port > 0 else None,
        "background_maintenance": background_maintenance,
        "allow_windows_job_breakaway": (os.name == "nt") if recovery else allow_windows_job_breakaway,
        "start_lock_held": _start_lock_held(guard_home),
        "launcher_env": _daemon_launcher_env(home_dir=home_dir, guard_home=guard_home, executable=executable),
        "env_port": os.environ.get("GUARD_DAEMON_PORT"),
    }


def recovery_host_payload(guard_home: Path, *, home_dir: Path | None) -> dict[str, object]:
    """The `daemon-manage.v1` request a native recovery session starts the daemon with."""

    frozen = bool(getattr(sys, "frozen", False))
    payload: dict[str, object] = {
        "schema": "daemon-manage.v1",
        "op": "ensure",
        "guard_home": str(Path(guard_home).absolute()),
        "implicit_home": str(_implicit_daemon_guard_home()),
        "caller_pid": os.getpid(),
        "caller_parent_pid": os.getppid(),
        "frozen_runtime": frozen,
        "frozen_parent_trusted": frozen and _trusted_frozen_bootloader_parent_pid(guard_home) == os.getppid(),
        "executable_name": ntpath.basename(sys.executable).strip().lower() or None,
    }
    extra = _ensure_request_extra(guard_home, home_dir=home_dir, recovery=True, background_maintenance=False)
    payload.update({key: value for key, value in extra.items() if value is not None})
    return payload


def _daemon_url_from_answer(answer: Mapping[str, object] | None, deadline: float) -> str:
    if answer is None:
        if time.monotonic() >= deadline:
            raise TimeoutError("Guard daemon operation deadline exceeded.")
        raise RuntimeError("Guard daemon start requires the native runtime.")
    url = answer.get("url")
    if isinstance(url, str) and url:
        return url
    message = answer.get("error")
    text = message if isinstance(message, str) and message else "Guard approval center did not start."
    if answer.get("kind") == "value":
        raise ValueError(text)
    raise RuntimeError(text)


# --- start, recovery and retirement --------------------------------------------------------------


def ensure_guard_daemon(
    guard_home: Path,
    *,
    home_dir: Path | None = None,
    start_timeout: float | None = None,
    preferred_port: int | None = None,
    allow_windows_job_breakaway: bool = False,
    executable: Path | None = None,
    deadline_monotonic: float | None = None,
    background_maintenance: bool = True,
    wake_key: str | None = None,
) -> str:
    """Reuse, adopt or launch the home's daemon through `daemon-manage ensure`."""

    if desktop_preflight_requested():
        raise RuntimeError("Guard daemon start is disabled during Desktop preflight.")
    if deadline_monotonic is not None and (
        isinstance(deadline_monotonic, bool) or deadline_monotonic != deadline_monotonic
    ):
        raise ValueError("Guard daemon operation deadline is invalid.")
    timeout = _default_guard_daemon_start_timeout() if start_timeout is None else start_timeout
    start_deadline = time.monotonic() + max(0.0, timeout)
    if deadline_monotonic is not None:
        start_deadline = min(start_deadline, deadline_monotonic)
        if time.monotonic() >= start_deadline:
            raise TimeoutError("Guard daemon operation deadline exceeded.")
    extra = _ensure_request_extra(
        guard_home,
        home_dir=home_dir,
        preferred_port=preferred_port,
        allow_windows_job_breakaway=allow_windows_job_breakaway,
        executable=executable,
        background_maintenance=background_maintenance,
    )
    if wake_key:
        extra["wake"] = wake_key
    answer = _daemon_manage("ensure", guard_home, deadline=start_deadline, allow_windows_breakaway=True, extra=extra)
    url = _daemon_url_from_answer(answer, start_deadline)
    if background_maintenance:
        _schedule_maintenance(guard_home)
    return url


def ensure_guard_daemon_after_update(
    guard_home: Path,
    *,
    home_dir: Path,
    preferred_port: int | None = None,
    allow_windows_job_breakaway: bool = False,
    executable: Path | None = None,
) -> str:
    """Restart the local daemon after a package update with a longer startup window."""

    return ensure_guard_daemon(
        guard_home,
        home_dir=home_dir,
        start_timeout=_post_update_guard_daemon_start_timeout(),
        preferred_port=preferred_port,
        allow_windows_job_breakaway=allow_windows_job_breakaway,
        executable=executable,
    )


def recover_guard_daemon_after_hook_failure(
    guard_home: Path,
    *,
    home_dir: Path | None = None,
    failure_kind: GuardDaemonHookFailureKind = "authenticated-control-plane-failure",
    recovery_lock_timeout_seconds: float | None = None,
) -> str:
    """Recover the home's daemon after a hook failure through `daemon-manage recover`."""

    timeout = (
        _default_guard_daemon_start_timeout()
        if recovery_lock_timeout_seconds is None
        else recovery_lock_timeout_seconds
    )
    deadline = time.monotonic() + max(0.0, timeout)
    answer = _daemon_manage(
        "recover",
        guard_home,
        deadline=deadline,
        allow_windows_breakaway=True,
        extra={"failure_kind": failure_kind, **_ensure_request_extra(guard_home, home_dir=home_dir, recovery=True)},
    )
    return _daemon_url_from_answer(answer, deadline)


def schedule_guard_daemon_recovery(
    guard_home: Path,
    *,
    home_dir: Path | None = None,
    failure_kind: GuardDaemonHookFailureKind = "authenticated-control-plane-failure",
    executable: Path | None = None,
) -> None:
    """Hand recovery to a detached native worker through `daemon-manage schedule_recovery`."""

    del executable
    try:
        trusted_home = _trusted_daemon_home(home_dir)
        extra = _ensure_request_extra(guard_home, home_dir=home_dir, recovery=True)
    except (OSError, RuntimeError, ValueError):
        return
    with suppress(OSError, RuntimeError, ValueError):
        _ = _daemon_manage(
            "schedule_recovery",
            guard_home,
            deadline=time.monotonic() + _RECOVERY_WORKER_TIMEOUT_SECONDS,
            allow_windows_breakaway=True,
            extra={
                "failure_kind": failure_kind,
                "worker_env": extra["launcher_env"],
                "worker_cwd": str(trusted_home),
                **extra,
            },
        )


def schedule_guard_daemon_ensure(guard_home: Path, *, home_dir: Path | None = None) -> str:
    """Reserve one detached daemon ensure without delaying a hook response.

    When a healthy daemon is not ready yet, return the predicted loopback origin
    so approval deep links stay absolute and repairable. Callers must not treat
    that predicted origin as a verified live URL.
    """

    if desktop_preflight_requested():
        return load_guard_daemon_url(guard_home) or ""
    predicted_url = guard_daemon_url_for_home(guard_home)
    try:
        trusted_home = _trusted_daemon_home(home_dir)
        extra = _ensure_request_extra(guard_home, home_dir=home_dir)
    except (OSError, RuntimeError, ValueError):
        return load_guard_daemon_url(guard_home) or predicted_url
    answer = _daemon_manage(
        "schedule_ensure",
        guard_home,
        deadline=time.monotonic() + _RECOVERY_WORKER_TIMEOUT_SECONDS,
        allow_windows_breakaway=True,
        extra={"worker_env": extra["launcher_env"], "worker_cwd": str(trusted_home), **extra},
        args={"predicted_url": predicted_url},
    )
    url = None if answer is None else answer.get("url")
    return url if isinstance(url, str) and url else predicted_url


def clear_guard_daemon_wake_reservation(guard_home: Path, *, token: str) -> bool:
    answer = _daemon_manage("wake_clear", guard_home, args={"key": token})
    return answer is not None and answer.get("done") is True


def retire_all_guard_daemons_for_home(
    guard_home: Path,
    *,
    keep_port: int | None = None,
    deadline: float | None = None,
) -> list[int]:
    """Stop Guard daemon processes for one guard home, optionally keeping one port alive."""

    answer = _daemon_manage("retire", guard_home, keep_port=keep_port, deadline=deadline)
    retired = None if answer is None else answer.get("retired")
    if not isinstance(retired, list):
        return []
    return [pid for pid in retired if type(pid) is int]


def guard_daemon_retirement_is_complete(guard_home: Path) -> bool:
    """Prove no authenticated, pending, or enumerable daemon remains for a home."""

    answer = _daemon_manage("retirement_complete", guard_home)
    return answer is not None and answer.get("complete") is True


def guard_recovery_posture(guard_home: Path) -> str:
    """Local protection for recovery: "on", "off" or "unknown" when unreadable."""

    answer = _daemon_manage("posture", guard_home)
    posture = None if answer is None else answer.get("posture")
    if posture == "on":
        return "on"
    return "off" if posture == "off" else "unknown"


def reap_orphaned_daemon_workers(*, deadline: float | None = None) -> None:
    """Stop hook workers whose daemon parent is already gone."""

    if os.name == "nt":
        return
    from .mdm.runtime_request import runtime_answer

    reap_deadline = time.monotonic() + _ORPHAN_REAP_TIMEOUT_SECONDS if deadline is None else deadline

    def request() -> dict[str, object] | None:
        budget = reap_deadline - time.monotonic() - _ORPHAN_REAP_LAUNCH_RESERVE_SECONDS
        if budget <= 0:
            return None
        return {
            "schema": "orphaned-worker-reap.v1",
            "self_pid": os.getpid(),
            "budget_ms": min(int(budget * 1000), _ORPHAN_REAP_MAX_BUDGET_MS),
        }

    if request() is None:
        return
    runtime_answer(
        "native-orphaned-worker-reap-v1",
        "orphaned-worker-reap",
        request,
        output_limit=_MANAGE_OUTPUT_LIMIT,
        deadline=reap_deadline,
    )


def _schedule_maintenance(guard_home: Path) -> None:
    """Retire duplicate daemons and reap stale test homes off the caller's path."""

    global _last_ephemeral_reap_at
    key = str(guard_home)
    now = time.monotonic()
    with _MAINTENANCE_LOCK:
        if key in _MAINTENANCE_IN_FLIGHT:
            return
        _MAINTENANCE_IN_FLIGHT.add(key)
        ephemeral = now - _last_ephemeral_reap_at >= _EPHEMERAL_REAP_INTERVAL_SECONDS
        if ephemeral:
            _last_ephemeral_reap_at = now

    def run() -> None:
        try:
            _ = _daemon_manage(
                "maintenance",
                guard_home,
                args={"current": _current_state(), "duplicates": True, "ephemeral": ephemeral},
            )
        except (OSError, RuntimeError, ValueError):
            pass
        finally:
            with _MAINTENANCE_LOCK:
                _MAINTENANCE_IN_FLIGHT.discard(key)

    try:
        threading.Thread(target=run, name="guard-daemon-maintenance", daemon=True).start()
    except RuntimeError:
        with _MAINTENANCE_LOCK:
            _MAINTENANCE_IN_FLIGHT.discard(key)


# --- the live daemon -----------------------------------------------------------------------------


def guard_daemon_url_for_home(guard_home: Path) -> str:
    port = _lifecycle(
        "configured_port", {"env_port": os.environ.get("GUARD_DAEMON_PORT"), "guard_home": str(guard_home)}
    )
    return f"http://127.0.0.1:{port['port']}"


def _guard_daemon_url_port(url: str) -> int | None:
    import urllib.parse

    try:
        return urllib.parse.urlparse(url).port
    except ValueError:
        return None


def _live_guard_daemon_identity(
    guard_home: Path,
    *,
    require_current_runtime: bool = True,
    expected_pid: int | None = None,
) -> tuple[str, str] | None:
    frozen = bool(getattr(sys, "frozen", False))
    try:
        answer = _ask(
            "live",
            guard_home,
            current=_current_state() if require_current_runtime else None,
            require_current=require_current_runtime and not frozen,
            expected_pid=expected_pid,
        )
    except (OSError, RuntimeError, ValueError):
        return None
    url, auth = answer.get("url"), answer.get("auth")
    if not isinstance(url, str) or not isinstance(auth, str):
        return None
    if require_current_runtime and frozen:
        state = load_authenticated_daemon_state(guard_home)
        if state is None or not _guard_daemon_state_matches_current_runtime(state, guard_home):
            return None
    return url, auth


def _live_guard_daemon_url(
    guard_home: Path,
    *,
    require_current_runtime: bool = True,
    expected_pid: int | None = None,
) -> str | None:
    identity = _live_guard_daemon_identity(
        guard_home, require_current_runtime=require_current_runtime, expected_pid=expected_pid
    )
    return identity[0] if identity is not None else None


def load_guard_daemon_url(guard_home: Path) -> str | None:
    return _live_guard_daemon_url(guard_home, require_current_runtime=True)


def load_running_guard_daemon_identity(guard_home: Path, *, health_timeout: float = 1.0) -> tuple[str, str] | None:
    del health_timeout
    return _live_guard_daemon_identity(guard_home, require_current_runtime=True)


def _load_authenticated_daemon_identity(guard_home: Path) -> tuple[dict[str, object], str] | None:
    identity = _live_guard_daemon_identity(guard_home, require_current_runtime=False)
    state = load_authenticated_daemon_state(guard_home) if identity is not None else None
    return None if identity is None or state is None else (state, identity[1])


# --- records -------------------------------------------------------------------------------------


def auth_file_path(guard_home: Path) -> Path:
    return guard_home / _AUTH_FILE


def load_guard_daemon_auth_token(guard_home: Path) -> str | None:
    value = read_private_regular_text(auth_file_path(guard_home), max_bytes=4096, require_private_parent=True)
    return value or None


def ensure_guard_daemon_auth_token(guard_home: Path) -> str:
    """Return the guard home's daemon auth value, creating it only when absent."""

    auth = _ask("ensure_auth", guard_home).get("auth")
    if not isinstance(auth, str) or not auth:
        raise OSError("Guard could not write the daemon auth file.")
    return auth


def _state_path(guard_home: Path) -> Path:
    return guard_home / _STATE_FILE


def _optional_mapping(answer: Mapping[str, object], key: str) -> dict[str, object] | None:
    value = answer.get(key)
    return cast("dict[str, object]", value) if isinstance(value, dict) else None


def _load_state(guard_home: Path) -> dict[str, object] | None:
    return _optional_mapping(_ask("state", guard_home), "state")


def load_authenticated_daemon_state(guard_home: Path) -> dict[str, object] | None:
    try:
        return _optional_mapping(_ask("authenticated", guard_home), "state")
    except RuntimeError:
        return None


def write_guard_daemon_state(
    guard_home: Path,
    port: int,
    auth_token: str,
    *,
    pid: int | None = None,
    write_auth_token: bool = True,
    host: str = "127.0.0.1",
    state_id: str | None = None,
    started_at: str | None = None,
    trust_status: dict[str, object] | None = None,
) -> None:
    nonce = os.environ.get(_LAUNCH_NONCE_ENV)
    _ = _ask(
        "write_state",
        guard_home,
        auth=auth_token,
        port=port,
        pid=pid,
        host=host,
        state_id=state_id,
        started_at=started_at,
        launch_nonce=nonce,
        trust_status=trust_status,
        write_auth=write_auth_token,
        current=_current_state(),
    )


def republish_guard_daemon_trust_status(guard_home: Path, trust_status: dict[str, object]) -> bool:
    """Re-sign the running daemon's state with a new ``trust_status``."""

    return _ask("republish_trust", guard_home, trust_status=dict(trust_status)).get("done") is True


def clear_guard_daemon_state(guard_home: Path) -> None:
    _ = _ask("clear_state", guard_home)


def _clear_authenticated_guard_daemon_state_if_current(
    guard_home: Path,
    *,
    expected_state: dict[str, object],
) -> bool:
    """Tombstone only the exact signed state snapshot that was classified."""

    return _ask("clear_state_if", guard_home, expected=expected_state).get("done") is True


def _daemon_lifecycle_artifact_is_exact_tombstone(path: Path) -> bool:
    return _ask("state_tombstone", path.parent).get("tombstone") is True


def load_authenticated_guard_daemon_pending_launch(guard_home: Path) -> dict[str, object] | None:
    """One signed pending-launch identity, or ``None``."""

    return _optional_mapping(_ask("pending", guard_home), "pending")


def load_authenticated_guard_daemon_start_progress(guard_home: Path) -> dict[str, object] | None:
    """One signed still-starting record, or ``None``."""

    return _optional_mapping(_ask("progress", guard_home), "progress")


def _lifecycle_events(guard_home: Path, *, limit: int, incident: bool) -> tuple[list[dict[str, object]], str]:
    try:
        answer = _ask("lifecycle_events", guard_home, limit=max(0, limit), incident=incident)
    except RuntimeError:
        return [], "journal_unavailable"
    events = answer.get("events")
    status = answer.get("status")
    if not isinstance(events, list) or not isinstance(status, str):
        return [], "journal_unavailable"
    return [cast("dict[str, object]", event) for event in events if isinstance(event, dict)], status


def load_daemon_lifecycle_events(guard_home: Path, *, limit: int = 20) -> list[dict[str, object]]:
    """The newest lifecycle journal events, oldest first."""

    return _lifecycle_events(guard_home, limit=limit, incident=False)[0]


def load_bounded_incident_lifecycle_events(guard_home: Path, *, limit: int = 20) -> tuple[list[dict[str, object]], str]:
    """A small journal snapshot for incident reports, with why entries are missing."""

    return _lifecycle_events(guard_home, limit=limit, incident=True)


def _guard_daemon_start_in_progress(guard_home: Path) -> bool:
    return _ask("start_in_progress", guard_home, current=_current_state()).get("in_progress") is True


# --- the approval-center locator -----------------------------------------------------------------


def _locator(value: object) -> ApprovalCenterLocator | None:
    if not isinstance(value, dict):
        return None
    payload = cast("dict[str, object]", value)
    return ApprovalCenterLocator(
        guard_home=Path(str(payload["guard_home"])),
        daemon_url=str(payload["daemon_url"]),
        approval_url_base=str(payload["approval_url_base"]),
        pid=int(cast("int", payload["pid"])),
        started_at=str(payload["started_at"]),
        state_path=Path(str(payload["state_path"])),
    )


def read_approval_center_locator(guard_home: Path) -> ApprovalCenterLocator | None:
    try:
        return _locator(_ask("locator_read", guard_home).get("locator"))
    except (OSError, RuntimeError, ValueError, KeyError):
        return None


def publish_approval_center_locator(guard_home: Path, daemon_url: str) -> ApprovalCenterLocator:
    """Publish browser discovery for an already authenticated live daemon."""

    locator = _locator(_ask("locator_publish", guard_home, daemon_url=daemon_url).get("locator"))
    if locator is None:
        raise RuntimeError("Guard daemon identity does not match the active local service.")
    return locator


def repair_approval_center_locator(guard_home: Path) -> dict[str, object]:
    """Repair stale locator and authenticated daemon-discovery state."""

    answer = _daemon_manage("repair_locator", guard_home)
    if answer is None:
        raise RuntimeError("Guard could not repair the daemon locator: the native runtime did not answer.")
    error = answer.get("error")
    if error is not None or answer.get("repaired") is not True:
        raise RuntimeError(f"Guard daemon locator repair stopped safely: {error}.")
    cleared = answer.get("cleared")
    return {"repaired": True, "cleared": list(cleared) if isinstance(cleared, list) else []}


# --- processes -----------------------------------------------------------------------------------


def _pid_facts(pid: int, *want: str, expected_home: Path | None = None) -> dict[str, object]:
    home = expected_home or _implicit_daemon_guard_home()
    try:
        return _ask(
            "pid",
            home,
            pid=pid,
            want=list(want),
            expected_home=None if expected_home is None else str(expected_home),
        )
    except (OSError, RuntimeError, ValueError):
        return {}


def _guard_daemon_pid_is_running(pid: int) -> bool:
    return _pid_facts(pid, "running").get("running") is True


def _guard_daemon_pid_is_proven_dead(pid: int) -> bool:
    return _pid_facts(pid, "proven_dead").get("proven_dead") is True


def _guard_daemon_command_for_pid(pid: int) -> str | None:
    command = _pid_facts(pid, "command").get("command")
    return command if isinstance(command, str) else None


def _guard_daemon_pid_command_identity(pid: int, *, expected_guard_home: Path | None = None) -> bool | None:
    """Classify a PID as the expected daemon, another process, or unresolvable."""

    identity = _pid_facts(pid, "identity", expected_home=expected_guard_home).get("identity")
    return identity if isinstance(identity, bool) else None


def _guard_daemon_pid_matches_command(pid: int, expected_guard_home: Path | None = None) -> bool:
    return _pid_facts(pid, "matches_home", expected_home=expected_guard_home).get("matches_home") is True


def _guard_daemon_pid_identity_for_retirement(pid: int) -> tuple[str, str] | None:
    """An exact process generation and OS owner, captured before inventory signals."""

    value = _pid_facts(pid, "retirement").get("retirement")
    if isinstance(value, list) and len(value) == 2 and all(isinstance(part, str) and part for part in value):
        return str(value[0]), str(value[1])
    return None


def process_start_token(pid: int, *, deadline_monotonic: float | None = None) -> str | None:
    if deadline_monotonic is None:
        return _process_start_marker(pid)
    return _process_start_marker(pid, deadline_monotonic=deadline_monotonic)


def _retire_guard_daemon_pid(
    pid: int,
    *,
    expected_guard_home: Path | None = None,
    expected_creation_time: int | None = None,
    expected_start_marker: str | None = None,
    expected_owner_marker: str | None = None,
    timeout: float | None = None,
    deadline_monotonic: float | None = None,
    expected_start_token: str | None = None,
) -> bool:
    start_marker = expected_start_marker if expected_start_marker is not None else expected_start_token
    deadline = None if timeout is None else time.monotonic() + max(0.0, timeout)
    if deadline_monotonic is not None:
        deadline = deadline_monotonic if deadline is None else min(deadline, deadline_monotonic)
    answer = _daemon_manage(
        "retire_pid",
        expected_guard_home or _implicit_daemon_guard_home(),
        deadline=deadline,
        args={
            "pid": pid,
            "expected_home": None if expected_guard_home is None else str(expected_guard_home),
            "creation_time": expected_creation_time,
            "start_marker": start_marker,
            "owner_marker": expected_owner_marker,
        },
    )
    return answer is not None and answer.get("retired") is True


def _running_guard_daemon_processes_for_guard_home(guard_home: Path) -> list[tuple[int, int]]:
    try:
        answer = _ask("inventory", guard_home)
    except (OSError, RuntimeError, ValueError):
        return []
    processes = answer.get("processes")
    if not isinstance(processes, list):
        return []
    return [(int(entry[0]), int(entry[1])) for entry in processes if isinstance(entry, list) and len(entry) == 2]


def _split_process_command(command: str) -> list[str] | None:
    return cast("list[str] | None", _lifecycle("split_command", {"command": command})["parts"])


def _trusted_frozen_bootloader_parent_pid(guard_home: Path) -> int | None:
    """The proven PyInstaller one-file parent PID for this daemon child."""

    if not bool(getattr(sys, "frozen", False)):
        return None
    parent_pid = os.getppid()
    if parent_pid <= 1 or parent_pid == os.getpid():
        return None
    try:
        executable = str(Path(sys.executable).expanduser().resolve(strict=True))
    except (OSError, RuntimeError):
        return None
    answer = _daemon_manage(
        "pid",
        guard_home,
        args={"pid": parent_pid, "want": ["command", "matches_home"], "expected_home": str(guard_home)},
        frozen_check=False,
    )
    if answer is None or answer.get("matches_home") is not True:
        return None
    command = answer.get("command")
    if not isinstance(command, str):
        return None
    parts = _split_process_command(command) if os.name == "nt" else None
    head = parts[0] if parts else command[: len(executable)]
    try:
        trusted = Path(head).resolve(strict=True) == Path(executable)
    except (OSError, RuntimeError):
        return None
    return parent_pid if trusted else None


# --- locks ---------------------------------------------------------------------------------------


def _lock_file(handle: BinaryIO, deadline: float | None) -> bool:
    """Take the exclusive lock on `handle`, waiting until `deadline` (forever when `None`)."""

    if os.name == "nt":
        handle.seek(0)
        if os.fstat(handle.fileno()).st_size == 0:
            handle.write(b"0")
            handle.flush()
    while True:
        try:
            _try_lock_once(handle)
            return True
        except OSError:
            if deadline is not None and time.monotonic() >= deadline:
                return False
            remaining = GUARD_DAEMON_POLL_INTERVAL_SECONDS if deadline is None else deadline - time.monotonic()
            time.sleep(max(0.0, min(GUARD_DAEMON_POLL_INTERVAL_SECONDS, remaining)))


@contextmanager
def guard_daemon_start_lock(guard_home: Path, *, deadline: float | None = None) -> Generator[None]:
    """Serialize daemon replacement while allowing a lock-owning repair to restart."""

    lock_key = str(guard_home.resolve())
    depth_key = (threading.get_ident(), lock_key)
    with _LOCKS_GUARD:
        thread_lock = _START_LOCKS.setdefault(lock_key, threading.Lock())
        depth = _START_DEPTHS.get(depth_key, 0)
        if depth:
            _START_DEPTHS[depth_key] = depth + 1
    if depth:
        try:
            yield
        finally:
            with _LOCKS_GUARD:
                remaining = _START_DEPTHS[depth_key] - 1
                if remaining:
                    _START_DEPTHS[depth_key] = remaining
                else:
                    _ = _START_DEPTHS.pop(depth_key, None)
        return
    if not thread_lock.acquire(timeout=-1 if deadline is None else max(0.0, deadline - time.monotonic())):
        raise RuntimeError("Timed out waiting to start the Guard daemon.")
    try:
        lock_path = guard_home / _START_LOCK_FILE
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        with lock_path.open("a+b") as handle:
            if not _lock_file(handle, deadline):
                raise RuntimeError("Timed out waiting to start the Guard daemon.")
            try:
                with _LOCKS_GUARD:
                    _START_DEPTHS[depth_key] = 1
                yield
            finally:
                with _LOCKS_GUARD:
                    _ = _START_DEPTHS.pop(depth_key, None)
                release_file_lock(handle)
    finally:
        thread_lock.release()


_guard_daemon_start_lock = guard_daemon_start_lock


@contextmanager
def _guard_daemon_recovery_lock(guard_home: Path, *, timeout_seconds: float | None = None) -> Generator[None]:
    """Serialize a complete daemon recovery transaction for one Guard home."""

    lock_key = str(guard_home.resolve())
    with _LOCKS_GUARD:
        thread_lock = _RECOVERY_LOCKS.setdefault(lock_key, threading.Lock())
    deadline = None if timeout_seconds is None else time.monotonic() + max(0.0, timeout_seconds)
    if not thread_lock.acquire(timeout=-1 if deadline is None else max(0.0, deadline - time.monotonic())):
        raise RuntimeError("Timed out waiting for Guard daemon recovery ownership.")
    try:
        lock_path = guard_home / _RECOVERY_LOCK_FILE
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        with lock_path.open("a+b") as handle:
            if not _lock_file(handle, deadline):
                raise RuntimeError("Timed out waiting for Guard daemon recovery ownership.")
            try:
                yield
            finally:
                release_file_lock(handle)
    finally:
        thread_lock.release()


def _try_lock_once(handle: BinaryIO) -> None:
    if os.name == "nt":
        import msvcrt

        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
    else:
        import fcntl

        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)


def try_lock_daemon_file(handle: BinaryIO) -> bool:
    """Take the exclusive lock on `handle` without waiting."""

    return _lock_file(handle, time.monotonic())
