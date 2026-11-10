"""Guard daemon lifecycle helpers."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import logging
import math
import ntpath
import os
import re
import secrets
import signal
import stat
import subprocess
import sys
import sysconfig
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from contextlib import contextmanager, suppress
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, TypedDict, cast

from ...version import __version__
from .. import live_process_identity as _live_process_identity
from .. import posix_processes, windows_processes
from ..fork_safety import forget_in_child
from ..frozen_runtime_commands import (
    decode_frozen_daemon_serve_payload,
)
from ..live_process_identity import process_owner_marker
from ..mdm.file_lock import release_file_lock
from ..native_daemon_lifecycle import (
    NativeDaemonLifecycleError,
    await_native_runtime,
    bind_daemon_lifecycle_deadline,
    native_daemon_lifecycle,
    reset_daemon_lifecycle_deadline,
)
from ..private_file_io import read_private_regular_text
from ..windows_paths import (
    windows_command_line_to_argv,
    windows_process_creation_time,
    windows_process_is_running,
    windows_process_liveness,
    windows_terminate_process_if_creation_time,
)
from .atomic_replace import replace_file
from .auth_token import auth_token_path as _auth_token_path
from .auth_token import load_guard_daemon_auth_token as load_guard_daemon_auth_token
from .discovery import (
    authenticate_daemon_state,
    ensure_daemon_discovery_key,
    load_authenticated_daemon_state,
    load_daemon_discovery_key,
    verify_daemon_state,
)
from .file_locking import lock_daemon_file as _lock_daemon_start_file
from .file_locking import try_lock_daemon_file as _try_lock_daemon_file
from .handed_off_launch import resolve_handed_off_guard_daemon_pending_launch
from .lifecycle_journal import record_daemon_lifecycle_event as record_daemon_lifecycle_event
from .pipx_import_paths import pipx_shared_import_paths
from .start_heartbeat import (
    START_HEARTBEAT_CODE,
)
from .start_lock import guard_daemon_start_lock as _guard_daemon_start_lock
from .startup_phase import timed_phase

_LOGGER = logging.getLogger(__name__)
GUARD_DAEMON_COMPATIBILITY_VERSION = 2
GUARD_DAEMON_POLL_INTERVAL_SECONDS = 0.1
# Slowest observed cold start on a loaded host.  The resident adds its own
# margin on top of this floor (the contract field is still named
# ``worker_ready_floor``), so the client outlasts a daemon that is still
# binding its socket and writing its state file.
_START_TIMEOUT_FLOOR_SECONDS = 14.0
_EPHEMERAL_GUARD_DAEMON_REAP_INTERVAL_SECONDS = 30.0
_EPHEMERAL_GUARD_DAEMON_STALE_SECONDS = 30.0
_EPHEMERAL_GUARD_DAEMON_MAX_STATES = 512
_GUARD_DAEMON_PRIVATE_FILE_MODE = 0o600
_GUARD_DAEMON_PRIVATE_DIR_MODE = 0o700
_APPROVAL_CENTER_LOCATOR_FILE = "approval-center-locator.json"
_GUARD_DAEMON_PENDING_LAUNCH_FILE = "daemon-launch-pending.json"
_GUARD_DAEMON_LAUNCH_NONCE_ENV = "HOL_GUARD_DAEMON_LAUNCH_NONCE"
_GUARD_DAEMON_LAUNCH_NONCE_HEX_LENGTH = 64
_GUARD_DAEMON_START_PROGRESS_FILE = "daemon-start-progress.json"
_GUARD_DAEMON_WAKE_RESERVATION_FILE = "daemon-wake-reservation.json"
_GUARD_DAEMON_RECOVERY_RESERVATION_FILE = "daemon-recovery-reservation.json"
_GUARD_DAEMON_OWNER_LOCK_FILE = "daemon-owner.lock"
_GUARD_DAEMON_RECOVERY_LOCK_FILE = "daemon-recovery.lock"
_GUARD_DAEMON_STATE_MAX_BYTES = 64 * 1024
_GUARD_DAEMON_PENDING_LAUNCH_MAX_BYTES = 4096
_GUARD_DAEMON_START_PROGRESS_MAX_BYTES = 4096
_GUARD_DAEMON_RESERVATION_MAX_BYTES = 4096
_GUARD_DAEMON_RECOVERY_WORKER_TIMEOUT_SECONDS = 30.0
_START_CLASSIFICATION_RESERVE_SECONDS = 3.0
_START_CLASSIFICATION_RESERVE_FRACTION = 0.25
# One readiness poll may ask the resident who published daemon state. Cap that
# ask so a missed answer is retried instead of spending the whole start budget.
_SPAWNED_URL_POLL_LIFECYCLE_SECONDS = 5.0
_GUARD_DAEMON_PROCESS_QUERY_OUTPUT_LIMIT_BYTES = 1024 * 1024
_RUNTIME_FINGERPRINT_HEX_LENGTH = 64
_WINDOWS_CREATE_NEW_PROCESS_GROUP = 0x00000200
_WINDOWS_DETACHED_PROCESS = 0x00000008
_WINDOWS_CREATE_BREAKAWAY_FROM_JOB = 0x01000000
_GUARD_DAEMON_BOOTSTRAP = (
    "import json,runpy,sys; "
    # Signal liveness before the slow Guard imports so a cold start is not
    # mistaken for a stuck child.
    f"exec({START_HEARTBEAT_CODE!r}); "
    "trusted_prefix=sys.argv.pop(1); "
    "trusted_exec_prefix=sys.argv.pop(1); "
    "trusted_paths=json.loads(sys.argv.pop(1)); "
    "module=sys.argv.pop(1); "
    "sys.prefix=trusted_prefix; "
    "sys.exec_prefix=trusted_exec_prefix; "
    "sys.path[:0]=trusted_paths; "
    "sys.argv[0]=module; "
    "runpy.run_module(module,run_name='__main__',alter_sys=True)"
)
_GUARD_DAEMON_GATED_BOOTSTRAP = (
    "import sys; gate=sys.stdin.buffer.read(1); sys.exit(70) if gate != b'1' else None; " + _GUARD_DAEMON_BOOTSTRAP
)
_GUARD_DAEMON_ENV_KEYS = frozenset(
    {
        "APPDATA",
        "COMSPEC",
        "GUARD_DAEMON_IDLE_TIMEOUT_SECONDS",
        "HOME",
        "HOL_GUARD_DESKTOP",
        "HOL_GUARD_DESKTOP_RUNTIME_OWNER",
        "HOL_GUARD_DESKTOP_VERSION",
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
_SHIM_TOOL_DIRS_ENV = "HOL_GUARD_SHIM_TOOL_DIRS"
_GUARD_DAEMON_DESKTOP_ENV_KEYS = ("HOL_GUARD_DESKTOP", "HOL_GUARD_DESKTOP_RUNTIME_OWNER", "HOL_GUARD_DESKTOP_VERSION")
_RECOVERY_LOCKS: dict[str, threading.Lock] = {}
_RECOVERY_LOCKS_GUARD = threading.Lock()
_STATE_WRITE_LOCKS: dict[str, threading.Lock] = {}
_STATE_WRITE_LOCKS_GUARD = threading.Lock()
_EPHEMERAL_REAP_SCHEDULE_LOCK = threading.Lock()
_EPHEMERAL_REAP_IN_FLIGHT = False
_DUPLICATE_RETIRE_SCHEDULE_LOCK = threading.Lock()
_DUPLICATE_RETIRE_IN_FLIGHT: set[str] = set()
forget_in_child(_RECOVERY_LOCKS)
forget_in_child(_STATE_WRITE_LOCKS)
forget_in_child(_DUPLICATE_RETIRE_IN_FLIGHT)
_LAST_EPHEMERAL_REAP_AT = 0.0
_runtime_fingerprint_cache: tuple[str, str] | None = None


def _launch_nonce_is_valid(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == _GUARD_DAEMON_LAUNCH_NONCE_HEX_LENGTH
        and re.fullmatch(r"[0-9a-f]+", value) is not None
    )


GuardDaemonHookFailureKind = Literal[
    "authenticated-control-plane-failure",
    "overload",
    "transport-failure",
]


@dataclasses.dataclass(frozen=True, slots=True)
class ApprovalCenterLocator:
    """Structured snapshot of where the Guard approval-center daemon is running."""

    guard_home: Path
    daemon_url: str
    approval_url_base: str
    pid: int
    started_at: str
    state_path: Path


class _ExistingGuardDaemon(TypedDict):
    url: str
    auth_token: str
    pid: int


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


def _daemon_launcher_env(
    *,
    home_dir: Path | None = None,
    guard_home: Path | None = None,
    executable: Path | None = None,
    launch_nonce: str | None = None,
) -> dict[str, str]:
    """Build a minimal detached-daemon environment without Python startup hooks."""

    env = {key: value for key, value in os.environ.items() if key.upper() in _GUARD_DAEMON_ENV_KEYS}
    trusted_home = _trusted_daemon_home(home_dir)
    env.update(
        {
            "HOME": str(trusted_home),
            "PYTHONNOUSERSITE": "1",
            "PYTHONSAFEPATH": "1",
            # The daemon inherits its launcher's PATH, which a desktop or IDE launcher
            # reduces to the system directories. Package-manager detection must still
            # find what the user's shell reaches, so it searches the well-known
            # directories too. A launching shell cannot switch this off.
            _SHIM_TOOL_DIRS_ENV: "1",
        }
    )
    if getattr(sys, "frozen", False) is True or executable is not None:
        env["PYINSTALLER_RESET_ENVIRONMENT"] = "1"
        for key in _GUARD_DAEMON_DESKTOP_ENV_KEYS:
            if value := os.environ.get(key):
                env[key] = value
            else:
                env.pop(key, None)
    else:
        env.pop("PYINSTALLER_RESET_ENVIRONMENT", None)
        for key in _GUARD_DAEMON_DESKTOP_ENV_KEYS:
            env.pop(key, None)
    if os.name == "nt":
        env["USERPROFILE"] = str(trusted_home)
    if guard_home is not None and not _guard_home_is_ephemeral(guard_home):
        env["GUARD_DAEMON_IDLE_TIMEOUT_SECONDS"] = "0"
    if isinstance(launch_nonce, str) and _launch_nonce_is_valid(launch_nonce):
        env[_GUARD_DAEMON_LAUNCH_NONCE_ENV] = launch_nonce
    _bind_native_runtime_override(env)
    return env


def _bind_native_runtime_override(env: dict[str, str]) -> None:
    """Hand the daemon the caller's pinned native runtime.

    The daemon's route policy has no Python answer, so a daemon without a
    native runtime fails every POST closed. A shadow/force override with an
    explicit binary is how a source checkout names its runtime; without this
    the minimal environment would drop it and the detached daemon would find no
    runtime. ``off`` and ``auto`` are never forwarded, so an ambient value
    can name a runtime but cannot switch the native path off for the daemon.
    """

    from ..native_runtime import native_mode

    binary = os.environ.get("HOL_GUARD_NATIVE_BINARY")
    mode = native_mode()
    if binary and Path(binary).is_absolute() and mode in {"shadow", "force"}:
        env["HOL_GUARD_NATIVE"] = mode
        env["HOL_GUARD_NATIVE_BINARY"] = binary
    # Daemon startup asks the source compiler whether this installation carries
    # a release bundle. A source checkout names its compiler the same way; the
    # compiler refuses either override when a packaged compiler is present.
    for key in ("HOL_GUARD_NATIVE_SOURCE_COMPILER", "HOL_GUARD_NATIVE_TEST_SOURCE_COMPILER"):
        if (compiler := os.environ.get(key)) and Path(compiler).is_absolute():
            env[key] = compiler


def _trusted_daemon_prefix(value: str) -> Path:
    prefix = Path(value).expanduser()
    if not prefix.is_absolute():
        raise RuntimeError("Guard daemon requires an absolute active Python prefix.")
    try:
        resolved = prefix.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise RuntimeError("Guard daemon requires an available active Python prefix.") from error
    if not resolved.is_dir():
        raise RuntimeError("Guard daemon requires a directory-valued active Python prefix.")
    return resolved


def _trusted_daemon_interpreter() -> Path:
    interpreter = Path(sys.executable).expanduser()
    if not interpreter.is_absolute() or not interpreter.is_file():
        raise RuntimeError("Guard daemon requires an absolute active Python interpreter.")
    return interpreter


def _trusted_daemon_python_flags() -> list[str]:
    flags = ["-I"]
    if tuple(sys.version_info[:2]) >= (3, 11):
        flags.append("-P")
    return flags


def _trusted_daemon_import_paths() -> tuple[Path, ...]:
    source_root = Path(__file__).resolve().parents[3]
    candidates = [source_root]
    try:
        configured_paths = sysconfig.get_paths()
    except (AttributeError, KeyError, OSError, TypeError, ValueError) as error:
        raise RuntimeError("Guard daemon could not resolve active Python import paths.") from error
    for key in ("purelib", "platlib"):
        value = configured_paths.get(key)
        if isinstance(value, str) and value.strip():
            candidates.append(Path(value).expanduser())

    candidates.extend(pipx_shared_import_paths(_trusted_daemon_prefix(sys.prefix), configured_paths))

    trusted_paths: list[Path] = []
    seen: set[Path] = set()
    for index, candidate in enumerate(candidates):
        required = index == 0
        if not candidate.is_absolute():
            if required:
                raise RuntimeError("Guard daemon requires absolute trusted import paths.")
            continue
        try:
            resolved = candidate.resolve(strict=True)
        except (OSError, RuntimeError) as error:
            if required:
                raise RuntimeError("Guard daemon requires available trusted import paths.") from error
            continue
        if not resolved.is_dir():
            if required:
                raise RuntimeError("Guard daemon requires directory-valued trusted import paths.")
            continue
        if resolved not in seen:
            seen.add(resolved)
            trusted_paths.append(resolved)
    return tuple(trusted_paths)


def _isolated_python_module_command(
    module: str,
    import_paths: tuple[Path, ...],
    module_args: list[str],
    *,
    gate_on_stdin: bool = False,
) -> list[str]:
    return [
        str(_trusted_daemon_interpreter()),
        *_trusted_daemon_python_flags(),
        "-S",
        "-c",
        _GUARD_DAEMON_GATED_BOOTSTRAP if gate_on_stdin else _GUARD_DAEMON_BOOTSTRAP,
        str(_trusted_daemon_prefix(sys.prefix)),
        str(_trusted_daemon_prefix(sys.exec_prefix)),
        json.dumps([str(path) for path in import_paths], separators=(",", ":")),
        module,
        *module_args,
    ]


def _native_int(value: object) -> int | None:
    """``value`` when it is a real integer (not a bool), otherwise ``None``."""

    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _native_fields(source: Mapping[str, object], keys: tuple[str, ...]) -> dict[str, object]:
    """The decision-relevant fields of a loaded record, in a JSON-safe form."""

    fields: dict[str, object] = {}
    for key in keys:
        value = source.get(key)
        fields[key] = None if isinstance(value, float) and not math.isfinite(value) else value
    return fields


def _reservation_facts(reservation: dict[str, object] | None) -> dict[str, object] | None:
    if not isinstance(reservation, dict):
        return None
    return _native_fields(
        reservation,
        ("created_at", "pid", "process_command_digest", "process_start_marker", "process_creation_time"),
    )


def _lifecycle_fact_resolver(guard_home: Path | None) -> Callable[[str], object]:
    """Answer the resident's fact requests from the operating system."""

    def resolve(key: str) -> object:
        kind, _, argument = key.partition(":")
        if kind == "argv":
            return windows_command_line_to_argv(argument)
        if kind == "frozen":
            try:
                decoded_home, _executable, decoded_port = decode_frozen_daemon_serve_payload(argument)
            except (OSError, RuntimeError, TypeError, ValueError):
                return None
            return {"guard_home": str(decoded_home), "port": decoded_port}
        if kind == "resolve":
            try:
                return str(Path(argument).resolve())
            except OSError:
                return None
        if key == "frozen_parent_trusted":
            from ..frozen_daemon_runtime import _trusted_frozen_bootloader_parent_pid

            return guard_home is not None and _trusted_frozen_bootloader_parent_pid(guard_home) == os.getppid()
        if key == "heartbeat_age":
            return None if guard_home is None else _runtime_state_age_seconds(guard_home)
        pid = int(argument)
        if kind == "pid_running":
            return _guard_daemon_pid_is_running(pid)
        if kind == "cmd":
            return _guard_daemon_command_for_pid(pid)
        if kind == "start_token":
            return process_start_token(pid)
        if kind == "win_ctime":
            return windows_process_creation_time(pid)
        if kind == "win_live":
            return windows_process_liveness(pid)
        if kind == "matches_command":
            return _guard_daemon_pid_matches_command(pid, expected_guard_home=guard_home)
        raise NativeDaemonLifecycleError("native_daemon_lifecycle_fact_unknown")

    return resolve


def _lifecycle(
    check: str,
    query: Mapping[str, object],
    *,
    home: Path | None = None,
    facts_home: Path | None = None,
) -> dict[str, Any]:
    """The resident's verdict for one lifecycle ``check``; Python never recomputes it."""

    return native_daemon_lifecycle(
        check,
        query,
        resolve_fact=_lifecycle_fact_resolver(facts_home),
        guard_home=home,
        platform="nt" if os.name == "nt" else "posix",
    )


def _start_timeouts() -> dict[str, Any]:
    query = {
        "desktop": os.environ.get("HOL_GUARD_DESKTOP", "").strip() == "1",
        "worker_ready_floor": _START_TIMEOUT_FLOOR_SECONDS,
    }
    return _lifecycle("start_timeouts", query)


def desktop_preflight_requested() -> bool:
    return os.environ.get("HOL_GUARD_DESKTOP_PREFLIGHT", "").strip().lower() in {"1", "true", "yes"}


def _default_guard_daemon_start_timeout() -> float:
    return float(_start_timeouts()["default"])


def _post_update_guard_daemon_start_timeout() -> float:
    return float(_start_timeouts()["post_update"])


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
) -> str:
    if desktop_preflight_requested():
        raise RuntimeError("Guard daemon start is disabled during Desktop preflight.")
    if deadline_monotonic is not None and (
        isinstance(deadline_monotonic, bool) or not math.isfinite(deadline_monotonic)
    ):
        raise ValueError("Guard daemon operation deadline is invalid.")
    caller_deadline = bind_daemon_lifecycle_deadline(deadline_monotonic)
    try:
        timeout = _default_guard_daemon_start_timeout() if start_timeout is None else start_timeout
        start_deadline = time.monotonic() + max(0.0, timeout)
        if deadline_monotonic is not None:
            start_deadline = min(start_deadline, deadline_monotonic)
            if time.monotonic() >= start_deadline:
                raise TimeoutError("Guard daemon operation deadline exceeded.")
        operation_deadline = bind_daemon_lifecycle_deadline(start_deadline)
        try:
            return _ensure_guard_daemon_body(
                guard_home,
                home_dir=home_dir,
                preferred_port=preferred_port,
                allow_windows_job_breakaway=allow_windows_job_breakaway,
                executable=executable,
                start_deadline=start_deadline,
                background_maintenance=background_maintenance,
            )
        finally:
            reset_daemon_lifecycle_deadline(operation_deadline)
    finally:
        reset_daemon_lifecycle_deadline(caller_deadline)


def _ensure_guard_daemon_body(
    guard_home: Path,
    *,
    home_dir: Path | None,
    preferred_port: int | None,
    allow_windows_job_breakaway: bool,
    executable: Path | None,
    start_deadline: float,
    background_maintenance: bool,
) -> str:
    """Reuse, adopt or launch the home's daemon through `daemon-manage ensure`."""

    from . import start_lock
    from .native_serve import launch_configuration, native_serve_executable

    if background_maintenance:
        _schedule_stale_ephemeral_guard_daemon_reap(exclude_guard_home=guard_home)
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
    lock_key = str(guard_home.resolve())
    start_lock_held = any(key == lock_key and depth > 0 for (_thread, key), depth in start_lock._THREAD_DEPTHS.items())
    answer = _daemon_manage(
        "ensure",
        guard_home,
        deadline=start_deadline,
        allow_windows_breakaway=True,
        extra={
            "launch": launch,
            "serve_executable": str(serve_executable) if serve_executable is not None else None,
            "executable": str(executable) if executable is not None else None,
            "home_dir": str(trusted_home),
            "launch_cwd": str(trusted_home),
            "preferred_port": preferred_port if isinstance(preferred_port, int) and preferred_port > 0 else None,
            "background_maintenance": background_maintenance,
            "allow_windows_job_breakaway": allow_windows_job_breakaway,
            "start_lock_held": start_lock_held,
            "launcher_env": _daemon_launcher_env(home_dir=home_dir, guard_home=guard_home, executable=executable),
            "env_port": os.environ.get("GUARD_DAEMON_PORT"),
        },
    )
    if answer is None:
        if time.monotonic() >= start_deadline:
            raise TimeoutError("Guard daemon operation deadline exceeded.")
        raise RuntimeError("Guard daemon start requires the native runtime.")
    url = answer.get("url")
    if isinstance(url, str) and url:
        if background_maintenance:
            _schedule_duplicate_guard_daemon_retirement(guard_home)
        return url
    message = answer.get("error")
    text = message if isinstance(message, str) and message else "Guard approval center did not start."
    raise RuntimeError(text)


def _windows_daemon_creation_flags(*, allow_job_breakaway: bool) -> int:
    flags = _WINDOWS_CREATE_NEW_PROCESS_GROUP | _WINDOWS_DETACHED_PROCESS
    if allow_job_breakaway:
        flags |= _WINDOWS_CREATE_BREAKAWAY_FROM_JOB
    return flags


def ensure_guard_daemon_after_update(
    guard_home: Path,
    *,
    home_dir: Path,
    preferred_port: int | None = None,
    allow_windows_job_breakaway: bool = False,
    executable: Path | None = None,
) -> str:
    """Restart the local daemon after a package update with a longer startup window."""
    if executable is None:
        return ensure_guard_daemon(
            guard_home,
            home_dir=home_dir,
            start_timeout=_post_update_guard_daemon_start_timeout(),
            preferred_port=preferred_port,
            allow_windows_job_breakaway=allow_windows_job_breakaway,
        )
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
    from .recovery_lifecycle import recover_guard_daemon_after_hook_failure as recover

    return recover(
        guard_home,
        home_dir=home_dir,
        failure_kind=failure_kind,
        recovery_lock_timeout_seconds=recovery_lock_timeout_seconds,
    )


def schedule_guard_daemon_recovery(
    guard_home: Path,
    *,
    home_dir: Path | None = None,
    failure_kind: GuardDaemonHookFailureKind = "authenticated-control-plane-failure",
    executable: Path | None = None,
) -> None:
    from .recovery_lifecycle import schedule_guard_daemon_recovery as schedule

    schedule(
        guard_home,
        home_dir=home_dir,
        failure_kind=failure_kind,
        executable=executable,
    )


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


_DAEMON_MANAGE_DEFAULT_SECONDS = 30.0
_DAEMON_MANAGE_OUTPUT_LIMIT = 64 * 1024


def _daemon_manage(
    op: str,
    guard_home: Path,
    *,
    keep_port: int | None = None,
    deadline: float | None = None,
    allow_windows_breakaway: bool = False,
    extra: Mapping[str, object] | None = None,
) -> dict[str, object] | None:
    """One `daemon-manage` answer from the native runtime, or `None`."""

    from ..frozen_daemon_runtime import _trusted_frozen_bootloader_parent_pid
    from ..mdm.runtime_request import runtime_answer

    manage_deadline = time.monotonic() + _DAEMON_MANAGE_DEFAULT_SECONDS if deadline is None else deadline

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
            "frozen_runtime": bool(getattr(sys, "frozen", False)),
            "frozen_parent_trusted": _trusted_frozen_bootloader_parent_pid(guard_home) == os.getppid(),
            "executable_name": ntpath.basename(sys.executable).strip().lower() or None,
            "budget_ms": min(int(budget * 1000), 600_000),
        }
        if keep_port is not None:
            payload["keep_port"] = keep_port
        if extra:
            payload.update({key: value for key, value in extra.items() if value is not None})
        return payload

    return runtime_answer(
        "daemon-manage-v1",
        "daemon-manage",
        request,
        output_limit=_DAEMON_MANAGE_OUTPUT_LIMIT,
        deadline=manage_deadline + 1.0,
        **({"allow_windows_breakaway": True} if allow_windows_breakaway else {}),
    )


_ORPHAN_REAP_TIMEOUT_SECONDS = 15.0
_ORPHAN_REAP_LAUNCH_RESERVE_SECONDS = 0.25
_ORPHAN_REAP_MAX_BUDGET_MS = 60_000
_ORPHAN_REAP_OUTPUT_LIMIT = 64 * 1024


def reap_orphaned_daemon_workers(*, deadline: float | None = None) -> None:
    """Stop hook workers whose daemon parent is already gone.

    The native runtime lists the processes, selects the orphaned workers and
    stops them. A runtime that cannot answer leaves them for the next start,
    as a missing process listing did before. Without a caller deadline the
    status check and the reap share `_ORPHAN_REAP_TIMEOUT_SECONDS`.
    """

    if os.name == "nt":
        return
    from ..mdm.runtime_request import runtime_answer

    reap_deadline = time.monotonic() + _ORPHAN_REAP_TIMEOUT_SECONDS if deadline is None else deadline

    def request() -> dict[str, object] | None:
        # Sized after the status check, so a cold lookup never leaves the
        # runtime a budget longer than the launch has left.
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
        output_limit=_ORPHAN_REAP_OUTPUT_LIMIT,
        deadline=reap_deadline,
    )


def guard_daemon_retirement_is_complete(guard_home: Path) -> bool:
    """Prove no authenticated, pending, or enumerable daemon remains for a home."""

    answer = _daemon_manage("retirement_complete", guard_home)
    return answer is not None and answer.get("complete") is True


def guard_daemon_url_for_home(guard_home: Path) -> str:
    return f"http://127.0.0.1:{_configured_port(guard_home)}"


def _guard_daemon_wake_reservation_path(guard_home: Path) -> Path:
    return guard_home / _GUARD_DAEMON_WAKE_RESERVATION_FILE


def _load_reservation(path: Path) -> dict[str, object] | None:
    raw_payload = read_private_regular_text(
        path,
        max_bytes=_GUARD_DAEMON_RESERVATION_MAX_BYTES,
        require_private_parent=True,
    )
    if raw_payload is None:
        return None
    try:
        payload = json.loads(raw_payload)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def _clear_reservation(guard_home: Path, path: Path, token: str) -> bool:
    with _guard_daemon_state_write_lock(guard_home):
        reservation = _load_reservation(path)
        if not isinstance(reservation, dict) or not secrets.compare_digest(
            str(reservation.get("token", "")),
            token,
        ):
            return False
        _write_private_atomic_text(path, "{}")
    return True


def _claim_guard_daemon_wake_reservation(guard_home: Path) -> str | None:
    token = secrets.token_hex(16)
    now = time.time()
    _ensure_private_directory(guard_home)
    with _guard_daemon_state_write_lock(guard_home):
        existing = _load_reservation(_guard_daemon_wake_reservation_path(guard_home))
        query = {"existing": _reservation_facts(existing), "now": now}
        if not _lifecycle("wake_claim", query, home=guard_home)["claim"]:
            return None
        _write_private_atomic_text(
            _guard_daemon_wake_reservation_path(guard_home),
            json.dumps({"created_at": now, "token": token}, sort_keys=True),
        )
    return token


def clear_guard_daemon_wake_reservation(guard_home: Path, *, token: str) -> bool:
    return _clear_reservation(guard_home, _guard_daemon_wake_reservation_path(guard_home), token)


def _guard_daemon_recovery_reservation_path(guard_home: Path) -> Path:
    return guard_home / _GUARD_DAEMON_RECOVERY_RESERVATION_FILE


def _load_guard_daemon_recovery_reservation(guard_home: Path) -> dict[str, object] | None:
    return _load_reservation(_guard_daemon_recovery_reservation_path(guard_home))


def _claim_guard_daemon_recovery_reservation(guard_home: Path) -> str | None:
    token = secrets.token_hex(16)
    now = time.time()
    _ensure_private_directory(guard_home)
    with _guard_daemon_state_write_lock(guard_home):
        existing = _load_guard_daemon_recovery_reservation(guard_home)
        query = {"existing": _reservation_facts(existing), "now": now}
        if not _lifecycle("recovery_claim", query, home=guard_home)["claim"]:
            return None
        _write_private_atomic_text(
            _guard_daemon_recovery_reservation_path(guard_home),
            json.dumps({"created_at": now, "token": token}, sort_keys=True),
        )
    return token


def _bind_guard_daemon_recovery_reservation(
    guard_home: Path,
    *,
    token: str,
    pid: int,
    process_creation_time: int | None = None,
) -> bool:
    if pid <= 0:
        return False
    with _guard_daemon_state_write_lock(guard_home):
        reservation = _load_guard_daemon_recovery_reservation(guard_home)
        if not isinstance(reservation, dict) or not secrets.compare_digest(
            str(reservation.get("token", "")),
            token,
        ):
            return False
        payload = dict(reservation)
        payload["pid"] = pid
        process_command = _guard_daemon_command_for_pid(pid)
        if process_command is not None:
            payload["process_command_digest"] = hashlib.sha256(
                process_command.encode("utf-8", errors="replace")
            ).hexdigest()
        process_start_marker = process_start_token(pid)
        if process_start_marker is not None:
            payload["process_start_marker"] = process_start_marker
        if process_creation_time is not None:
            payload["process_creation_time"] = process_creation_time
        _write_private_atomic_text(
            _guard_daemon_recovery_reservation_path(guard_home),
            json.dumps(payload, sort_keys=True),
        )
    return True


def clear_guard_daemon_recovery_reservation(guard_home: Path, *, token: str) -> bool:
    return _clear_reservation(guard_home, _guard_daemon_recovery_reservation_path(guard_home), token)


def schedule_guard_daemon_ensure(
    guard_home: Path,
    *,
    home_dir: Path | None = None,
) -> str:
    """Reserve one detached daemon ensure without delaying a hook response.

    When a healthy daemon is not ready yet, return the predicted loopback origin
    so approval deep links stay absolute and repairable. Callers must not treat
    that predicted origin as a verified live URL.
    """

    if desktop_preflight_requested():
        return load_guard_daemon_url(guard_home) or ""
    existing_url = load_guard_daemon_url(guard_home)
    if existing_url is not None:
        return existing_url
    predicted_url = guard_daemon_url_for_home(guard_home)
    try:
        wake_token = _claim_guard_daemon_wake_reservation(guard_home)
    except (OSError, RuntimeError, ValueError):
        return predicted_url
    if wake_token is None:
        return predicted_url
    try:
        trusted_home = _trusted_daemon_home(home_dir)
        command = _isolated_python_module_command(
            "codex_plugin_scanner.cli",
            _trusted_daemon_import_paths(),
            [
                "guard",
                "daemon",
                "ensure",
                "--guard-home",
                str(guard_home),
                "--home",
                str(trusted_home),
                "--wake-token",
                wake_token,
            ],
        )
        launcher_env = _daemon_launcher_env(home_dir=trusted_home, guard_home=guard_home)
        if os.name == "nt":
            subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                cwd=trusted_home,
                env=launcher_env,
                creationflags=_windows_daemon_creation_flags(allow_job_breakaway=False),
            )
        else:
            subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                cwd=trusted_home,
                env=launcher_env,
                start_new_session=True,
            )
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError):
        with suppress(OSError, RuntimeError, ValueError):
            clear_guard_daemon_wake_reservation(guard_home, token=wake_token)
    return predicted_url


def load_guard_daemon_url(guard_home: Path) -> str | None:
    return _live_guard_daemon_url(guard_home, require_current_runtime=True)


def load_running_guard_daemon_identity(guard_home: Path, *, health_timeout: float = 1.0) -> tuple[str, str] | None:
    return _live_guard_daemon_identity(guard_home, require_current_runtime=True, health_timeout=health_timeout)


def _live_guard_daemon_url(
    guard_home: Path,
    *,
    require_current_runtime: bool = True,
    expected_pid: int | None = None,
) -> str | None:
    identity = _live_guard_daemon_identity(
        guard_home,
        require_current_runtime=require_current_runtime,
        expected_pid=expected_pid,
    )
    return identity[0] if identity is not None else None


def _live_guard_daemon_identity(
    guard_home: Path,
    *,
    require_current_runtime: bool = True,
    expected_pid: int | None = None,
    health_timeout: float = 1.0,
) -> tuple[str, str] | None:
    identity = _load_authenticated_daemon_identity(guard_home)
    if identity is None:
        return None
    payload, auth_token = identity
    if require_current_runtime and not _guard_daemon_state_matches_current_runtime(payload):
        return None
    gate_query = {"payload": _native_fields(payload, ("compatibility_version", "port", "pid"))}
    gate = _lifecycle("live_state_gate", gate_query, home=guard_home)
    if not gate["ok"]:
        return None
    port = int(gate["port"])
    pid = int(gate["pid"])
    if expected_pid is not None and not _guard_daemon_pid_is_spawned_launch(pid, expected_pid):
        return None
    url = f"http://127.0.0.1:{port}"
    try:
        with urllib.request.urlopen(_daemon_health_request(f"{url}/healthz"), timeout=health_timeout) as response:
            raw_payload = response.read().decode("utf-8")
            if response.status != 200 or not _healthz_payload_is_current(raw_payload):
                return None
    except (OSError, ValueError, urllib.error.URLError):
        return None
    if _guard_daemon_pid_matches_command(pid, expected_guard_home=guard_home):
        return url, auth_token
    # Wrapped daemons may require authenticated detailed health for binding.
    if _daemon_healthz_details_match_guard_home(url, guard_home, auth_token=auth_token, timeout=health_timeout):
        return url, auth_token
    return None


def _load_authenticated_daemon_identity(guard_home: Path) -> tuple[dict[str, object], str] | None:
    payload = load_authenticated_daemon_state(guard_home)
    if payload is None:
        return None
    auth_token = load_guard_daemon_auth_token(guard_home)
    binding = {"payload": _native_fields(payload, ("auth_token_id", "state_id")), "auth_token": auth_token}
    if auth_token is None or not _lifecycle("identity_binding", binding, home=guard_home)["bound"]:
        return None
    return payload, auth_token


def ensure_guard_daemon_auth_token(guard_home: Path) -> str:
    """Return the guard home's daemon auth token, creating it only when absent.

    Every daemon for one guard home must share this token: hooks sign approval
    links with the file's token, so a daemon minting its own would reject them.
    """

    token_path = _auth_token_path(guard_home)
    _ensure_private_directory(token_path.parent)
    with _guard_daemon_state_write_lock(guard_home):
        token = load_guard_daemon_auth_token(guard_home)
        if token is not None and token.strip():
            return token
        token = secrets.token_hex(16)
        _write_private_atomic_text(token_path, token)
        return token


def _daemon_health_request(url: str, auth_token: str | None = None) -> urllib.request.Request:
    headers: dict[str, str] = {}
    if isinstance(auth_token, str) and auth_token.strip():
        headers["X-Guard-Token"] = auth_token
    return urllib.request.Request(url, headers=headers, method="GET")


def _daemon_healthz_details_payload(url: str, auth_token: str, *, timeout: float = 1.0) -> dict[str, object] | None:
    try:
        request = _daemon_health_request(f"{url}/v1/healthz/details", auth_token)
        with urllib.request.urlopen(request, timeout=timeout) as response:
            if response.status != 200:
                return None
            payload = json.loads(response.read().decode("utf-8"))
    except (OSError, ValueError, json.JSONDecodeError, urllib.error.URLError):
        return None
    return payload if isinstance(payload, dict) else None


def _daemon_healthz_details_match_guard_home(
    url: str, guard_home: Path, *, auth_token: str, timeout: float = 1.0
) -> bool:
    payload = _daemon_healthz_details_payload(url, auth_token, timeout=timeout)
    if payload is None:
        return False
    return _healthz_payload_matches_guard_home(json.dumps(payload), guard_home)


def _daemon_healthz_details_match_current_runtime(payload: dict[str, object]) -> bool:
    """Match live daemon identity including protocol compatibility."""

    # Same-release peers still require a current compatibility version.
    # A peer with a different fingerprint must name its install root: a daemon
    # from before the upgrade omits it and would otherwise pass as a same-release peer.
    fingerprint = payload.get("runtime_fingerprint")
    if fingerprint != _current_guard_daemon_runtime_fingerprint() and not isinstance(payload.get("source_root"), str):
        return False
    return _guard_daemon_state_matches_current_runtime(payload)


def _guard_daemon_url_port(url: str) -> int | None:
    try:
        parsed = urllib.parse.urlparse(url)
        return parsed.port
    except ValueError:
        return None


def _schedule_duplicate_guard_daemon_retirement(guard_home: Path) -> None:
    lock_key = str(guard_home.resolve())
    with _DUPLICATE_RETIRE_SCHEDULE_LOCK:
        if _DUPLICATE_RETIRE_IN_FLIGHT:
            return
        _DUPLICATE_RETIRE_IN_FLIGHT.add(lock_key)
    retirement = _retire_current_duplicate_guard_daemons

    def retire() -> None:
        try:
            retirement(guard_home)
        except Exception:
            # A later lifecycle call can retry this best-effort cleanup.
            pass
        finally:
            with _DUPLICATE_RETIRE_SCHEDULE_LOCK:
                _DUPLICATE_RETIRE_IN_FLIGHT.discard(lock_key)

    thread = threading.Thread(
        target=retire,
        name="guard-daemon-duplicate-retirement",
        daemon=True,
    )
    try:
        thread.start()
    except RuntimeError:
        with _DUPLICATE_RETIRE_SCHEDULE_LOCK:
            _DUPLICATE_RETIRE_IN_FLIGHT.discard(lock_key)


def _retire_current_duplicate_guard_daemons(guard_home: Path) -> None:
    with _guard_daemon_start_lock(guard_home):
        current_url = load_guard_daemon_url(guard_home)
        keep_port = _guard_daemon_url_port(current_url) if current_url is not None else None
        if keep_port is None:
            return
        _retire_duplicate_guard_daemons_unlocked(guard_home, keep_port=keep_port)


def _retire_duplicate_guard_daemons_unlocked(guard_home: Path, *, keep_port: int) -> None:
    saw_duplicate = False
    for pid, port in _running_guard_daemon_processes_for_guard_home(guard_home):
        if port == keep_port:
            continue
        saw_duplicate = True
        retirement_identity = _guard_daemon_pid_identity_for_retirement(pid)
        if retirement_identity is None:
            return
        expected_start_marker, expected_owner_marker = retirement_identity
        if not _retire_guard_daemon_pid(
            pid,
            expected_guard_home=guard_home,
            expected_start_marker=expected_start_marker,
            expected_owner_marker=expected_owner_marker,
        ):
            return
    if not saw_duplicate:
        return
    if any(port != keep_port for _pid, port in _running_guard_daemon_processes_for_guard_home(guard_home)):
        return
    _rewrite_kept_daemon_state_if_missing(guard_home, keep_port=keep_port)


def _rewrite_kept_daemon_state_if_missing(guard_home: Path, *, keep_port: int) -> None:
    kept_pid = _guard_daemon_pid_for_guard_home_port(guard_home, keep_port)
    if kept_pid is None or _daemon_state_points_to(guard_home, pid=kept_pid, port=keep_port):
        return
    auth_token = load_guard_daemon_auth_token(guard_home)
    if auth_token is None:
        return
    daemon_url = f"http://127.0.0.1:{keep_port}"
    details = _daemon_healthz_details_payload(daemon_url, auth_token)
    if details is None or not _healthz_payload_matches_guard_home(json.dumps(details), guard_home):
        return
    if details.get("pid") != kept_pid:
        return
    write_guard_daemon_state(guard_home, keep_port, auth_token, pid=kept_pid, write_auth_token=False)


def _guard_daemon_pid_for_guard_home_port(guard_home: Path, port: int) -> int | None:
    for pid, candidate_port in _running_guard_daemon_processes_for_guard_home(guard_home):
        if candidate_port == port:
            return pid
    return None


def _daemon_state_executable() -> str:
    try:
        return str(Path(sys.executable).resolve(strict=True))
    except OSError:
        return sys.executable


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
    state_path = _state_path(guard_home)
    _ensure_private_directory(state_path.parent)
    with _guard_daemon_state_write_lock(guard_home):
        discovery_key = ensure_daemon_discovery_key(guard_home)
        state_pid = pid if isinstance(pid, int) and pid > 0 else os.getpid()
        state_payload: dict[str, object] = {
            "guard_home": str(guard_home.resolve()),
            "host": host,
            "port": port,
            "compatibility_version": GUARD_DAEMON_COMPATIBILITY_VERSION,
            "package_version": __version__,
            "executable": _daemon_state_executable(),
            "source_root": _current_guard_daemon_source_root(),
            "runtime_fingerprint": _current_guard_daemon_runtime_fingerprint(),
            "pid": state_pid,
            "started_at": started_at or datetime.now(timezone.utc).isoformat(),
            "state_id": state_id or secrets.token_hex(16),
            "auth_token_id": hashlib.sha256(auth_token.encode("utf-8")).hexdigest(),
        }
        process_marker = process_start_token(state_pid)
        if isinstance(process_marker, str) and process_marker:
            state_payload["process_start_marker"] = process_marker
        process_owner = process_owner_marker(state_pid)
        if isinstance(process_owner, str) and process_owner:
            state_payload["user"] = process_owner
            state_payload["owner"] = process_owner
        launch_nonce = os.environ.get(_GUARD_DAEMON_LAUNCH_NONCE_ENV)
        if _launch_nonce_is_valid(launch_nonce):
            state_payload["launch_nonce"] = launch_nonce
            state_payload["launch_generation"] = launch_nonce
            state_payload["generation"] = launch_nonce
        if os.name == "nt":
            creation_time = windows_process_creation_time(state_pid)
            if creation_time is not None:
                state_payload["process_creation_time"] = creation_time
        if trust_status is not None:
            state_payload["trust_status"] = trust_status
        daemon_state = authenticate_daemon_state(
            state_payload,
            discovery_key=discovery_key,
        )
        # ``write_auth_token=False`` never replaces another daemon's token, but
        # a missing file is restored so hooks can keep signing approval links.
        existing_token = load_guard_daemon_auth_token(guard_home)
        if write_auth_token or existing_token is None or not existing_token.strip():
            _write_private_atomic_text(_auth_token_path(guard_home), auth_token)
        _write_private_atomic_text(
            state_path,
            json.dumps(daemon_state, indent=2),
        )


def republish_guard_daemon_trust_status(guard_home: Path, trust_status: dict[str, object]) -> bool:
    """Re-sign the running daemon's state with a new ``trust_status``.

    The native daemon publishes its state once; an integrity transition a
    replay commits updates that state in place so passive trust readers see
    it. Every other field, the state id included, is kept.
    """

    state_path = _state_path(guard_home)
    with _guard_daemon_state_write_lock(guard_home):
        current = load_authenticated_daemon_state(guard_home)
        discovery_key = load_daemon_discovery_key(guard_home)
        if current is None or discovery_key is None:
            return False
        payload = {
            field: value
            for field, value in current.items()
            if field not in {"discovery_protocol_version", "discovery_key_id", "state_signature"}
        }
        payload["trust_status"] = dict(trust_status)
        _write_private_atomic_text(
            state_path,
            json.dumps(authenticate_daemon_state(payload, discovery_key=discovery_key), indent=2),
        )
    return True


def clear_guard_daemon_state(guard_home: Path) -> None:
    state_path = _state_path(guard_home)
    _ensure_private_directory(state_path.parent)
    with _guard_daemon_state_write_lock(guard_home):
        _write_private_atomic_text(state_path, "{}")


def _clear_guard_daemon_state_if_current_unlocked(guard_home: Path, *, pid: int, port: int) -> bool:
    payload = _load_state(guard_home)
    if not isinstance(payload, dict):
        return False
    if payload.get("pid") != pid or payload.get("port") != port:
        return False
    clear_guard_daemon_state(guard_home)
    return True


def _clear_authenticated_guard_daemon_state_if_current(
    guard_home: Path,
    *,
    expected_state: dict[str, object],
) -> bool:
    """Tombstone only the exact signed state snapshot that was classified."""

    with _guard_daemon_state_write_lock(guard_home):
        current_state = load_authenticated_daemon_state(guard_home)
        if current_state != expected_state:
            return False
        _write_private_atomic_text(_state_path(guard_home), "{}")
        return True


def _daemon_state_points_to(guard_home: Path, *, pid: int, port: int) -> bool:
    payload = _load_state(guard_home)
    return isinstance(payload, dict) and payload.get("pid") == pid and payload.get("port") == port


def repair_approval_center_locator(guard_home: Path) -> dict[str, object]:
    """Repair stale locator and authenticated daemon-discovery state.

    A healthy live daemon is preserved. A live daemon with an invalid identity
    bundle is retired before its state is cleared, and an invalid discovery
    file is removed so the next daemon start can regenerate it. Raises
    RuntimeError when the repair cannot finish safely.
    """

    answer = _daemon_manage("repair_locator", guard_home)
    if answer is None:
        raise RuntimeError("Guard could not repair the daemon locator: the native runtime did not answer.")
    error = answer.get("error")
    if error is not None or answer.get("repaired") is not True:
        raise RuntimeError(f"Guard daemon locator repair stopped safely: {error}.")
    cleared = answer.get("cleared")
    return {"repaired": True, "cleared": list(cleared) if isinstance(cleared, list) else []}


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
    fields = ("pid", "daemon_url", "approval_url_base", "started_at", "state_path", "guard_home")
    shape = _lifecycle("locator_shape", {"payload": _native_fields(payload, fields)}, home=guard_home)
    if not shape["valid"]:
        return None
    pid = int(shape["pid"])
    daemon_url = cast("str", payload["daemon_url"])
    if not _guard_daemon_pid_matches_command(pid, expected_guard_home=guard_home):
        state = load_authenticated_daemon_state(guard_home)
        binding = {
            "state": None if not isinstance(state, dict) else _native_fields(state, ("pid", "port")),
            "pid": pid,
            "daemon_url": daemon_url,
        }
        if not _lifecycle("locator_binding", binding, home=guard_home)["bound"]:
            return None
    return ApprovalCenterLocator(
        guard_home=Path(cast("str", payload["guard_home"])),
        daemon_url=daemon_url,
        approval_url_base=cast("str", payload["approval_url_base"]),
        pid=pid,
        started_at=cast("str", payload["started_at"]),
        state_path=Path(cast("str", payload["state_path"])),
    )


def _daemon_identity_matches_locator(
    guard_home: Path,
    *,
    pid: int,
    daemon_url: str,
) -> bool:
    if not _guard_daemon_pid_is_running(pid):
        return False
    if _guard_daemon_pid_matches_command(pid, expected_guard_home=guard_home):
        return True
    auth_token = load_guard_daemon_auth_token(guard_home)
    if auth_token is None:
        return False
    details = _daemon_healthz_details_payload(daemon_url, auth_token)
    return bool(
        isinstance(details, dict)
        and details.get("pid") == pid
        and _healthz_payload_matches_guard_home(json.dumps(details), guard_home)
        and _daemon_healthz_details_match_current_runtime(details)
    )


def publish_approval_center_locator(
    guard_home: Path,
    daemon_url: str,
) -> ApprovalCenterLocator:
    """Publish browser discovery for an already authenticated live daemon."""

    state = load_authenticated_daemon_state(guard_home)
    if not isinstance(state, dict):
        raise RuntimeError("Guard daemon identity is unavailable.")
    pid = state.get("pid")
    port = state.get("port")
    if (
        not isinstance(pid, int)
        or pid <= 0
        or not isinstance(port, int)
        or daemon_url != f"http://127.0.0.1:{port}"
        or not _daemon_identity_matches_locator(guard_home, pid=pid, daemon_url=daemon_url)
    ):
        raise RuntimeError("Guard daemon identity does not match the active local service.")
    started_at = state.get("started_at")
    if not isinstance(started_at, str) or not started_at:
        started_at = datetime.now(tz=timezone.utc).isoformat()
    locator = ApprovalCenterLocator(
        guard_home=guard_home,
        daemon_url=daemon_url,
        approval_url_base=daemon_url,
        pid=pid,
        started_at=started_at,
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
    shape = _native_fields(payload, ("compatibility_version", "source_root", "runtime_fingerprint", "guard_home"))
    query = {"payload": shape, "guard_home": str(guard_home)}
    # Pure verdict. Binding it to the stale home would start a resident there,
    # and that failure would skip retirement of every other ephemeral daemon.
    return bool(_lifecycle("state_shape", query)["result"])


def _state_path(guard_home: Path) -> Path:
    return guard_home / "daemon-state.json"


def _daemon_lifecycle_artifact_is_exact_tombstone(path: Path) -> bool:
    if not _daemon_lifecycle_artifact_is_quarantinable(path):
        return False
    try:
        before = path.stat(follow_symlinks=False)
        if before.st_size != 2:
            return False
        with path.open("rb") as handle:
            raw = handle.read(3)
            opened = os.fstat(handle.fileno())
        after = path.stat(follow_symlinks=False)
    except OSError:
        return False
    identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    identity_opened = (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
    identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    return raw == b"{}" and identity_before == identity_opened == identity_after


def _daemon_lifecycle_artifact_is_quarantinable(path: Path) -> bool:
    try:
        parent_metadata = path.parent.lstat()
        metadata = path.lstat()
    except OSError:
        return False
    if not stat.S_ISDIR(parent_metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        return False
    if not stat.S_ISREG(metadata.st_mode):
        return False
    if os.name == "nt":
        return True
    return (
        parent_metadata.st_uid == os.getuid()
        and metadata.st_uid == os.getuid()
        and not stat.S_IMODE(parent_metadata.st_mode) & 0o077
    )


def _pending_launch_path(guard_home: Path) -> Path:
    return guard_home / _GUARD_DAEMON_PENDING_LAUNCH_FILE


def _guard_daemon_pending_launch_is_generation_bound(pending: dict[str, object] | None) -> bool:
    return (
        isinstance(pending, dict)
        and _launch_nonce_is_valid(pending.get("launch_nonce"))
        and pending.get("launch_generation") == pending.get("launch_nonce")
        and pending.get("generation") == pending.get("launch_nonce")
    )


def load_authenticated_guard_daemon_pending_launch(guard_home: Path) -> dict[str, object] | None:
    """Load one signed pending-launch identity from a private regular file."""
    raw_payload = read_private_regular_text(
        _pending_launch_path(guard_home),
        max_bytes=_GUARD_DAEMON_PENDING_LAUNCH_MAX_BYTES,
        require_private_parent=True,
    )
    if raw_payload is None:
        return None
    try:
        payload = json.loads(raw_payload)
    except json.JSONDecodeError:
        return None
    discovery_key = load_daemon_discovery_key(guard_home)
    if (
        discovery_key is None
        or not isinstance(payload, dict)
        or not verify_daemon_state(payload, discovery_key=discovery_key)
        or payload.get("state_kind") != "daemon_launch_pending"
    ):
        return None
    pid = payload.get("pid")
    port = payload.get("port")
    creation_time = payload.get("process_creation_time")
    payload_guard_home = payload.get("guard_home")
    if (
        type(pid) is not int
        or pid <= 0
        or type(port) is not int
        or not 0 < port <= 65535
        or not isinstance(payload_guard_home, str)
    ):
        return None
    if os.name == "nt" and (type(creation_time) is not int or creation_time <= 0):
        return None
    launch_nonce = payload.get("launch_nonce")
    launch_generation = payload.get("launch_generation")
    process_marker = payload.get("process_start_marker")
    process_owner = payload.get("owner", payload.get("user"))
    runtime_fingerprint = payload.get("runtime_fingerprint")
    if os.name != "nt" and (
        not _launch_nonce_is_valid(launch_nonce)
        or launch_generation != launch_nonce
        or payload.get("generation") != launch_nonce
        or not isinstance(process_marker, str)
        or not process_marker
        or not isinstance(process_owner, str)
        or not process_owner
        or not isinstance(runtime_fingerprint, str)
        or not runtime_fingerprint
    ):
        return None
    try:
        if Path(payload_guard_home).resolve() != guard_home.resolve():
            return None
    except OSError:
        return None
    return payload


def _clear_guard_daemon_pending_launch_if_current(
    guard_home: Path,
    *,
    pid: int,
    creation_time: int | None,
    launch_nonce: str | None = None,
    process_start_marker: str | None = None,
) -> bool:
    with _guard_daemon_state_write_lock(guard_home):
        pending = load_authenticated_guard_daemon_pending_launch(guard_home)
        if pending is None:
            return not _pending_launch_path(guard_home).is_file()
        if pending.get("pid") != pid:
            return False
        if os.name == "nt" and pending.get("process_creation_time") != creation_time:
            return False
        if launch_nonce is not None and not secrets.compare_digest(str(pending.get("launch_nonce", "")), launch_nonce):
            return False
        if process_start_marker is not None and not secrets.compare_digest(
            str(pending.get("process_start_marker", "")), process_start_marker
        ):
            return False
        _write_private_atomic_text(_pending_launch_path(guard_home), "{}")
        return True


def _start_progress_path(guard_home: Path) -> Path:
    return guard_home / _GUARD_DAEMON_START_PROGRESS_FILE


class GuardDaemonStartProgress(TypedDict):
    state_kind: str
    guard_home: str
    pid: int
    port: int
    process_start_token: str
    recorded_at_ns: int
    spawned_at_ns: int


def load_authenticated_guard_daemon_start_progress(guard_home: Path) -> GuardDaemonStartProgress | None:
    """Load one signed still-starting record from a private regular file."""

    raw_payload = read_private_regular_text(
        _start_progress_path(guard_home),
        max_bytes=_GUARD_DAEMON_START_PROGRESS_MAX_BYTES,
        require_private_parent=True,
    )
    if raw_payload is None:
        return None
    try:
        payload = json.loads(raw_payload)
    except json.JSONDecodeError:
        return None
    discovery_key = load_daemon_discovery_key(guard_home)
    if (
        discovery_key is None
        or not isinstance(payload, dict)
        or not verify_daemon_state(payload, discovery_key=discovery_key)
        or payload.get("state_kind") != "daemon_start_progress"
    ):
        return None
    pid = payload.get("pid")
    port = payload.get("port")
    recorded_at_ns = payload.get("recorded_at_ns")
    spawned_at_ns = payload.get("spawned_at_ns")
    start_token = payload.get("process_start_token")
    payload_guard_home = payload.get("guard_home")
    if (
        type(pid) is not int
        or pid <= 0
        or type(port) is not int
        or not 0 < port <= 65535
        or type(recorded_at_ns) is not int
        or recorded_at_ns <= 0
        or type(spawned_at_ns) is not int
        or spawned_at_ns <= 0
        or not isinstance(start_token, str)
        or not start_token
        or not isinstance(payload_guard_home, str)
    ):
        return None
    try:
        if Path(payload_guard_home).resolve() != guard_home.resolve():
            return None
    except OSError:
        return None
    return cast(GuardDaemonStartProgress, cast(object, payload))


def _resolve_abandoned_guard_daemon_pending_launch(guard_home: Path, pending: dict[str, object] | None) -> bool:
    """Tombstone a launch that handed off, or whose root is gone with no daemon left.

    Only a matching handoff resolves a launch that may still publish. A launch
    that timed out or crashed before its handoff never publishes one, so its
    receipt would otherwise refuse every later daemon start for this home, and
    every later Guard core with it. Once the root process is gone and a proven
    inventory finds no daemon for this home, nothing of that launch can still
    answer for it. A helper it moved into its own session cannot be found from
    here either way: keeping the receipt would not stop that helper, only Guard.
    The clear below rereads the receipt under the state lock and only removes
    the same launch.
    """

    if resolve_handed_off_guard_daemon_pending_launch(guard_home, pending):
        return True
    if pending is None or not _guard_daemon_pending_launch_is_abandoned(pending):
        return False
    if _guard_daemon_process_inventory_for_guard_home(guard_home) != []:
        return False
    pid = pending["pid"]
    creation_time = pending.get("process_creation_time")
    assert type(pid) is int
    return _clear_guard_daemon_pending_launch_if_current(
        guard_home,
        pid=pid,
        creation_time=creation_time if type(creation_time) is int else None,
        launch_nonce=str(pending["launch_nonce"]),
        process_start_marker=str(pending["process_start_marker"]),
    )


def _guard_daemon_pending_launch_is_abandoned(pending: dict[str, object] | None) -> bool:
    """Whether a generation-bound launch's root process is gone."""

    if not _guard_daemon_pending_launch_is_generation_bound(pending):
        return False
    assert pending is not None
    pid = pending.get("pid")
    marker = pending.get("process_start_marker")
    if type(pid) is not int or pid <= 0 or not isinstance(marker, str) or not marker:
        return False
    return _guard_daemon_pending_launch_root_is_gone(
        pid, marker=marker, creation_time=pending.get("process_creation_time")
    )


def _guard_daemon_pending_launch_root_is_gone(pid: int, *, marker: str, creation_time: object) -> bool:
    if _guard_daemon_pid_is_proven_dead(pid):
        return True
    # A live pid that started at another moment is a reused pid, not the launch.
    if os.name == "nt":
        actual_creation_time = windows_process_creation_time(pid)
        return type(creation_time) is int and actual_creation_time is not None and actual_creation_time != creation_time
    actual_marker = process_start_token(pid)
    return isinstance(actual_marker, str) and bool(actual_marker) and actual_marker != marker


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


def _write_private_atomic_text(path: Path, text: str) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        if os.name != "nt" and hasattr(os, "fchmod"):
            os.fchmod(descriptor, _GUARD_DAEMON_PRIVATE_FILE_MODE)
        with os.fdopen(descriptor, "w", encoding="utf-8", closefd=False) as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.close(descriptor)
        descriptor = -1
        replace_file(temporary_path, path)
        _set_private_mode(path, _GUARD_DAEMON_PRIVATE_FILE_MODE)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        with suppress(OSError):
            temporary_path.unlink()


def _set_private_mode(path: Path, mode: int) -> None:
    if os.name == "nt":
        if path.is_dir():
            _set_windows_private_directory(path)
        return
    try:
        os.chmod(path, mode)
    except OSError:
        return


def _set_windows_private_directory(path: Path) -> None:
    from ..native_policy_snapshot import NativePolicySnapshotError
    from ..native_policy_snapshot_windows_atomic import _windows_ensure_private_directory

    try:
        _windows_ensure_private_directory(path)
    except (NativePolicySnapshotError, OSError, RuntimeError, TypeError, ValueError) as exc:
        _LOGGER.warning("Could not make a Windows daemon directory private: %s", type(exc).__name__)


def _guard_home_is_ephemeral(guard_home: Path) -> bool:
    return bool(_lifecycle("ephemeral_home", {"guard_home": str(guard_home)})["ephemeral"])


def _runtime_state_age_seconds(guard_home: Path) -> float | None:
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
        heartbeat = datetime.fromisoformat(last_heartbeat_at)
    except ValueError:
        return None
    if heartbeat.tzinfo is None:
        heartbeat = heartbeat.replace(tzinfo=timezone.utc)
    return max(0.0, (datetime.now(timezone.utc) - heartbeat).total_seconds())


def _guard_home_from_command_parts(parts: list[str]) -> Path | None:
    home = _lifecycle("inspect_parts", {"parts": list(parts)})["guard_home"]
    return None if home is None else Path(home)


def _implicit_daemon_guard_home() -> Path:
    from ..config import resolve_guard_home

    return resolve_guard_home(None)


def _split_process_command(command: str) -> list[str] | None:
    return cast("list[str] | None", _lifecycle("split_command", {"command": command})["parts"])


def _guard_daemon_command_parts_match(parts: list[str]) -> bool:
    return bool(_lifecycle("inspect_parts", {"parts": list(parts)})["matches"])


def _guard_daemon_process_inventory_for_guard_home(
    guard_home: Path,
) -> list[tuple[int, int]] | None:
    """Return a proven process inventory, or ``None`` when enumeration is unknown."""

    output: str | None = None
    entries: list[tuple[int, str]] | None = None
    if os.name == "nt":
        candidate_names = {
            "hol-guard.exe",
            "plugin-guard.exe",
            "py.exe",
            "python.exe",
            "python3.exe",
            "pythonw.exe",
        }
        executable_name = ntpath.basename(sys.executable).strip().lower()
        if executable_name:
            candidate_names.add(executable_name)
        with timed_phase("process_inventory_enumerate"):
            entries = windows_processes.windows_process_command_line_inventory(
                candidate_executable_names=frozenset(candidate_names),
                max_command_line_bytes=_GUARD_DAEMON_PROCESS_QUERY_OUTPUT_LIMIT_BYTES,
            )
        if entries is None:
            return None
    else:
        inventory = posix_processes.posix_process_inventory()
        if inventory is None:
            return None
        if isinstance(inventory, str):
            output = inventory
        else:
            entries = inventory

    query: dict[str, object] = {
        "guard_home": str(guard_home),
        "implicit_home": str(_implicit_daemon_guard_home()),
        "own_pid": os.getpid(),
        "parent_pid": os.getppid(),
        "frozen_runtime": bool(getattr(sys, "frozen", False)),
    }
    if output is not None:
        query["ps_output"] = output
    else:
        query["entries"] = [[pid, command_line] for pid, command_line in entries or []]
    with timed_phase("process_inventory_verdict"):
        verdict = _lifecycle("process_inventory", query, home=guard_home, facts_home=guard_home)
    if not verdict["known"]:
        return None
    return [(int(pid), int(port)) for pid, port in verdict["processes"]]


def _running_guard_daemon_processes_for_guard_home(guard_home: Path) -> list[tuple[int, int]]:
    inventory = _guard_daemon_process_inventory_for_guard_home(guard_home)
    return inventory if inventory is not None else []


def _guard_daemon_state_matches_current_runtime(payload: dict[str, object]) -> bool:
    from .runtime_peer import daemon_state_matches_current_runtime

    return daemon_state_matches_current_runtime(payload)


def _current_guard_daemon_source_root() -> str:
    return str(Path(__file__).resolve().parents[3])


def _measure_runtime_fingerprint(source_root: Path, cache_dir: Path | None) -> tuple[str, str, bool]:
    """The native runtime's (tree signature, fingerprint, reused) for `source_root`.

    `runtime_fingerprint.rs` walks the tree and hashes it. Given `cache_dir`
    it also reads and rewrites the private cache file there, so a tree whose
    signature still matches comes back without reading a file.
    """

    from ..mdm.runtime_request import runtime_answer

    request: dict[str, object] = {
        "schema": "runtime-fingerprint.v1",
        "source_root": str(source_root),
        "version": __version__,
    }
    if cache_dir is not None:
        request["cache_dir"] = str(cache_dir)

    def ask() -> dict[str, object] | None:
        return runtime_answer(
            "native-runtime-fingerprint-v1",
            "runtime-fingerprint",
            request,
            output_limit=4096,
            timeout_seconds=60.0,
        )

    answer = ask()
    # A freshly installed runtime can miss its first capability probe; wait
    # that out once rather than failing the daemon start.
    if answer is None and await_native_runtime(60.0) > 0.0:
        answer = ask()
    tree_sig = None if answer is None else answer.get("tree_sig")
    fingerprint = None if answer is None else answer.get("fingerprint")
    reused = None if answer is None else answer.get("reused")
    if (
        not isinstance(tree_sig, str)
        or not isinstance(fingerprint, str)
        or not _is_sha256_hex(fingerprint)
        or type(reused) is not bool
    ):
        raise RuntimeError("Guard daemon runtime identity requires the native runtime.")
    return tree_sig, fingerprint, reused


def _runtime_fingerprint_cache_dir() -> Path:
    return Path.home() / ".hol-guard" / "runtime-fingerprint-cache"


def _is_sha256_hex(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == _RUNTIME_FINGERPRINT_HEX_LENGTH
        and not set(value) - set("0123456789abcdef")
    )


def _current_guard_daemon_runtime_fingerprint() -> str:
    global _runtime_fingerprint_cache
    if _runtime_fingerprint_cache is not None:
        return _runtime_fingerprint_cache[1]
    source_root = Path(_current_guard_daemon_source_root())
    tree_sig, fingerprint, _reused = _measure_runtime_fingerprint(source_root, _runtime_fingerprint_cache_dir())
    _runtime_fingerprint_cache = (tree_sig, fingerprint)
    return fingerprint


def current_guard_daemon_runtime_fingerprint() -> str:
    """Return the installed runtime identity used for daemon compatibility."""

    return _current_guard_daemon_runtime_fingerprint()


def _guard_daemon_start_in_progress(guard_home: Path) -> bool:
    payload = _load_state(guard_home)
    if not isinstance(payload, dict) or not _guard_daemon_state_matches_current_runtime(payload):
        return False
    pid = payload.get("pid")
    return isinstance(pid, int) and pid > 0 and _guard_daemon_pid_is_running(pid)


def _guard_daemon_pid_is_running(pid: int) -> bool:
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


def _guard_daemon_parent_pid(pid: int) -> int | None:
    """Return the parent PID for a live process, or ``None`` when it cannot be proven."""

    return posix_processes.posix_parent_pid(pid)


def _guard_daemon_pid_is_spawned_launch(pid: int, expected_pid: int) -> bool:
    """Match the launched handle, including a PyInstaller one-file child."""

    if expected_pid <= 0:
        return False
    if pid == expected_pid:
        return True
    if not _guard_daemon_pid_is_running(expected_pid):
        return False
    if os.name == "nt":
        # Windows does not prove a parent pid. The onefile bootloader that
        # Desktop spawned and the daemon child that published state share one
        # serve command for this home and port. That is the same attribution
        # that keeps the child as still starting, so the first wait can adopt it.
        # An older process is a previous daemon, not this child. A lifecycle
        # miss is inconclusive for this poll and must not abort startup.
        spawned_created = windows_process_creation_time(expected_pid)
        candidate_created = windows_process_creation_time(pid)
        if (
            isinstance(spawned_created, int)
            and isinstance(candidate_created, int)
            and candidate_created < spawned_created
        ):
            return False
        from .start_classification import _pid_in_process_tree

        token = bind_daemon_lifecycle_deadline(time.monotonic() + _SPAWNED_URL_POLL_LIFECYCLE_SECONDS)
        try:
            return _pid_in_process_tree(pid, expected_pid)
        except (NativeDaemonLifecycleError, TimeoutError):
            return False
        finally:
            reset_daemon_lifecycle_deadline(token)
    return _guard_daemon_parent_pid(pid) == expected_pid


def _guard_daemon_pid_is_proven_dead(pid: int) -> bool:
    if os.name == "nt":
        return windows_process_liveness(pid) is False
    if _guard_daemon_child_has_exited(pid):
        return True
    return not _guard_daemon_pid_is_running(pid)


def _guard_daemon_child_has_exited(pid: int) -> bool:
    """Observe an exited child without consuming its owner's process status."""
    required = ("waitid", "P_PID", "WEXITED", "WNOHANG", "WNOWAIT", "CLD_EXITED", "CLD_KILLED", "CLD_DUMPED")
    if pid <= 0 or not all(hasattr(os, name) for name in required):
        if pid > 0 and sys.platform == "darwin":
            from ..runtime_transition_native_capture import darwin_child_has_exited

            return darwin_child_has_exited(pid)
        return False
    try:
        result = os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    except (OSError, ValueError, OverflowError):
        # Non-children and unsupported platforms retain the existing liveness proof.
        return False
    return (
        result is not None and result.si_pid == pid and result.si_code in (os.CLD_EXITED, os.CLD_KILLED, os.CLD_DUMPED)
    )


def _wait_for_guard_daemon_pid_death(pid: int, *, timeout: float = 1.0) -> bool:
    deadline = time.monotonic() + max(0.0, timeout)
    while time.monotonic() < deadline:
        if _guard_daemon_pid_is_proven_dead(pid):
            return True
        time.sleep(min(GUARD_DAEMON_POLL_INTERVAL_SECONDS, max(0.0, deadline - time.monotonic())))
    return _guard_daemon_pid_is_proven_dead(pid)


def _guard_daemon_pid_matches_command(pid: int, expected_guard_home: Path | None = None) -> bool:
    return _guard_daemon_pid_command_identity(pid, expected_guard_home=expected_guard_home) is True


def _guard_daemon_pid_command_identity(
    pid: int,
    *,
    expected_guard_home: Path | None = None,
) -> bool | None:
    """Classify a PID as the expected daemon, another process, or unresolvable."""

    command = _guard_daemon_command_for_pid(pid)
    if command is None:
        return None
    query = {
        "command": command,
        "expected_home": None if expected_guard_home is None else str(expected_guard_home),
        "implicit_home": str(_implicit_daemon_guard_home()),
    }
    return cast("bool | None", _lifecycle("command_identity", query, home=expected_guard_home)["identity"])


def _guard_daemon_command_for_pid(pid: int) -> str | None:
    if os.name == "nt":
        return windows_processes.windows_process_command_line(
            pid,
            max_command_line_bytes=_GUARD_DAEMON_PROCESS_QUERY_OUTPUT_LIMIT_BYTES,
        )
    return posix_processes.posix_process_command(pid)


def _guard_daemon_pid_identity_for_retirement(pid: int) -> tuple[str, str] | None:
    """Capture an exact process generation and OS owner before inventory signals."""

    start_marker = process_start_token(pid)
    owner_marker = process_owner_marker(pid)
    current_owner_marker = process_owner_marker(os.getpid())
    if (
        not isinstance(start_marker, str)
        or not start_marker
        or not isinstance(owner_marker, str)
        or not owner_marker
        or not isinstance(current_owner_marker, str)
        or not current_owner_marker
    ):
        return None
    try:
        if not secrets.compare_digest(owner_marker, current_owner_marker):
            return None
    except TypeError:
        return None
    return start_marker, owner_marker


def process_start_token(pid: int, *, deadline_monotonic: float | None = None) -> str | None:
    """Resolve the live process generation marker through the identity module at call time."""

    resolve = _live_process_identity.process_start_token
    if deadline_monotonic is None:
        return resolve(pid)
    return resolve(pid, deadline_monotonic=deadline_monotonic)


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
    # The start token is the same identity as the start marker; a caller may supply either.
    start_marker = expected_start_marker if expected_start_marker is not None else expected_start_token
    retirement_deadline = None if timeout is None else time.monotonic() + max(0.0, timeout)
    if deadline_monotonic is not None:
        retirement_deadline = (
            deadline_monotonic if retirement_deadline is None else min(retirement_deadline, deadline_monotonic)
        )

    def start_marker_matches() -> bool:
        if start_marker is None:
            return True
        actual_start_marker = (
            process_start_token(pid)
            if deadline_monotonic is None
            else process_start_token(pid, deadline_monotonic=deadline_monotonic)
        )
        return isinstance(actual_start_marker, str) and secrets.compare_digest(
            actual_start_marker,
            start_marker,
        )

    def owner_marker_matches() -> bool:
        owner_marker = expected_owner_marker
        if not isinstance(owner_marker, str) or not owner_marker:
            owner_marker = process_owner_marker(os.getpid())
        actual_owner_marker = process_owner_marker(pid)
        if not (
            isinstance(owner_marker, str)
            and bool(owner_marker)
            and isinstance(actual_owner_marker, str)
            and bool(actual_owner_marker)
        ):
            return False
        try:
            return secrets.compare_digest(actual_owner_marker, owner_marker)
        except TypeError:
            return False

    def wait_for_death() -> bool:
        if retirement_deadline is None:
            return _wait_for_guard_daemon_pid_death(pid)
        remaining = max(0.0, retirement_deadline - time.monotonic())
        return _wait_for_guard_daemon_pid_death(pid, timeout=min(1.0, remaining) if deadline_monotonic else remaining)

    def terminate_exact(creation_time: int) -> bool:
        if not start_marker_matches() or not owner_marker_matches():
            return False
        if retirement_deadline is None:
            return windows_terminate_process_if_creation_time(pid, creation_time)
        return windows_terminate_process_if_creation_time(
            pid,
            creation_time,
            timeout=max(0.0, retirement_deadline - time.monotonic()),
        )

    if _guard_daemon_pid_is_proven_dead(pid):
        return True
    if retirement_deadline is not None and time.monotonic() >= retirement_deadline:
        return False
    if os.name != "nt" and (not isinstance(start_marker, str) or not start_marker):
        return False
    # Admit the exact process generation before any further probing; it is
    # re-verified immediately before each signal below.
    if not start_marker_matches():
        return False
    if os.name == "nt" and expected_creation_time is not None:
        return terminate_exact(expected_creation_time)
    observed_creation_time: int | None = None
    if os.name == "nt":
        observed_creation_time = windows_process_creation_time(pid)
        if observed_creation_time is None:
            return False
    if not _guard_daemon_pid_matches_command(pid, expected_guard_home):
        identity = _guard_daemon_pid_command_identity(pid, expected_guard_home=expected_guard_home)
        # The pid is running a different command — not our daemon.
        # There is nothing to kill; return True so the caller clears
        # stale daemon-state.json instead of revisiting it forever.  An
        # unresolvable command fails closed instead of being treated as foreign.
        return identity is False
    if os.name == "nt":
        assert observed_creation_time is not None
        return terminate_exact(observed_creation_time)
    if retirement_deadline is not None and time.monotonic() >= retirement_deadline:
        return _guard_daemon_pid_is_proven_dead(pid)
    if not start_marker_matches() or not owner_marker_matches():
        return False
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return True
    except OSError:
        return _guard_daemon_pid_is_proven_dead(pid)
    if wait_for_death():
        return True
    if retirement_deadline is not None and time.monotonic() >= retirement_deadline:
        return _guard_daemon_pid_is_proven_dead(pid)
    if not start_marker_matches() or not owner_marker_matches():
        return False
    sigkill = getattr(signal, "SIGKILL", None)
    if sigkill is None:
        return False
    try:
        os.kill(pid, sigkill)
    except ProcessLookupError:
        return True
    except OSError:
        return _guard_daemon_pid_is_proven_dead(pid)
    return wait_for_death()


def _guard_daemon_handoff_matches_launch(
    guard_home: Path,
    *,
    launch_nonce: str,
    expected_pid: int,
    expected_port: int | None = None,
    require_same_runtime: bool = True,
) -> bool:
    """Accept a startup endpoint only when its signed state binds this launch.

    A launch of this process's own runtime must also publish this runtime's
    fingerprint. A launch of another executable, such as an updated Desktop
    Core, runs different bytes by design; the nonce, process ancestry, start
    markers and owner still bind it to this launch.
    """

    if not _launch_nonce_is_valid(launch_nonce) or expected_pid <= 0:
        return False
    pending = load_authenticated_guard_daemon_pending_launch(guard_home)
    identity = _load_authenticated_daemon_identity(guard_home)
    if pending is None or identity is None:
        return False
    state, _auth_token = identity
    expected_home = str(guard_home.resolve())
    if (
        pending.get("guard_home") != expected_home
        or state.get("guard_home") != expected_home
        or pending.get("launch_nonce") != launch_nonce
        or pending.get("launch_generation") != launch_nonce
        or pending.get("generation") != launch_nonce
        or state.get("launch_nonce") != launch_nonce
        or state.get("launch_generation") != launch_nonce
        or state.get("generation") != launch_nonce
        or pending.get("pid") != expected_pid
        or pending.get("port") != state.get("port")
        or (expected_port is not None and state.get("port") != expected_port)
        or (require_same_runtime and pending.get("runtime_fingerprint") != state.get("runtime_fingerprint"))
        or pending.get("owner", pending.get("user")) != state.get("owner", state.get("user"))
    ):
        return False
    if os.name == "nt" and pending.get("process_creation_time") != state.get("process_creation_time"):
        return False
    pending_marker = pending.get("process_start_marker")
    pending_owner = pending.get("owner", pending.get("user"))
    state_pid = state.get("pid")
    state_marker = state.get("process_start_marker")
    state_owner = state.get("owner", state.get("user"))
    if (
        not isinstance(pending_marker, str)
        or not pending_marker
        or not isinstance(pending_owner, str)
        or not pending_owner
        or not isinstance(state_pid, int)
        or state_pid <= 0
        or not isinstance(state_marker, str)
        or not state_marker
        or not isinstance(state_owner, str)
        or state_owner != pending_owner
    ):
        return False
    if process_start_token(expected_pid) != pending_marker or process_owner_marker(expected_pid) != pending_owner:
        return False
    if process_start_token(state_pid) != state_marker or process_owner_marker(state_pid) != state_owner:
        return False
    return state_pid == expected_pid or _guard_daemon_pid_is_spawned_launch(state_pid, expected_pid)


@contextmanager
def _guard_daemon_recovery_lock(guard_home: Path, *, timeout_seconds: float | None = None):
    """Serialize a complete daemon recovery transaction for one Guard home."""

    lock_key = str(guard_home.resolve())
    with _RECOVERY_LOCKS_GUARD:
        thread_lock = _RECOVERY_LOCKS.setdefault(lock_key, threading.Lock())
    deadline = None if timeout_seconds is None else time.monotonic() + max(0.0, timeout_seconds)
    if timeout_seconds is None:
        acquired_thread_lock = thread_lock.acquire()
    else:
        assert deadline is not None
        acquired_thread_lock = thread_lock.acquire(timeout=max(0.0, deadline - time.monotonic()))
    if not acquired_thread_lock:
        raise RuntimeError("Timed out waiting for Guard daemon recovery ownership.")
    file_locked = False
    try:
        lock_path = guard_home / _GUARD_DAEMON_RECOVERY_LOCK_FILE
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        with lock_path.open("a+b") as handle:
            if timeout_seconds is None:
                _lock_daemon_start_file(handle)
                file_locked = True
            else:
                assert deadline is not None
                while True:
                    if _try_lock_daemon_file(handle):
                        file_locked = True
                        break
                    remaining = deadline - time.monotonic()
                    if remaining <= 0.0:
                        break
                    time.sleep(
                        min(
                            GUARD_DAEMON_POLL_INTERVAL_SECONDS,
                            remaining,
                        )
                    )
                if not file_locked:
                    raise RuntimeError("Timed out waiting for Guard daemon recovery ownership.")
            try:
                yield
            finally:
                if file_locked:
                    _unlock_daemon_start_file(handle)
    finally:
        thread_lock.release()


def _same_daemon_invocation(left: str, right: str) -> bool:
    """Return whether two command lines are the same Guard daemon serve invocation."""

    return bool(_lifecycle("same_invocation", {"left": left, "right": right})["same"])


@contextmanager
def _guard_daemon_state_write_lock(guard_home: Path):
    """Serialize the token/state generation across threads and processes."""

    lock_key = str(guard_home.resolve())
    with _STATE_WRITE_LOCKS_GUARD:
        thread_lock = _STATE_WRITE_LOCKS.setdefault(lock_key, threading.Lock())
    with thread_lock:
        lock_path = guard_home / "daemon-state-write.lock"
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        with lock_path.open("a+b") as handle:
            _lock_daemon_start_file(handle)
            try:
                yield
            finally:
                _unlock_daemon_start_file(handle)


_unlock_daemon_start_file = release_file_lock


def _configured_port(guard_home: Path) -> int | None:
    query = {"env_port": os.environ.get("GUARD_DAEMON_PORT"), "guard_home": str(guard_home)}
    return cast("int | None", _lifecycle("configured_port", query, home=guard_home)["port"])


def _healthz_payload_is_current(raw_payload: str) -> bool:
    verdict = _lifecycle("healthz_current", {"raw_payload": raw_payload})
    if not verdict["valid_json"]:
        raise json.JSONDecodeError("invalid daemon health payload", raw_payload, 0)
    return bool(verdict["result"])


def _healthz_payload_matches_guard_home(raw_payload: str, guard_home: Path) -> bool:
    query = {"raw_payload": raw_payload, "guard_home": str(guard_home)}
    verdict = _lifecycle("healthz_home", query, home=guard_home)
    if not verdict["valid_json"]:
        raise json.JSONDecodeError("invalid daemon health payload", raw_payload, 0)
    return bool(verdict["result"])


# Re-exported so ``manager`` stays the single patch surface; the janitor module
# resolves every collaborator through ``manager`` at call time.
from .manager_ephemeral_reap import (  # noqa: E402, F401
    _collect_daemon_state_paths,
    _ephemeral_guard_daemon_state_paths,
    _ephemeral_guard_home_is_inactive,
    _path_name_looks_like_pytest_temp_root,
    _pytest_temp_roots,
    _reap_one_stale_ephemeral_state_file,
    _reap_stale_ephemeral_guard_daemons,
    _running_ephemeral_guard_daemon_processes,
    _schedule_stale_ephemeral_guard_daemon_reap,
    _state_path_age_seconds,
)
