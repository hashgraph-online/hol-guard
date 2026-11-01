"""Guard daemon lifecycle helpers."""

from __future__ import annotations

import dataclasses
import hashlib
import json
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
from functools import partial
from pathlib import Path
from typing import Any, BinaryIO, Literal, TypedDict, cast

from ...version import __version__
from .. import live_process_identity as _live_process_identity
from .. import windows_processes
from ..fork_safety import forget_in_child
from ..frozen_runtime_commands import (
    decode_frozen_daemon_serve_payload,
    frozen_daemon_serve_command,
)
from ..live_process_identity import process_owner_marker
from ..mdm.file_lock import release_file_lock
from ..native_daemon_lifecycle import (
    NativeDaemonLifecycleError,
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
    daemon_discovery_key_path,
    ensure_daemon_discovery_key,
    load_authenticated_daemon_state,
    load_daemon_discovery_key,
    verify_daemon_state,
)
from .file_locking import lock_daemon_file as _lock_daemon_start_file
from .file_locking import try_lock_daemon_file as _try_lock_daemon_file
from .handed_off_launch import resolve_handed_off_guard_daemon_pending_launch
from .lifecycle_journal import record_daemon_lifecycle_event
from .pipx_import_paths import pipx_shared_import_paths
from .start_classification import (
    GuardDaemonStillStartingError,
    SpawnedDaemonSignals,
    classify_spawned_daemon,
    collect_spawned_daemon_signals,
    daemon_still_starting_evidence_present,
)
from .start_heartbeat import (
    SLOW_START_MAX_SECONDS,
    START_HEARTBEAT_CODE,
    START_HEARTBEAT_ENV,
    clear_start_heartbeat,
    start_heartbeat_path,
)
from .start_lock import guard_daemon_start_lock as _guard_daemon_start_lock
from .startup_phase import timed_phase

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
_GUARD_DAEMON_PROCESS_QUERY_TIMEOUT_SECONDS = 5.0
_GUARD_DAEMON_PROCESS_QUERY_OUTPUT_LIMIT_BYTES = 1024 * 1024
_GUARD_DAEMON_PROCESS_QUERY_MONITOR_INTERVAL_SECONDS = 0.01
_GUARD_DAEMON_PROCESS_QUERY_TERMINATE_GRACE_SECONDS = 0.25
_RUNTIME_FINGERPRINT_CACHE_MAX_BYTES = 4096
_RUNTIME_FINGERPRINT_HEX_LENGTH = 64
_WINDOWS_CREATE_NEW_PROCESS_GROUP = 0x00000200
_WINDOWS_DETACHED_PROCESS = 0x00000008
_WINDOWS_CREATE_BREAKAWAY_FROM_JOB = 0x01000000
_GUARD_DAEMON_POSIX_PS_PATHS = ("/bin/ps", "/usr/bin/ps")
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


@dataclasses.dataclass(slots=True)
class _GuardDaemonLaunch:
    process: subprocess.Popen[bytes]
    launch_nonce: str
    deadline: float
    process_start_marker: str | None = None
    receipt_recorded: bool = False


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


def _guard_daemon_launch_command(
    guard_home: Path,
    port: int,
    *,
    home_dir: Path | None = None,
    gate_on_stdin: bool = False,
    executable: Path | None = None,
) -> list[str]:
    trusted_home = _trusted_daemon_home(home_dir)
    if bool(getattr(sys, "frozen", False)) or executable is not None:
        launch = Path(executable) if executable is not None else Path(sys.executable).expanduser()
        if not launch.is_absolute() or not launch.is_file():
            raise RuntimeError("Frozen Guard daemon requires the signed Guard executable.")
        if gate_on_stdin:
            if not bool(getattr(sys, "frozen", False)):
                raise RuntimeError("Frozen Guard daemon gated launch requires the signed Guard executable.")
            return list(
                frozen_daemon_serve_command(
                    guard_home,
                    trusted_home,
                    port,
                    executable=str(launch.resolve(strict=True)),
                )
            )
        return [
            str(launch.resolve(strict=True)),
            "daemon",
            "--serve",
            "--guard-home",
            str(guard_home),
            "--home",
            str(trusted_home),
            "--port",
            str(port),
        ]
    return _isolated_python_module_command(
        "codex_plugin_scanner.cli",
        _trusted_daemon_import_paths(),
        [
            "guard",
            "daemon",
            "--serve",
            "--guard-home",
            str(guard_home),
            "--home",
            str(trusted_home),
            "--port",
            str(port),
        ],
        gate_on_stdin=gate_on_stdin,
    )


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
    launch_cwd = _trusted_daemon_home(home_dir)
    if background_maintenance:
        _schedule_stale_ephemeral_guard_daemon_reap(exclude_guard_home=guard_home)
    state_path = _state_path(guard_home)
    initial_pending = load_authenticated_guard_daemon_pending_launch(guard_home)
    initial_progress = load_authenticated_guard_daemon_start_progress(guard_home)
    # A live still-starting record is adopted or waited on under the start lock
    # below; only an unaccounted unresolved launch receipt fails closed here.
    initial_progress_is_live = initial_progress is not None and _guard_daemon_start_progress_is_live(
        guard_home, initial_progress
    )
    if (
        not initial_progress_is_live
        and _guard_daemon_pending_launch_is_generation_bound(initial_pending)
        and not _guard_daemon_pending_launch_state_is_resolved(guard_home)
        and not _resolve_abandoned_guard_daemon_pending_launch(guard_home, initial_pending)
    ):
        raise RuntimeError("A previous Guard daemon launch could not be retired safely.")
    existing_url = _live_or_newer_daemon_url(guard_home, executable=executable, preferred_port=preferred_port)
    if existing_url is not None:
        if background_maintenance:
            _schedule_duplicate_guard_daemon_retirement(guard_home)
        return existing_url
    with _guard_daemon_start_lock(guard_home, deadline=start_deadline):
        if executable is not None:
            existing_url = _live_or_newer_daemon_url(guard_home, executable=executable, preferred_port=preferred_port)
            if existing_url is not None:
                if background_maintenance:
                    _schedule_duplicate_guard_daemon_retirement(guard_home)
                return existing_url
        else:
            existing_url = load_guard_daemon_url(guard_home)
            if existing_url is not None and (
                preferred_port is None or _guard_daemon_url_port(existing_url) == preferred_port
            ):
                if background_maintenance:
                    _schedule_duplicate_guard_daemon_retirement(guard_home)
                return existing_url
            if existing_url is not None:
                retire_all_guard_daemons_for_home(guard_home, deadline=start_deadline)
                if not guard_daemon_retirement_is_complete(guard_home):
                    raise RuntimeError("Existing Guard daemon could not be retired safely.")
                clear_guard_daemon_state(guard_home)
        if (
            state_path.is_file()
            and _load_authenticated_daemon_identity(guard_home) is None
            and (background_maintenance or not _daemon_lifecycle_artifact_is_exact_tombstone(state_path))
        ):
            retire_all_guard_daemons_for_home(guard_home, deadline=start_deadline)
            if not _daemon_lifecycle_artifact_is_exact_tombstone(state_path):
                raise RuntimeError("Untrusted Guard daemon state could not be retired safely.")
            _remove_invalid_daemon_discovery_key(guard_home)
        adopted_url = (
            None if executable is not None else _adopt_existing_guard_daemon(guard_home, preferred_port=preferred_port)
        )
        if adopted_url is not None:
            if background_maintenance:
                _schedule_duplicate_guard_daemon_retirement(guard_home)
            return adopted_url
        stale_state = _load_state(guard_home)
        if isinstance(stale_state, dict) and not _guard_daemon_state_matches_current_runtime(stale_state):
            stale_pid = stale_state.get("pid")
            if (
                type(stale_pid) is int
                and stale_pid > 0
                and not _retire_guard_daemon_process({**stale_state, "guard_home": str(guard_home)})
            ):
                raise RuntimeError("Stale Guard daemon could not be retired safely.")
        if _guard_daemon_start_in_progress(guard_home):
            inflight_url = _wait_for_guard_daemon_url(guard_home, timeout=max(0.0, start_deadline - time.monotonic()))
            if inflight_url is not None:
                if background_maintenance:
                    _schedule_duplicate_guard_daemon_retirement(guard_home)
                return inflight_url
            retire_all_guard_daemons_for_home(guard_home, deadline=start_deadline)
            if not guard_daemon_retirement_is_complete(guard_home):
                raise RuntimeError("In-progress Guard daemon launch could not be retired safely.")
        start_progress = load_authenticated_guard_daemon_start_progress(guard_home)
        progress_is_live = start_progress is not None and _guard_daemon_start_progress_is_live(
            guard_home, start_progress
        )
        if start_progress is not None and not progress_is_live:
            _clear_guard_daemon_start_progress(guard_home)
        if progress_is_live:
            assert start_progress is not None
            progress_pid = start_progress["pid"]
            progress_spawned_at_ns = start_progress["spawned_at_ns"]
            adopted_url = _wait_for_guard_daemon_url(
                guard_home,
                timeout=max(0.0, start_deadline - time.monotonic()),
            )
            if adopted_url is not None:
                _clear_guard_daemon_start_progress(guard_home)
                if background_maintenance:
                    _schedule_duplicate_guard_daemon_retirement(guard_home)
                return adopted_url
            if _guard_daemon_pid_is_running(progress_pid) and daemon_still_starting_evidence_present(
                guard_home,
                root_pid=progress_pid,
                spawned_at_ns=progress_spawned_at_ns,
            ):
                raise GuardDaemonStillStartingError(
                    f"Guard daemon is still starting; retry shortly. Expected state file at {state_path}."
                )
            _clear_guard_daemon_start_progress(guard_home)
            retire_all_guard_daemons_for_home(guard_home, deadline=start_deadline)
            if not guard_daemon_retirement_is_complete(guard_home):
                raise RuntimeError("In-progress Guard daemon launch could not be retired safely.")
        pending_path_exists = _pending_launch_path(guard_home).is_file()
        pending_launch = load_authenticated_guard_daemon_pending_launch(guard_home)
        if pending_path_exists or pending_launch is not None:
            if (
                _guard_daemon_pending_launch_is_generation_bound(pending_launch)
                and not _guard_daemon_pending_launch_state_is_resolved(guard_home)
                and not _resolve_abandoned_guard_daemon_pending_launch(guard_home, pending_launch)
            ):
                raise RuntimeError("A previous Guard daemon launch could not be retired safely.")
            if _windows_pending_launch_needs_retirement(guard_home, progress_is_live=progress_is_live):
                retire_all_guard_daemons_for_home(guard_home, deadline=start_deadline)
            if not _guard_daemon_pending_launch_state_is_resolved(guard_home):
                raise RuntimeError("A previous Guard daemon launch could not be retired safely.")
        clear_guard_daemon_state(guard_home)
        # setsid() keeps hook workers alive after the daemon exits. They hold
        # the local store, so the replacement never publishes daemon state.
        if background_maintenance:
            reap_orphaned_daemon_workers(deadline=start_deadline)
        for candidate_port in _candidate_ports(guard_home, preferred_port=preferred_port):
            remaining_start_time = start_deadline - time.monotonic()
            if remaining_start_time <= 0:
                break
            launch_nonce = secrets.token_hex(_GUARD_DAEMON_LAUNCH_NONCE_HEX_LENGTH // 2)
            if executable is None:
                command = _guard_daemon_launch_command(
                    guard_home,
                    candidate_port,
                    home_dir=home_dir,
                    gate_on_stdin=os.name == "nt",
                )
                launcher_env = _daemon_launcher_env(
                    home_dir=home_dir,
                    guard_home=guard_home,
                    launch_nonce=launch_nonce,
                )
            else:
                command = _guard_daemon_launch_command(
                    guard_home,
                    candidate_port,
                    home_dir=home_dir,
                    gate_on_stdin=False,
                    executable=executable,
                )
                launcher_env = _daemon_launcher_env(
                    home_dir=home_dir,
                    guard_home=guard_home,
                    executable=executable,
                    launch_nonce=launch_nonce,
                )
            if time.monotonic() >= start_deadline:
                break
            clear_start_heartbeat(guard_home)
            launcher_env = {**launcher_env, START_HEARTBEAT_ENV: str(start_heartbeat_path(guard_home))}
            spawned_at_ns = time.time_ns()
            if os.name == "nt":
                process = subprocess.Popen(
                    command,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    cwd=launch_cwd,
                    env=launcher_env,
                    creationflags=_windows_daemon_creation_flags(
                        allow_job_breakaway=allow_windows_job_breakaway,
                    ),
                )
            else:
                process = subprocess.Popen(
                    command,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    cwd=launch_cwd,
                    env=launcher_env,
                    start_new_session=True,
                )
            launch = _GuardDaemonLaunch(
                process=process,
                launch_nonce=launch_nonce,
                deadline=start_deadline,
            )
            pending_creation_time: int | None = None
            handed_off = False
            retirement_attempted = False
            try:
                pending_creation_time = _record_guard_daemon_pending_launch(
                    guard_home,
                    launch=launch,
                    port=candidate_port,
                )
                _release_guard_daemon_launch_gate(process)
                wait_deadline = _spawned_daemon_wait_deadline(start_deadline)
                url = _wait_for_spawned_guard_daemon_url(
                    guard_home,
                    launch=launch,
                    executable=executable,
                    wait_deadline=wait_deadline,
                )
                if url is not None:
                    handed_off = True
                    if not _clear_spawned_guard_daemon_pending_launch(
                        guard_home, launch=launch, creation_time=pending_creation_time
                    ):
                        raise RuntimeError("Guard daemon pending launch state could not be cleared safely.")
                    if background_maintenance:
                        _schedule_duplicate_guard_daemon_retirement(guard_home)
                    return url
                signals = (
                    collect_spawned_daemon_signals(
                        guard_home,
                        process=process,
                        spawned_at_ns=spawned_at_ns,
                        pending_creation_time=pending_creation_time,
                    )
                    if process.poll() is None
                    else SpawnedDaemonSignals(
                        pending_launch_present=False,
                        lock_held_by_spawned_tree=False,
                        journal_start_requested_after=False,
                        start_heartbeat_present=False,
                    )
                )
                spawn_state = classify_spawned_daemon(
                    process,
                    pending_launch_present=signals.pending_launch_present,
                    lock_held_by_spawned_tree=signals.lock_held_by_spawned_tree,
                    journal_start_requested_after=signals.journal_start_requested_after,
                    start_heartbeat_present=signals.start_heartbeat_present,
                )
                if spawn_state == "progressing" and _record_guard_daemon_start_progress(
                    guard_home,
                    process=process,
                    port=candidate_port,
                    spawned_at_ns=spawned_at_ns,
                ):
                    raise GuardDaemonStillStartingError(
                        f"Guard daemon is still starting; retry shortly. Expected state file at {state_path}."
                    )
                retirement_attempted = True
                root_retired = _terminate_spawned_guard_daemon(process, deadline_monotonic=start_deadline)
                if launch.receipt_recorded:
                    # The signed launch receipt stays in place, so replacement is blocked
                    # until a matching handoff or a proven-dead generation resolves it.
                    raise RuntimeError(
                        "Guard approval center did not start; launch ownership could not be proven contained."
                    )
                if not root_retired:
                    raise RuntimeError("Guard daemon startup process could not be retired safely.")
                if not _clear_spawned_guard_daemon_pending_launch(
                    guard_home, launch=launch, creation_time=pending_creation_time
                ):
                    raise RuntimeError("Guard daemon pending launch state could not be cleared safely.")
                if time.monotonic() >= wait_deadline:
                    # Only the classification reserve is left; it cannot start
                    # another candidate, so a child that used its full wait ends
                    # the attempt. A child that exited early still frees the loop.
                    break
            except GuardDaemonStillStartingError:
                raise
            except BaseException:
                # Once the child has exposed its authenticated endpoint, the
                # process is handed off to the daemon lifecycle. A pending
                # launch cleanup failure must not terminate that live daemon.
                # The pending receipt stays until a matching handoff or a
                # proven-dead generation resolves it, so it is never cleared here.
                if not handed_off and not retirement_attempted:
                    _terminate_spawned_guard_daemon(process, deadline_monotonic=start_deadline)
                raise
    raise RuntimeError(f"Guard approval center did not start. Expected state file at {state_path}.")


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

    token = bind_daemon_lifecycle_deadline(deadline)
    try:
        return _retire_guard_daemons_for_home(guard_home, keep_port=keep_port, deadline=deadline)
    finally:
        reset_daemon_lifecycle_deadline(token)


def _retire_guard_daemons_for_home(
    guard_home: Path,
    *,
    keep_port: int | None,
    deadline: float | None,
) -> list[int]:
    retire_pid = (
        _retire_guard_daemon_pid if deadline is None else partial(_retire_guard_daemon_pid, deadline_monotonic=deadline)
    )
    retired: list[int] = []
    handled_pids: set[int] = set()
    pending_launch = load_authenticated_guard_daemon_pending_launch(guard_home)
    handed_off_launch_nonce: object = None
    if (
        _guard_daemon_pending_launch_is_generation_bound(pending_launch)
        and not _guard_daemon_pending_launch_state_is_resolved(guard_home)
        and not _guard_daemon_pending_launch_is_abandoned(pending_launch)
    ):
        # A launch-specific receipt is deliberately unresolved until its
        # owner publishes the matching handoff or its root is gone. Inventory
        # cannot prove that a same-home process is one of a live launch's
        # descendants.
        if not resolve_handed_off_guard_daemon_pending_launch(guard_home, pending_launch):
            return retired
        assert pending_launch is not None
        handed_off_launch_nonce = pending_launch["launch_nonce"]
    if isinstance(pending_launch, dict):
        pending_pid = pending_launch.get("pid")
        pending_port = pending_launch.get("port")
        pending_creation_time = pending_launch.get("process_creation_time")
        if type(pending_pid) is int and type(pending_creation_time) is int:
            if keep_port is not None and pending_port == keep_port:
                handled_pids.add(pending_pid)
            else:
                actual_creation_time = windows_process_creation_time(pending_pid)
                if actual_creation_time == pending_creation_time:
                    handled_pids.add(pending_pid)
                    if retire_pid(
                        pending_pid,
                        expected_guard_home=guard_home,
                        expected_creation_time=pending_creation_time,
                    ) and _guard_daemon_pid_is_proven_dead(pending_pid):
                        retired.append(pending_pid)
                        _clear_guard_daemon_pending_launch_if_current(
                            guard_home,
                            pid=pending_pid,
                            creation_time=pending_creation_time,
                        )
                elif actual_creation_time is not None or _guard_daemon_pid_is_proven_dead(pending_pid):
                    _clear_guard_daemon_pending_launch_if_current(
                        guard_home,
                        pid=pending_pid,
                        creation_time=pending_creation_time,
                    )
                else:
                    handled_pids.add(pending_pid)

    authenticated_state = load_authenticated_daemon_state(guard_home)
    if handed_off_launch_nonce is not None and (
        not _guard_daemon_pending_launch_state_is_resolved(guard_home)
        or (
            isinstance(authenticated_state, dict) and authenticated_state.get("launch_nonce") != handed_off_launch_nonce
        )
    ):
        # A start replaced the handed-off daemon after its receipt cleared.
        # That launch owns the home now, so this retirement leaves it alone.
        return retired
    if isinstance(authenticated_state, dict):
        state_pid = authenticated_state.get("pid")
        state_port = authenticated_state.get("port")
        if type(state_pid) is int and state_pid > 0 and type(state_port) is int:
            if keep_port is not None and state_port == keep_port:
                handled_pids.add(state_pid)
            elif state_pid in handled_pids and _guard_daemon_pid_is_proven_dead(state_pid):
                _clear_authenticated_guard_daemon_state_if_current(
                    guard_home,
                    expected_state=authenticated_state,
                )
            elif state_pid not in handled_pids:
                handled_pids.add(state_pid)
                state_id = authenticated_state.get("state_id")
                with suppress(Exception):
                    record_daemon_lifecycle_event(
                        guard_home,
                        event="retirement_requested",
                        reason="managed_retirement",
                        pid=state_pid,
                        session_id=state_id if isinstance(state_id, str) else None,
                    )
                expected_start_marker = authenticated_state.get("process_start_marker")
                expected_owner_marker = authenticated_state.get("user")
                if isinstance(expected_start_marker, str) and expected_start_marker.strip():
                    retirement_succeeded = retire_pid(
                        state_pid,
                        expected_guard_home=guard_home,
                        expected_start_marker=expected_start_marker,
                        expected_owner_marker=(
                            expected_owner_marker
                            if isinstance(expected_owner_marker, str) and expected_owner_marker
                            else None
                        ),
                    )
                else:
                    # Markerless live state cannot identify a PID generation: only a proven-dead
                    # PID may be treated as retired, and no signal is ever sent to it.
                    retirement_succeeded = _guard_daemon_pid_is_proven_dead(state_pid)
                if retirement_succeeded:
                    if _guard_daemon_pid_is_proven_dead(state_pid):
                        _clear_authenticated_guard_daemon_state_if_current(
                            guard_home,
                            expected_state=authenticated_state,
                        )
                        if state_pid not in retired:
                            retired.append(state_pid)
                    elif (
                        _guard_daemon_pid_command_identity(
                            state_pid,
                            expected_guard_home=guard_home,
                        )
                        is False
                    ):
                        _clear_authenticated_guard_daemon_state_if_current(
                            guard_home,
                            expected_state=authenticated_state,
                        )

    inventory = _guard_daemon_process_inventory_for_guard_home(guard_home)
    if inventory is not None:
        for pid, port in inventory:
            if pid in handled_pids or (keep_port is not None and port == keep_port):
                continue
            retirement_identity = _guard_daemon_pid_identity_for_retirement(pid)
            if retirement_identity is None:
                continue
            expected_start_marker, expected_owner_marker = retirement_identity
            if retire_pid(
                pid,
                expected_guard_home=guard_home,
                expected_start_marker=expected_start_marker,
                expected_owner_marker=expected_owner_marker,
            ) and _guard_daemon_pid_is_proven_dead(pid):
                handled_pids.add(pid)
                if pid not in retired:
                    retired.append(pid)
        remaining = _guard_daemon_process_inventory_for_guard_home(guard_home)
        empty_inventory_confirmed = inventory == [] and remaining == []
        if inventory != [] and remaining == []:
            empty_inventory_confirmed = _guard_daemon_process_inventory_for_guard_home(guard_home) == []
        if empty_inventory_confirmed and keep_port is None:
            _reconcile_invalid_daemon_lifecycle_artifacts(guard_home)
            _resolve_abandoned_guard_daemon_pending_launch(guard_home, pending_launch)
    reap_orphaned_daemon_workers(deadline=deadline)
    return retired


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

    authenticated_state = load_authenticated_daemon_state(guard_home)
    if isinstance(authenticated_state, dict):
        state_pid = authenticated_state.get("pid")
        if type(state_pid) is not int or state_pid <= 0:
            return False
        if not _guard_daemon_pid_is_proven_dead(state_pid):
            return False
    elif _state_path(guard_home).is_file():
        if not _daemon_lifecycle_artifact_is_exact_tombstone(_state_path(guard_home)):
            return False
    if not _guard_daemon_pending_launch_state_is_resolved(
        guard_home
    ) and not _resolve_abandoned_guard_daemon_pending_launch(
        guard_home, load_authenticated_guard_daemon_pending_launch(guard_home)
    ):
        return False
    inventory = _guard_daemon_process_inventory_for_guard_home(guard_home)
    return inventory == []


def guard_daemon_process_count(guard_home: Path) -> int | None:
    """Return the number of enumerable daemon processes for one Guard home."""

    inventory = _guard_daemon_process_inventory_for_guard_home(guard_home)
    return None if inventory is None else len(inventory)


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


def _adopt_existing_guard_daemon(
    guard_home: Path,
    *,
    preferred_port: int | None = None,
) -> str | None:
    if os.name == "nt":
        return None
    if isinstance(preferred_port, int) and preferred_port > 0:
        adopted = _initialize_existing_guard_daemon(guard_home, preferred_port)
        if adopted is not None:
            write_guard_daemon_state(
                guard_home, preferred_port, adopted["auth_token"], pid=adopted["pid"], write_auth_token=False
            )
            return adopted["url"]
    candidate_ports = _adoptable_guard_daemon_ports(guard_home)
    if isinstance(preferred_port, int) and preferred_port > 0:
        candidate_ports = list(dict.fromkeys([preferred_port, *candidate_ports]))
    for port in candidate_ports:
        adopted = _initialize_existing_guard_daemon(guard_home, port)
        if adopted is None:
            continue
        write_guard_daemon_state(guard_home, port, adopted["auth_token"], pid=adopted["pid"], write_auth_token=False)
        return adopted["url"]
    return None


def _adoptable_guard_daemon_ports(guard_home: Path) -> list[int]:
    state = _load_state(guard_home)
    query = {
        "env_port": os.environ.get("GUARD_DAEMON_PORT"),
        "guard_home": str(guard_home),
        "state_port": _native_int(state.get("port")) if isinstance(state, dict) else None,
        "running_ports": [port for _pid, port in _running_guard_daemon_processes_for_guard_home(guard_home)],
    }
    return [int(port) for port in _lifecycle("adoptable_ports", query, home=guard_home)["ports"]]


def _initialize_existing_guard_daemon(guard_home: Path, port: int) -> _ExistingGuardDaemon | None:
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
    if (
        details_payload is None
        or not _healthz_payload_matches_guard_home(json.dumps(details_payload), guard_home)
        or not _daemon_healthz_details_match_current_runtime(details_payload)
    ):
        return None
    pid = details_payload.get("pid")
    if not isinstance(pid, int) or pid <= 0:
        return None
    return {"url": url, "auth_token": auth_token, "pid": pid}


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


def clear_guard_daemon_state(guard_home: Path) -> None:
    state_path = _state_path(guard_home)
    _ensure_private_directory(state_path.parent)
    with _guard_daemon_state_write_lock(guard_home):
        _write_private_atomic_text(state_path, "{}")


def clear_guard_daemon_state_if_current(guard_home: Path, *, pid: int, port: int) -> bool:
    with _guard_daemon_start_lock(guard_home):
        return _clear_guard_daemon_state_if_current_unlocked(guard_home, pid=pid, port=port)


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

    A healthy live daemon is preserved.  A live daemon with an invalid identity
    bundle is retired before its state is cleared, and an invalid discovery key
    is removed so the next daemon start can regenerate it.  Raises OSError if a
    required write fails so callers can detect incomplete repair.

    Safe to call while the database is live.  Returns a dict describing what was cleared.
    """
    cleared: list[str] = []
    locator = _locator_path(guard_home)
    if locator.is_file():
        locator.unlink()
        cleared.append("locator")
    state = _state_path(guard_home)
    state_payload = _load_state(guard_home) if state.is_file() else None
    identity_is_invalid = _load_authenticated_daemon_identity(guard_home) is None
    discovery_key_path = daemon_discovery_key_path(guard_home)
    invalid_discovery_key_existed = discovery_key_path.is_file() and load_daemon_discovery_key(guard_home) is None
    if state.is_file():
        identity_payload = state_payload if isinstance(state_payload, dict) else {}
        pid = identity_payload.get("pid")
        pid_is_live = type(pid) is int and pid > 0 and _guard_daemon_pid_is_running(pid)
        command_identity: bool | None = False
        if type(pid) is int and pid_is_live:
            command_identity = _guard_daemon_pid_command_identity(pid, expected_guard_home=guard_home)
        if pid_is_live and command_identity is None:
            raise RuntimeError("Live Guard daemon process identity could not be resolved safely.")
        daemon_is_live = pid_is_live and command_identity is True
        if identity_is_invalid:
            retire_all_guard_daemons_for_home(guard_home)
            if not _daemon_lifecycle_artifact_is_exact_tombstone(state):
                raise RuntimeError("Untrusted Guard daemon state could not be retired safely.")
            if daemon_is_live:
                cleared.append("daemon_process")
            daemon_is_live = False
        if not daemon_is_live:
            clear_guard_daemon_state(guard_home)
            cleared.append("daemon_state")
    if identity_is_invalid:
        discovery_key_removed = _remove_invalid_daemon_discovery_key(guard_home)
        if discovery_key_removed or (invalid_discovery_key_existed and not discovery_key_path.exists()):
            cleared.append("daemon_discovery_key")
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


def _reconcile_invalid_daemon_lifecycle_artifacts(guard_home: Path) -> bool:
    """Quarantine invalid records only after callers prove process inventory empty."""

    with _guard_daemon_state_write_lock(guard_home):
        state_path = _state_path(guard_home)
        if state_path.is_file() and load_authenticated_daemon_state(guard_home) is None:
            if not _quarantine_daemon_lifecycle_artifact(
                state_path,
                quarantine_path=guard_home / "daemon-state.invalid.json",
                max_preserved_bytes=_GUARD_DAEMON_STATE_MAX_BYTES,
            ):
                return False
            _remove_invalid_daemon_discovery_key(guard_home)
        pending_path = _pending_launch_path(guard_home)
        if (
            os.name == "nt"
            and pending_path.is_file()
            and load_authenticated_guard_daemon_pending_launch(guard_home) is None
            and not _quarantine_daemon_lifecycle_artifact(
                pending_path,
                quarantine_path=guard_home / "daemon-launch-pending.invalid.json",
                max_preserved_bytes=_GUARD_DAEMON_PENDING_LAUNCH_MAX_BYTES,
            )
        ):
            return False
    return True


def _quarantine_daemon_lifecycle_artifact(
    path: Path,
    *,
    quarantine_path: Path,
    max_preserved_bytes: int,
) -> bool:
    """Atomically replace one unchanged private invalid record with an exact tombstone."""

    if not _daemon_lifecycle_artifact_is_quarantinable(path):
        return False
    try:
        before = path.stat(follow_symlinks=False)
        with path.open("rb") as handle:
            raw = handle.read(max_preserved_bytes + 1)
            opened = os.fstat(handle.fileno())
        after = path.stat(follow_symlinks=False)
    except OSError:
        return False
    identity_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
    identity_opened = (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
    identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if identity_before != identity_opened or identity_before != identity_after:
        return False
    if raw == b"{}" and before.st_size == 2 and _daemon_lifecycle_artifact_is_exact_tombstone(path):
        return True
    try:
        os.replace(path, quarantine_path)
        if len(raw) > max_preserved_bytes:
            _write_private_atomic_text(
                quarantine_path,
                json.dumps(
                    {
                        "quarantined": True,
                        "reason": "oversized_invalid_daemon_lifecycle_artifact",
                        "original_size": before.st_size,
                    },
                    sort_keys=True,
                ),
            )
        _write_private_atomic_text(path, "{}")
    except OSError:
        return False
    return True


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


def _record_guard_daemon_pending_launch(
    guard_home: Path,
    *,
    launch: _GuardDaemonLaunch,
    port: int,
) -> int | None:
    """Persist launch identity before a detached daemon may escape its parent."""

    process = launch.process
    pid = getattr(process, "pid", None)
    if type(pid) is not int or pid <= 0:
        # Lightweight launch doubles do not expose a native process identity.
        # Real Popen handles always do, and must take the identity-bound path.
        return None
    launch_nonce = launch.launch_nonce
    if not _launch_nonce_is_valid(launch_nonce):
        raise RuntimeError("Guard daemon launch nonce could not be recorded.")
    process_marker: str | None = None
    process_owner: str | None = None
    launch_deadline = launch.deadline
    for _attempt in range(10):
        if time.monotonic() >= launch_deadline:
            break
        process_marker = process_start_token(pid)
        process_owner = process_owner_marker(pid) if isinstance(process_marker, str) and process_marker else None
        if isinstance(process_marker, str) and process_marker and isinstance(process_owner, str) and process_owner:
            break
        if getattr(process, "poll", lambda: None)() is not None:
            break
        sleep_seconds = 0.02
        sleep_seconds = min(sleep_seconds, max(0.0, launch_deadline - time.monotonic()))
        if sleep_seconds <= 0:
            break
        time.sleep(sleep_seconds)
    if not isinstance(process_marker, str) or not process_marker:
        raise RuntimeError("Guard daemon process start marker could not be recorded.")
    if not isinstance(process_owner, str) or not process_owner:
        raise RuntimeError("Guard daemon process owner could not be recorded.")
    creation_time = windows_process_creation_time(pid) if os.name == "nt" else None
    if os.name == "nt" and creation_time is None:
        raise RuntimeError("Guard daemon process identity could not be recorded.")
    launch.process_start_marker = process_marker
    _ensure_private_directory(guard_home)
    with _guard_daemon_state_write_lock(guard_home):
        discovery_key = ensure_daemon_discovery_key(guard_home)
        pending_payload: dict[str, object] = {
            "state_kind": "daemon_launch_pending",
            "guard_home": str(guard_home.resolve()),
            "pid": pid,
            "port": port,
            "launch_nonce": launch_nonce,
            "launch_generation": launch_nonce,
            "generation": launch_nonce,
            "process_start_marker": process_marker,
            "user": process_owner,
            "owner": process_owner,
            "runtime_fingerprint": _current_guard_daemon_runtime_fingerprint(),
        }
        if creation_time is not None:
            pending_payload["process_creation_time"] = creation_time
        pending = authenticate_daemon_state(pending_payload, discovery_key=discovery_key)
        _write_private_atomic_text(
            _pending_launch_path(guard_home),
            json.dumps(pending, sort_keys=True),
        )
    launch.receipt_recorded = True
    return creation_time


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


def _clear_spawned_guard_daemon_pending_launch(
    guard_home: Path,
    *,
    launch: _GuardDaemonLaunch,
    creation_time: int | None,
) -> bool:
    process = launch.process
    pid = getattr(process, "pid", None)
    if type(pid) is not int or pid <= 0:
        return True
    return _clear_guard_daemon_pending_launch_if_current(
        guard_home,
        pid=pid,
        creation_time=creation_time,
        launch_nonce=launch.launch_nonce,
        process_start_marker=launch.process_start_marker,
    )


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


def _record_guard_daemon_start_progress(
    guard_home: Path,
    *,
    process: subprocess.Popen[bytes],
    port: int,
    spawned_at_ns: int,
) -> bool:
    """Persist an authenticated marker so the next starter adopts the live spawn."""

    start_token = process_start_token(process.pid)
    if start_token is None:
        return False
    _ensure_private_directory(guard_home)
    try:
        with _guard_daemon_state_write_lock(guard_home):
            discovery_key = ensure_daemon_discovery_key(guard_home)
            progress = authenticate_daemon_state(
                {
                    "state_kind": "daemon_start_progress",
                    "guard_home": str(guard_home.resolve()),
                    "pid": process.pid,
                    "port": port,
                    "process_start_token": start_token,
                    "recorded_at_ns": time.time_ns(),
                    "spawned_at_ns": spawned_at_ns,
                },
                discovery_key=discovery_key,
            )
            _write_private_atomic_text(
                _start_progress_path(guard_home),
                json.dumps(progress, sort_keys=True),
            )
    except OSError:
        return False
    return True


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


def _clear_guard_daemon_start_progress(guard_home: Path) -> None:
    with _guard_daemon_state_write_lock(guard_home):
        _write_private_atomic_text(_start_progress_path(guard_home), "{}")


def _guard_daemon_start_progress_is_live(guard_home: Path, record: GuardDaemonStartProgress) -> bool:
    """Whether the record still names a live, identity-proven daemon for this home."""

    now_ns = time.time_ns()
    if _start_progress_record_is_live(guard_home, record, now_ns=now_ns):
        return True
    # A slow machine can still be importing after the recorded window. Keep the
    # same identity checks but judge age by the bounded slow-start window, and
    # only while the spawned tree still shows start evidence.
    spawned_at_ns = record.get("spawned_at_ns")
    if (
        type(spawned_at_ns) is not int
        or not 0 < now_ns - spawned_at_ns < int(SLOW_START_MAX_SECONDS * 1_000_000_000)
        or not _start_progress_record_is_live(guard_home, record, now_ns=record["recorded_at_ns"])
    ):
        return False
    return daemon_still_starting_evidence_present(guard_home, root_pid=record["pid"], spawned_at_ns=spawned_at_ns)


def _start_progress_record_is_live(guard_home: Path, record: GuardDaemonStartProgress, *, now_ns: int) -> bool:
    query = {
        "record": _native_fields(record, ("pid", "process_start_token", "recorded_at_ns")),
        "now_ns": now_ns,
        "worker_ready_floor": _START_TIMEOUT_FLOOR_SECONDS,
    }
    return bool(_lifecycle("start_progress_live", query, home=guard_home, facts_home=guard_home)["live"])


def _windows_pending_launch_needs_retirement(guard_home: Path, *, progress_is_live: bool) -> bool:
    """A live still-starting record exempts its pid from the previous-launch retire."""

    if os.name != "nt" or progress_is_live:
        return False
    return _pending_launch_path(guard_home).is_file() or (
        load_authenticated_guard_daemon_pending_launch(guard_home) is not None
    )


def _guard_daemon_pending_launch_state_is_resolved(guard_home: Path) -> bool:
    """A launch resolves once a tombstone replaces its receipt.

    Its own handoff leaves that tombstone, and so does
    ``_resolve_abandoned_guard_daemon_pending_launch`` once the launch is gone.
    Callers must fail closed while the receipt remains unresolved.
    """

    path = _pending_launch_path(guard_home)
    return not path.is_file() or _daemon_lifecycle_artifact_is_exact_tombstone(path)


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


def _remove_invalid_daemon_discovery_key(guard_home: Path) -> bool:
    if load_daemon_discovery_key(guard_home) is not None:
        return False
    key_path = daemon_discovery_key_path(guard_home)
    try:
        key_path.unlink()
    except FileNotFoundError:
        return False
    return True


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
    from ..native_policy_snapshot_windows_state import _windows_ensure_private_directory

    try:
        _windows_ensure_private_directory(path)
    except (NativePolicySnapshotError, OSError, RuntimeError, TypeError, ValueError):
        return


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
        ps_path = _trusted_posix_ps_path()
        if ps_path is None:
            if not sys.platform.startswith("linux"):
                return None
            proc_entries = _linux_proc_process_entries()
            if proc_entries is None:
                return None
            entries = proc_entries
        else:
            output = _bounded_process_query_stdout([ps_path, "-axo", "pid=,command="])
            if output is None:
                return None

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


def _runtime_identity_paths(source_root: Path) -> list[Path]:
    package_root = source_root / "codex_plugin_scanner"
    static_root = package_root / "guard" / "daemon" / "static"
    paths = [*package_root.rglob("*.py")]
    native_manifest = package_root / "_native" / "runtime-manifest.json"
    if native_manifest.is_file():
        paths.append(native_manifest)
    if static_root.is_dir():
        paths.extend(path for path in static_root.rglob("*") if path.is_file())
    return paths


def _runtime_tree_signature(source_root: Path, paths: list[Path]) -> str:
    digest = hashlib.sha256()
    digest.update(__version__.encode("utf-8"))
    for path in sorted(paths):
        try:
            stat_result = path.stat()
        except OSError:
            continue
        digest.update(str(path.relative_to(source_root)).encode("utf-8"))
        digest.update(str(stat_result.st_size).encode("utf-8"))
        digest.update(str(stat_result.st_mtime_ns).encode("utf-8"))
    return digest.hexdigest()


def _hash_runtime_contents(source_root: Path, paths: list[Path]) -> str:
    digest = hashlib.sha256()
    digest.update(__version__.encode("utf-8"))
    for path in sorted(paths):
        try:
            stat_result = path.stat()
        except OSError:
            continue
        digest.update(str(path.relative_to(source_root)).encode("utf-8"))
        digest.update(str(stat_result.st_size).encode("utf-8"))
        try:
            with path.open("rb") as handle:
                while chunk := handle.read(65536):
                    digest.update(chunk)
        except OSError:
            continue
    return digest.hexdigest()


def _runtime_fingerprint_cache_path(source_root: Path) -> Path:
    digest = hashlib.sha256(os.fsencode(str(source_root))).hexdigest()
    return Path.home() / ".hol-guard" / "runtime-fingerprint-cache" / f"{digest}.json"


def _is_sha256_hex(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == _RUNTIME_FINGERPRINT_HEX_LENGTH
        and not set(value) - set("0123456789abcdef")
    )


def _load_runtime_fingerprint_cache(source_root: Path, tree_sig: str) -> str | None:
    raw_payload = read_private_regular_text(
        _runtime_fingerprint_cache_path(source_root),
        max_bytes=_RUNTIME_FINGERPRINT_CACHE_MAX_BYTES,
        require_private_parent=True,
    )
    if raw_payload is None:
        return None
    try:
        payload = json.loads(raw_payload)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    if payload.get("source_root") != str(source_root):
        return None
    cached_tree_sig = payload.get("tree_sig")
    cached_fingerprint = payload.get("content_fingerprint")
    if cached_tree_sig != tree_sig or not isinstance(cached_fingerprint, str):
        return None
    if not _is_sha256_hex(cached_fingerprint):
        return None
    return cached_fingerprint


def _store_runtime_fingerprint_cache(source_root: Path, tree_sig: str, fingerprint: str) -> None:
    cache_path = _runtime_fingerprint_cache_path(source_root)
    try:
        _ensure_private_directory(cache_path.parent)
        _write_private_atomic_text(
            cache_path,
            json.dumps(
                {
                    "content_fingerprint": fingerprint,
                    "source_root": str(source_root),
                    "tree_sig": tree_sig,
                },
                sort_keys=True,
            ),
        )
    except (OSError, RuntimeError, ValueError):
        return


def _current_guard_daemon_runtime_fingerprint() -> str:
    global _runtime_fingerprint_cache
    if _runtime_fingerprint_cache is not None:
        return _runtime_fingerprint_cache[1]
    source_root = Path(_current_guard_daemon_source_root())
    paths = _runtime_identity_paths(source_root)
    tree_sig = _runtime_tree_signature(source_root, paths)
    cached = _load_runtime_fingerprint_cache(source_root, tree_sig)
    if cached is not None:
        _runtime_fingerprint_cache = (tree_sig, cached)
        return cached
    fingerprint = _hash_runtime_contents(source_root, paths)
    _store_runtime_fingerprint_cache(source_root, tree_sig, fingerprint)
    _runtime_fingerprint_cache = (tree_sig, fingerprint)
    return fingerprint


def current_guard_daemon_runtime_fingerprint() -> str:
    """Return the installed runtime identity used for daemon compatibility."""

    return _current_guard_daemon_runtime_fingerprint()


def current_guard_daemon_source_root() -> str:
    """Return the install root whose runtime identity this process reports."""

    return _current_guard_daemon_source_root()


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

    if pid <= 0:
        return None
    if os.name == "nt":
        return None
    ps_path = _trusted_posix_ps_path()
    if ps_path is None:
        return None
    output = _bounded_process_query_stdout([ps_path, "-p", str(pid), "-o", "ppid="])
    if output is None:
        return None
    try:
        parent_pid = int(output.strip())
    except ValueError:
        return None
    return parent_pid if parent_pid > 0 else None


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
    ps_path = _trusted_posix_ps_path()
    if ps_path is None:
        return None
    output = _bounded_process_query_stdout(
        [ps_path, "-p", str(pid), "-o", "command="],
    )
    if output is None:
        return None
    stdout = output.strip()
    return stdout or None


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


def _retire_guard_daemon_process(payload: dict[str, object]) -> bool:
    pid = payload.get("pid")
    if not isinstance(pid, int) or pid <= 0:
        return False
    guard_home = payload.get("guard_home")
    expected_guard_home = Path(guard_home) if isinstance(guard_home, str) and guard_home.strip() else None
    expected_start_marker = payload.get("process_start_marker")
    if not isinstance(expected_start_marker, str) or not expected_start_marker:
        # A stale state record may point at a recycled PID. If command identity
        # proves that a live process belongs to another Guard home or command,
        # clear the record without signaling it. A matching or unresolvable
        # process still requires a generation marker below.
        if _guard_daemon_pid_is_proven_dead(pid):
            return True
        identity = _guard_daemon_pid_command_identity(pid, expected_guard_home=expected_guard_home)
        return identity is False
    expected_owner_marker = payload.get("user")
    return _retire_guard_daemon_pid(
        pid,
        expected_guard_home=expected_guard_home,
        expected_start_marker=expected_start_marker,
        expected_owner_marker=expected_owner_marker if isinstance(expected_owner_marker, str) else None,
    )


def _terminate_spawned_guard_daemon(
    process: subprocess.Popen[bytes],
    *,
    deadline_monotonic: float | None = None,
) -> bool:
    """Terminate and reap the exact child handle after startup fails."""

    deadline = time.monotonic() + 2.0
    if deadline_monotonic is not None:
        deadline = min(deadline, deadline_monotonic)
    process_stdin = getattr(process, "stdin", None)
    if process_stdin is not None:
        with suppress(OSError, ValueError):
            process_stdin.close()
    if process.poll() is not None:
        return True
    with suppress(OSError):
        process.terminate()
    try:
        process.wait(timeout=min(1.0, max(0.0, deadline - time.monotonic())))
    except subprocess.TimeoutExpired:
        with suppress(OSError):
            process.kill()
        try:
            process.wait(timeout=min(1.0, max(0.0, deadline - time.monotonic())))
        except subprocess.TimeoutExpired:
            return False
    return process.poll() is not None


def _release_guard_daemon_launch_gate(process: subprocess.Popen[bytes]) -> None:
    if os.name != "nt":
        return
    if process.stdin is None:
        raise RuntimeError("Guard daemon launch gate is unavailable.")
    try:
        _ = process.stdin.write(b"1")
        process.stdin.flush()
    except (OSError, ValueError) as error:
        raise RuntimeError("Guard daemon launch gate could not be released.") from error
    finally:
        with suppress(OSError, ValueError):
            process.stdin.close()


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


def _spawned_daemon_wait_deadline(start_deadline: float) -> float:
    """Return when the readiness wait must stop to leave time for classification.

    Classification queries the spawned process tree under the same lifecycle
    deadline. When the wait spends the whole budget those queries time out, and
    the error path terminates a child that was still starting normally, so a
    slow host never completes a start.
    """

    remaining = max(0.0, start_deadline - time.monotonic())
    reserve = min(_START_CLASSIFICATION_RESERVE_SECONDS, remaining * _START_CLASSIFICATION_RESERVE_FRACTION)
    return start_deadline - reserve


def _wait_for_spawned_guard_daemon_url(
    guard_home: Path,
    *,
    launch: _GuardDaemonLaunch,
    executable: Path | None,
    wait_deadline: float,
) -> str | None:
    try:
        return _wait_for_started_guard_daemon_url(
            guard_home,
            timeout=max(0.0, wait_deadline - time.monotonic()),
            launch=launch,
            executable=executable,
        )
    except TimeoutError:
        # An expired poll is not evidence that the child is stuck; let the
        # classifier decide whether it is dead, blocked, or still starting.
        return None


def _wait_for_started_guard_daemon_url(
    guard_home: Path,
    *,
    timeout: float,
    launch: _GuardDaemonLaunch,
    executable: Path | None,
) -> str | None:
    process = launch.process
    launch_nonce = launch.launch_nonce if launch.receipt_recorded else None
    if executable is None:
        return _wait_for_guard_daemon_url(
            guard_home,
            timeout=timeout,
            process=process,
            expected_pid=getattr(process, "pid", None),
            expected_launch_nonce=launch_nonce if isinstance(launch_nonce, str) else None,
        )
    return _wait_for_guard_daemon_url(
        guard_home,
        timeout=timeout,
        process=process,
        require_current_runtime=False,
        expected_pid=process.pid,
        expected_launch_nonce=launch_nonce if isinstance(launch_nonce, str) else None,
    )


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


def _wait_for_guard_daemon_url(
    guard_home: Path,
    *,
    timeout: float,
    process: subprocess.Popen[bytes] | None = None,
    require_current_runtime: bool = True,
    expected_pid: int | None = None,
    expected_launch_nonce: str | None = None,
) -> str | None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if require_current_runtime:
                url = load_guard_daemon_url(guard_home)
            else:
                # The spawned-launch check and the state gate share this resident.
                # A missed answer has to stay inside the poll. Escaping here used
                # to tear down a child that had already published state.
                token = bind_daemon_lifecycle_deadline(
                    min(deadline, time.monotonic() + _SPAWNED_URL_POLL_LIFECYCLE_SECONDS)
                )
                try:
                    url = _live_guard_daemon_url(
                        guard_home,
                        require_current_runtime=False,
                        expected_pid=expected_pid,
                    )
                finally:
                    reset_daemon_lifecycle_deadline(token)
        except (NativeDaemonLifecycleError, TimeoutError):
            url = None
        if url is not None and (
            expected_launch_nonce is None
            or _guard_daemon_handoff_matches_launch(
                guard_home,
                launch_nonce=expected_launch_nonce,
                expected_pid=expected_pid if expected_pid is not None else -1,
                expected_port=_guard_daemon_url_port(url),
                require_same_runtime=require_current_runtime,
            )
        ):
            return url
        if process is not None and process.poll() is not None:
            return None
        time.sleep(GUARD_DAEMON_POLL_INTERVAL_SECONDS)
    return None


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


def _windows_venv_launcher_parent_pid() -> int | None:
    """Ignore the Windows venv redirector that stays alive beside the real interpreter.

    ``Scripts\\python.exe`` keeps the daemon command line and spawns the base
    interpreter with the same arguments. That parent is not a second daemon.
    A competing daemon is still rejected, and the owner file lock still
    serializes the slot when the parent really holds it.
    """

    if os.name != "nt":
        return None
    parent_pid = os.getppid()
    if parent_pid <= 0 or parent_pid == os.getpid():
        return None
    parent_command = windows_processes.windows_process_command_line(parent_pid)
    own_command = windows_processes.windows_process_command_line(os.getpid())
    if parent_command is None or own_command is None:
        return None
    if not _same_daemon_invocation(parent_command, own_command):
        return None
    return parent_pid


def _inventory_has_competing_daemon(inventory: list[tuple[int, int]]) -> bool:
    query = {
        "inventory": [[pid, port] for pid, port in inventory],
        "own_pid": os.getpid(),
        "launcher_parent": _windows_venv_launcher_parent_pid(),
    }
    return bool(_lifecycle("competing_daemon", query)["competing"])


def acquire_guard_daemon_owner_lock(guard_home: Path) -> BinaryIO:
    """Claim the single daemon slot before any background worker can read secrets."""

    inventory = _guard_daemon_process_inventory_for_guard_home(guard_home)
    if inventory is None:
        raise RuntimeError("Guard could not verify that the daemon slot is available.")
    if _inventory_has_competing_daemon(inventory):
        raise RuntimeError("A Guard daemon is already active for this Guard home.")
    lock_path = guard_home / _GUARD_DAEMON_OWNER_LOCK_FILE
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    handle = lock_path.open("a+b")
    if not _try_lock_daemon_file(handle):
        handle.close()
        raise RuntimeError("A Guard daemon is already active for this Guard home.")
    inventory = _guard_daemon_process_inventory_for_guard_home(guard_home)
    if inventory is None or _inventory_has_competing_daemon(inventory):
        _unlock_daemon_start_file(handle)
        handle.close()
        raise RuntimeError("A Guard daemon is already active for this Guard home.")
    return handle


def release_guard_daemon_owner_lock(handle: BinaryIO | None) -> None:
    if handle is None or handle.closed:
        return
    _unlock_daemon_start_file(handle)
    handle.close()


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


def _candidate_ports(guard_home: Path, *, preferred_port: int | None = None) -> list[int]:
    query = {
        "env_port": os.environ.get("GUARD_DAEMON_PORT"),
        "guard_home": str(guard_home),
        "preferred_port": _native_int(preferred_port),
    }
    return [int(port) for port in _lifecycle("candidate_ports", query, home=guard_home)["ports"]]


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


def _live_or_newer_daemon_url(guard_home: Path, *, executable: Path | None, preferred_port: int | None) -> str | None:
    from .runtime_peer import live_or_newer_daemon_url as resolve_live

    return resolve_live(guard_home, executable=executable, preferred_port=preferred_port, current_version=__version__)


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
from .manager_process_query import (  # noqa: E402, F401
    _bounded_process_query_stdout,
    _capture_bounded_process_query_stdout,
    _linux_proc_process_entries,
    _process_query_environment,
    _spawn_bounded_process_query,
    _terminate_bounded_process_query,
    _trusted_posix_ps_path,
)
