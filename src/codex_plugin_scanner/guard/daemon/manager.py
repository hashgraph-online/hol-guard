"""Guard daemon lifecycle helpers."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import ntpath
import os
import re
import secrets
import shlex
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
from contextlib import contextmanager, suppress
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO, TypedDict

from ...version import __version__
from ..windows_paths import (
    trusted_windows_system_executable,
    windows_command_line_to_argv,
    windows_process_creation_time,
    windows_process_is_running,
    windows_process_liveness,
    windows_terminate_process_if_creation_time,
)
from .discovery import (
    authenticate_daemon_state,
    daemon_discovery_key_path,
    ensure_daemon_discovery_key,
    load_authenticated_daemon_state,
    load_daemon_discovery_key,
    verify_daemon_state,
)

DEFAULT_GUARD_DAEMON_PORT = 4781
GUARD_DAEMON_PORT_RANGE = 1000
REQUIRED_DAEMON_TABLES = frozenset({"guard_connect_states"})
GUARD_DAEMON_COMPATIBILITY_VERSION = 2
GUARD_DAEMON_START_TIMEOUT_SECONDS = 5.0
GUARD_DAEMON_POST_UPDATE_START_TIMEOUT_SECONDS = 30.0
GUARD_DAEMON_POLL_INTERVAL_SECONDS = 0.1
GUARD_DAEMON_HOOK_RECOVERY_COOLDOWN_SECONDS = 5.0
_EPHEMERAL_GUARD_DAEMON_REAP_INTERVAL_SECONDS = 30.0
_EPHEMERAL_GUARD_DAEMON_STALE_SECONDS = 30.0
_EPHEMERAL_GUARD_DAEMON_MAX_STATES = 512
_GUARD_DAEMON_PRIVATE_FILE_MODE = 0o600
_GUARD_DAEMON_PRIVATE_DIR_MODE = 0o700
_APPROVAL_CENTER_LOCATOR_FILE = "approval-center-locator.json"
_GUARD_DAEMON_PENDING_LAUNCH_FILE = "daemon-launch-pending.json"
_GUARD_DAEMON_STATE_MAX_BYTES = 64 * 1024
_GUARD_DAEMON_PENDING_LAUNCH_MAX_BYTES = 4096
_GUARD_DAEMON_PROCESS_QUERY_TIMEOUT_SECONDS = 5.0
_GUARD_DAEMON_PROCESS_QUERY_OUTPUT_LIMIT_BYTES = 1024 * 1024
_GUARD_DAEMON_PROCESS_QUERY_MONITOR_INTERVAL_SECONDS = 0.01
_GUARD_DAEMON_PROCESS_QUERY_TERMINATE_GRACE_SECONDS = 0.25
_WINDOWS_CREATE_NEW_PROCESS_GROUP = 0x00000200
_WINDOWS_DETACHED_PROCESS = 0x00000008
_WINDOWS_CREATE_BREAKAWAY_FROM_JOB = 0x01000000
_GUARD_DAEMON_POSIX_PS_PATHS = ("/bin/ps", "/usr/bin/ps")
_GUARD_DAEMON_BOOTSTRAP = (
    "import json,runpy,sys; "
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
        "HOME",
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

_START_LOCKS: dict[str, threading.Lock] = {}
_START_LOCKS_GUARD = threading.Lock()
_STATE_WRITE_LOCKS: dict[str, threading.Lock] = {}
_STATE_WRITE_LOCKS_GUARD = threading.Lock()
_LAST_EPHEMERAL_REAP_AT = 0.0
_runtime_fingerprint_cache: str | None = None


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


def _daemon_launcher_env(*, home_dir: Path | None = None) -> dict[str, str]:
    """Build a minimal detached-daemon environment without Python startup hooks."""

    env = {key: value for key, value in os.environ.items() if key.upper() in _GUARD_DAEMON_ENV_KEYS}
    trusted_home = _trusted_daemon_home(home_dir)
    env.update(
        {
            "HOME": str(trusted_home),
            "PYTHONNOUSERSITE": "1",
            "PYTHONSAFEPATH": "1",
        }
    )
    if os.name == "nt":
        env["USERPROFILE"] = str(trusted_home)
    return env


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
) -> list[str]:
    trusted_home = _trusted_daemon_home(home_dir)
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


def ensure_guard_daemon(
    guard_home: Path,
    *,
    home_dir: Path | None = None,
    start_timeout: float | None = None,
    preferred_port: int | None = None,
    allow_windows_job_breakaway: bool = False,
) -> str:
    timeout = GUARD_DAEMON_START_TIMEOUT_SECONDS if start_timeout is None else start_timeout
    _reap_stale_ephemeral_guard_daemons(exclude_guard_home=guard_home)
    state_path = _state_path(guard_home)
    existing_url = load_guard_daemon_url(guard_home)
    if existing_url is not None:
        existing_port = _guard_daemon_url_port(existing_url)
        if preferred_port is None or existing_port == preferred_port:
            _retire_duplicate_guard_daemons(guard_home, keep_port=existing_port)
            return existing_url
    with _guard_daemon_start_lock(guard_home):
        existing_url = load_guard_daemon_url(guard_home)
        if existing_url is not None:
            existing_port = _guard_daemon_url_port(existing_url)
            if preferred_port is None or existing_port == preferred_port:
                _retire_duplicate_guard_daemons(guard_home, keep_port=existing_port, start_lock_held=True)
                return existing_url
            retire_all_guard_daemons_for_home(guard_home)
            if not guard_daemon_retirement_is_complete(guard_home):
                raise RuntimeError("Existing Guard daemon could not be retired safely.")
            clear_guard_daemon_state(guard_home)
        if state_path.is_file() and _load_authenticated_daemon_identity(guard_home) is None:
            retire_all_guard_daemons_for_home(guard_home)
            if not _daemon_lifecycle_artifact_is_exact_tombstone(state_path):
                raise RuntimeError("Untrusted Guard daemon state could not be retired safely.")
            _remove_invalid_daemon_discovery_key(guard_home)
        adopted_url = _adopt_existing_guard_daemon(guard_home, preferred_port=preferred_port)
        if adopted_url is not None:
            _retire_duplicate_guard_daemons(
                guard_home,
                keep_port=_guard_daemon_url_port(adopted_url),
                start_lock_held=True,
            )
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
            inflight_url = _wait_for_guard_daemon_url(guard_home, timeout=timeout)
            if inflight_url is not None:
                _retire_duplicate_guard_daemons(
                    guard_home,
                    keep_port=_guard_daemon_url_port(inflight_url),
                    start_lock_held=True,
                )
                return inflight_url
            retire_all_guard_daemons_for_home(guard_home)
            if not guard_daemon_retirement_is_complete(guard_home):
                raise RuntimeError("In-progress Guard daemon launch could not be retired safely.")
        if os.name == "nt" and (
            _pending_launch_path(guard_home).is_file()
            or load_authenticated_guard_daemon_pending_launch(guard_home) is not None
        ):
            retire_all_guard_daemons_for_home(guard_home)
            if not _guard_daemon_pending_launch_state_is_resolved(guard_home):
                raise RuntimeError("A previous Guard daemon launch could not be retired safely.")
        clear_guard_daemon_state(guard_home)
        for candidate_port in _candidate_ports(guard_home, preferred_port=preferred_port):
            command = _guard_daemon_launch_command(
                guard_home,
                candidate_port,
                home_dir=home_dir,
                gate_on_stdin=os.name == "nt",
            )
            if os.name == "nt":
                process = subprocess.Popen(
                    command,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    env=_daemon_launcher_env(home_dir=home_dir),
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
                    env=_daemon_launcher_env(home_dir=home_dir),
                    start_new_session=True,
                )
            pending_creation_time: int | None = None
            try:
                pending_creation_time = _record_guard_daemon_pending_launch(
                    guard_home,
                    process=process,
                    port=candidate_port,
                )
                _release_guard_daemon_launch_gate(process)
                url = _wait_for_guard_daemon_url(
                    guard_home,
                    timeout=timeout,
                    process=process,
                )
                if url is not None:
                    if not _clear_spawned_guard_daemon_pending_launch(
                        guard_home, process=process, creation_time=pending_creation_time
                    ):
                        raise RuntimeError("Guard daemon pending launch state could not be cleared safely.")
                    _retire_duplicate_guard_daemons(
                        guard_home,
                        keep_port=_guard_daemon_url_port(url),
                        start_lock_held=True,
                    )
                    return url
                if not _terminate_spawned_guard_daemon(process):
                    raise RuntimeError("Guard daemon startup process could not be retired safely.")
                if not _clear_spawned_guard_daemon_pending_launch(
                    guard_home, process=process, creation_time=pending_creation_time
                ):
                    raise RuntimeError("Guard daemon pending launch state could not be cleared safely.")
            except BaseException:
                if _terminate_spawned_guard_daemon(process):
                    _clear_spawned_guard_daemon_pending_launch(
                        guard_home, process=process, creation_time=pending_creation_time
                    )
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
) -> str:
    """Restart the local daemon after a package update with a longer startup window."""
    return ensure_guard_daemon(
        guard_home,
        home_dir=home_dir,
        start_timeout=GUARD_DAEMON_POST_UPDATE_START_TIMEOUT_SECONDS,
        preferred_port=preferred_port,
        allow_windows_job_breakaway=allow_windows_job_breakaway,
    )


def recover_guard_daemon_after_hook_failure(
    guard_home: Path,
    *,
    home_dir: Path | None = None,
) -> str:
    """Restart an older daemon after its authenticated hook endpoint fails.

    The normal health endpoint can remain responsive while hook workers or the
    identity challenge are wedged. The managed bridge invokes this only after
    an authenticated hook request fails. A short generation cooldown prevents
    concurrent failed hooks from repeatedly retiring the replacement daemon.
    """

    with _guard_daemon_start_lock(guard_home):
        state = load_authenticated_daemon_state(guard_home)
        current_url = load_guard_daemon_url(guard_home)
        if current_url is not None and _daemon_generation_is_recent(state):
            return current_url
        retire_all_guard_daemons_for_home(guard_home)
        if not guard_daemon_retirement_is_complete(guard_home):
            raise RuntimeError("Unresponsive Guard daemon could not be retired safely.")
    return ensure_guard_daemon(guard_home, home_dir=home_dir)


def _daemon_generation_is_recent(state: dict[str, object] | None) -> bool:
    if not isinstance(state, dict):
        return False
    started_at = state.get("started_at")
    if not isinstance(started_at, str):
        return False
    try:
        started = datetime.fromisoformat(started_at)
    except ValueError:
        return False
    if started.tzinfo is None:
        return False
    age_seconds = (datetime.now(timezone.utc) - started.astimezone(timezone.utc)).total_seconds()
    return 0 <= age_seconds <= GUARD_DAEMON_HOOK_RECOVERY_COOLDOWN_SECONDS


def retire_all_guard_daemons_for_home(
    guard_home: Path,
    *,
    keep_port: int | None = None,
) -> list[int]:
    """Stop Guard daemon processes for one guard home, optionally keeping one port alive."""
    retired: list[int] = []
    handled_pids: set[int] = set()
    pending_launch = load_authenticated_guard_daemon_pending_launch(guard_home)
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
                    if _retire_guard_daemon_pid(
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
                retirement_succeeded = _retire_guard_daemon_pid(
                    state_pid,
                    expected_guard_home=guard_home,
                )
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
            if _retire_guard_daemon_pid(pid, expected_guard_home=guard_home) and _guard_daemon_pid_is_proven_dead(pid):
                handled_pids.add(pid)
                if pid not in retired:
                    retired.append(pid)
        remaining = _guard_daemon_process_inventory_for_guard_home(guard_home)
        empty_inventory_confirmed = inventory == [] and remaining == []
        if inventory != [] and remaining == []:
            empty_inventory_confirmed = _guard_daemon_process_inventory_for_guard_home(guard_home) == []
        if empty_inventory_confirmed and keep_port is None:
            _reconcile_invalid_daemon_lifecycle_artifacts(guard_home)
    return retired


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
    if not _guard_daemon_pending_launch_state_is_resolved(guard_home):
        return False
    inventory = _guard_daemon_process_inventory_for_guard_home(guard_home)
    return inventory == []


def guard_daemon_url_for_home(guard_home: Path) -> str:
    return f"http://127.0.0.1:{_configured_port(guard_home)}"


def load_guard_daemon_url(guard_home: Path) -> str | None:
    identity = _load_authenticated_daemon_identity(guard_home)
    if identity is None:
        return None
    payload, auth_token = identity
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
    if _daemon_healthz_details_match_guard_home(url, guard_home, auth_token=auth_token):
        return url
    compatibility_version = payload.get("compatibility_version")
    if compatibility_version != GUARD_DAEMON_COMPATIBILITY_VERSION:
        return None
    return None


def _load_authenticated_daemon_identity(guard_home: Path) -> tuple[dict[str, object], str] | None:
    payload = load_authenticated_daemon_state(guard_home)
    if payload is None:
        return None
    auth_token = load_guard_daemon_auth_token(guard_home)
    expected_token_id = payload.get("auth_token_id")
    if (
        auth_token is None
        or not isinstance(expected_token_id, str)
        or not secrets.compare_digest(
            hashlib.sha256(auth_token.encode("utf-8")).hexdigest(),
            expected_token_id,
        )
    ):
        return None
    return payload, auth_token


def load_guard_daemon_auth_token(guard_home: Path) -> str | None:
    token_path = _auth_token_path(guard_home)
    if not _private_daemon_file_is_valid(token_path):
        return None
    try:
        token = token_path.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return token or None


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


def _daemon_healthz_details_match_current_runtime(payload: dict[str, object]) -> bool:
    return (
        payload.get("package_version") == __version__
        and payload.get("runtime_fingerprint") == _current_guard_daemon_runtime_fingerprint()
    )


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
            write_guard_daemon_state(guard_home, preferred_port, adopted["auth_token"], pid=adopted["pid"])
            return adopted["url"]
    candidate_ports = _adoptable_guard_daemon_ports(guard_home)
    if isinstance(preferred_port, int) and preferred_port > 0:
        candidate_ports = _prepend_preferred_port(candidate_ports, preferred_port)
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


def _retire_duplicate_guard_daemons(
    guard_home: Path,
    *,
    keep_port: int | None,
    start_lock_held: bool = False,
) -> None:
    if keep_port is None:
        return
    if start_lock_held:
        _retire_duplicate_guard_daemons_unlocked(guard_home, keep_port=keep_port)
        return
    with _guard_daemon_start_lock(guard_home):
        _retire_duplicate_guard_daemons_unlocked(guard_home, keep_port=keep_port)


def _retire_duplicate_guard_daemons_unlocked(guard_home: Path, *, keep_port: int) -> None:
    saw_duplicate = False
    for pid, port in _running_guard_daemon_processes_for_guard_home(guard_home):
        if port == keep_port:
            continue
        saw_duplicate = True
        if not _retire_guard_daemon_pid(pid, expected_guard_home=guard_home):
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
) -> None:
    state_path = _state_path(guard_home)
    _ensure_private_directory(state_path.parent)
    with _guard_daemon_state_write_lock(guard_home):
        discovery_key = ensure_daemon_discovery_key(guard_home)
        daemon_state = authenticate_daemon_state(
            {
                "guard_home": str(guard_home.resolve()),
                "host": host,
                "port": port,
                "compatibility_version": GUARD_DAEMON_COMPATIBILITY_VERSION,
                "package_version": __version__,
                "source_root": _current_guard_daemon_source_root(),
                "runtime_fingerprint": _current_guard_daemon_runtime_fingerprint(),
                "pid": pid if isinstance(pid, int) and pid > 0 else os.getpid(),
                "started_at": started_at or datetime.now(timezone.utc).isoformat(),
                "state_id": state_id or secrets.token_hex(16),
                "auth_token_id": hashlib.sha256(auth_token.encode("utf-8")).hexdigest(),
            },
            discovery_key=discovery_key,
        )
        if write_auth_token:
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
    if not isinstance(daemon_url, str):
        return None
    if not isinstance(approval_url_base, str):
        return None
    if not isinstance(started_at, str):
        return None
    if not isinstance(state_path_str, str):
        return None
    if not isinstance(guard_home_str, str):
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


def _record_guard_daemon_pending_launch(
    guard_home: Path,
    *,
    process: subprocess.Popen[bytes],
    port: int,
) -> int | None:
    """Persist a Windows PID identity before a detached daemon may escape its parent."""

    if os.name != "nt":
        return None
    creation_time = windows_process_creation_time(process.pid)
    if creation_time is None:
        raise RuntimeError("Guard daemon process identity could not be recorded.")
    _ensure_private_directory(guard_home)
    with _guard_daemon_state_write_lock(guard_home):
        discovery_key = ensure_daemon_discovery_key(guard_home)
        pending = authenticate_daemon_state(
            {
                "state_kind": "daemon_launch_pending",
                "guard_home": str(guard_home.resolve()),
                "pid": process.pid,
                "port": port,
                "process_creation_time": creation_time,
            },
            discovery_key=discovery_key,
        )
        _write_private_atomic_text(
            _pending_launch_path(guard_home),
            json.dumps(pending, sort_keys=True),
        )
    return creation_time


def load_authenticated_guard_daemon_pending_launch(guard_home: Path) -> dict[str, object] | None:
    """Load one signed pending-launch PID identity from a private regular file."""

    if os.name != "nt":
        return None
    path = _pending_launch_path(guard_home)
    if not _private_daemon_file_is_valid(path):
        return None
    try:
        metadata = path.stat(follow_symlinks=False)
        if metadata.st_size <= 0 or metadata.st_size > _GUARD_DAEMON_PENDING_LAUNCH_MAX_BYTES:
            return None
        raw_payload = path.read_text(encoding="utf-8")
        payload = json.loads(raw_payload)
    except (OSError, ValueError, json.JSONDecodeError):
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
        or type(creation_time) is not int
        or creation_time <= 0
        or not isinstance(payload_guard_home, str)
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
) -> bool:
    if os.name != "nt" or creation_time is None:
        return True
    with _guard_daemon_state_write_lock(guard_home):
        pending = load_authenticated_guard_daemon_pending_launch(guard_home)
        if pending is None or pending.get("pid") != pid or pending.get("process_creation_time") != creation_time:
            return False
        _write_private_atomic_text(_pending_launch_path(guard_home), "{}")
        return True


def _clear_spawned_guard_daemon_pending_launch(
    guard_home: Path,
    *,
    process: subprocess.Popen[bytes],
    creation_time: int | None,
) -> bool:
    if creation_time is None:
        return True
    return _clear_guard_daemon_pending_launch_if_current(
        guard_home,
        pid=process.pid,
        creation_time=creation_time,
    )


def _guard_daemon_pending_launch_is_active(guard_home: Path) -> bool:
    pending = load_authenticated_guard_daemon_pending_launch(guard_home)
    if pending is None:
        return False
    pid = pending.get("pid")
    creation_time = pending.get("process_creation_time")
    if type(pid) is not int or type(creation_time) is not int:
        return False
    actual_creation_time = windows_process_creation_time(pid)
    if actual_creation_time != creation_time:
        if actual_creation_time is not None or not _guard_daemon_pid_is_running(pid):
            _clear_guard_daemon_pending_launch_if_current(
                guard_home,
                pid=pid,
                creation_time=creation_time,
            )
        return False
    return _guard_daemon_pid_is_running(pid)


def _guard_daemon_pending_launch_state_is_resolved(guard_home: Path) -> bool:
    if os.name != "nt":
        return True
    path = _pending_launch_path(guard_home)
    if not path.is_file():
        return True
    pending = load_authenticated_guard_daemon_pending_launch(guard_home)
    if pending is not None:
        if _guard_daemon_pending_launch_is_active(guard_home):
            return False
        pending = load_authenticated_guard_daemon_pending_launch(guard_home)
        if pending is not None:
            return False
    return _daemon_lifecycle_artifact_is_exact_tombstone(path)


def _auth_token_path(guard_home: Path) -> Path:
    return guard_home / "daemon-auth-token"


def _private_daemon_file_is_valid(path: Path) -> bool:
    try:
        parent_metadata = path.parent.lstat()
        metadata = path.lstat()
    except OSError:
        return False
    if not stat.S_ISDIR(parent_metadata.st_mode):
        return False
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        return False
    if os.name == "nt":
        return True
    return (
        parent_metadata.st_uid == os.getuid()
        and metadata.st_uid == os.getuid()
        and not stat.S_IMODE(parent_metadata.st_mode) & 0o077
        and not stat.S_IMODE(metadata.st_mode) & 0o077
    )


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
        os.replace(temporary_path, path)
        _set_private_mode(path, _GUARD_DAEMON_PRIVATE_FILE_MODE)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        with suppress(OSError):
            temporary_path.unlink()


def _set_private_mode(path: Path, mode: int) -> None:
    if os.name == "nt":
        return
    try:
        os.chmod(path, mode)
    except OSError:
        return


def _reap_stale_ephemeral_guard_daemons(*, exclude_guard_home: Path | None = None) -> None:
    now = time.monotonic()
    last_reap_at = globals().get("_LAST_EPHEMERAL_REAP_AT", 0.0)
    if not isinstance(last_reap_at, (int, float)):
        last_reap_at = 0.0
    if now - float(last_reap_at) < _EPHEMERAL_GUARD_DAEMON_REAP_INTERVAL_SECONDS:
        return
    globals()["_LAST_EPHEMERAL_REAP_AT"] = now
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
        state_age_seconds = _state_path_age_seconds(state_path)
        if state_age_seconds < _EPHEMERAL_GUARD_DAEMON_STALE_SECONDS:
            continue
        payload = _load_state(guard_home)
        if not _ephemeral_guard_home_is_inactive(
            guard_home,
            fallback_age_seconds=state_age_seconds,
            state_payload=payload,
        ):
            continue
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


def _ephemeral_guard_home_is_inactive(
    guard_home: Path,
    *,
    fallback_age_seconds: float,
    state_payload: dict[str, object] | None = None,
) -> bool:
    payload = state_payload if isinstance(state_payload, dict) else _load_state(guard_home)
    if isinstance(payload, dict):
        pid = payload.get("pid")
        if not isinstance(pid, int) or pid <= 0:
            return fallback_age_seconds >= _EPHEMERAL_GUARD_DAEMON_STALE_SECONDS
        if not _guard_daemon_pid_is_running(pid):
            return fallback_age_seconds >= _EPHEMERAL_GUARD_DAEMON_STALE_SECONDS
        if not _guard_daemon_pid_matches_command(pid, expected_guard_home=guard_home):
            return fallback_age_seconds >= _EPHEMERAL_GUARD_DAEMON_STALE_SECONDS
    heartbeat_age_seconds = _runtime_state_age_seconds(guard_home)
    if heartbeat_age_seconds is None:
        return fallback_age_seconds >= _EPHEMERAL_GUARD_DAEMON_STALE_SECONDS
    return heartbeat_age_seconds >= _EPHEMERAL_GUARD_DAEMON_STALE_SECONDS


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


def _spawn_bounded_process_query(command: list[str]) -> subprocess.Popen[bytes]:
    child_environment = _process_query_environment(command)
    if os.name == "nt":
        return subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
            env=child_environment,
        )
    return subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        bufsize=0,
        start_new_session=True,
        env=child_environment,
    )


def _process_query_environment(command: list[str]) -> dict[str, str]:
    """Return an environment that cannot redirect trusted process-query tools."""

    if os.name != "nt":
        return {"LANG": "C", "LC_ALL": "C"}
    if not command:
        return {}
    system_directory = ntpath.dirname(ntpath.dirname(ntpath.dirname(command[0])))
    windows_directory = ntpath.dirname(system_directory)
    return {
        "ComSpec": ntpath.join(system_directory, "cmd.exe"),
        "PATH": system_directory,
        "SystemRoot": windows_directory,
        "WINDIR": windows_directory,
    }


def _trusted_posix_ps_path() -> str | None:
    """Resolve ``ps`` only from fixed operating-system locations."""

    if os.name == "nt":
        return None
    for raw_path in _GUARD_DAEMON_POSIX_PS_PATHS:
        candidate = Path(raw_path)
        try:
            resolved = candidate.resolve(strict=True)
            metadata = resolved.stat()
        except (OSError, RuntimeError):
            continue
        if stat.S_ISREG(metadata.st_mode) and os.access(resolved, os.X_OK):
            return str(resolved)
    return None


def _trusted_windows_powershell_path() -> str | None:
    """Resolve Windows PowerShell from the kernel-reported system directory."""

    if os.name != "nt":
        return None
    try:
        powershell = trusted_windows_system_executable(
            "WindowsPowerShell",
            "v1.0",
            "powershell.exe",
        )
    except (OSError, RuntimeError, ValueError):
        return None
    return str(powershell)


def _terminate_bounded_process_query(process: subprocess.Popen[bytes]) -> None:
    if os.name == "nt":
        with suppress(OSError):
            process.terminate()
    else:
        with suppress(OSError):
            os.killpg(process.pid, signal.SIGTERM)
    with suppress(subprocess.TimeoutExpired):
        _ = process.wait(timeout=_GUARD_DAEMON_PROCESS_QUERY_TERMINATE_GRACE_SECONDS)
    if process.poll() is not None:
        return
    if os.name == "nt":
        with suppress(OSError):
            process.kill()
    else:
        with suppress(OSError):
            os.killpg(process.pid, signal.SIGKILL)
    with suppress(subprocess.TimeoutExpired):
        _ = process.wait(timeout=_GUARD_DAEMON_PROCESS_QUERY_TERMINATE_GRACE_SECONDS)


def _capture_bounded_process_query_stdout(
    stream: BinaryIO,
    captured: bytearray,
    output_limit_bytes: int,
    overflow: threading.Event,
    errors: list[OSError | ValueError],
) -> None:
    try:
        while True:
            remaining = output_limit_bytes - len(captured)
            chunk = stream.read(min(64 * 1024, remaining + 1))
            if not chunk:
                return
            if len(chunk) > remaining:
                captured.extend(chunk[:remaining])
                overflow.set()
                return
            captured.extend(chunk)
    except (OSError, ValueError) as error:
        errors.append(error)
    finally:
        with suppress(OSError, ValueError):
            stream.close()


def _bounded_process_query_stdout(
    command: list[str],
    *,
    timeout_seconds: float = _GUARD_DAEMON_PROCESS_QUERY_TIMEOUT_SECONDS,
    output_limit_bytes: int = _GUARD_DAEMON_PROCESS_QUERY_OUTPUT_LIMIT_BYTES,
) -> str | None:
    """Return bounded child stdout, or ``None`` after failure, timeout, or overflow."""

    if timeout_seconds <= 0 or output_limit_bytes < 0:
        return None
    try:
        process = _spawn_bounded_process_query(command)
    except (OSError, subprocess.SubprocessError, ValueError):
        return None
    if process.stdout is None:
        _terminate_bounded_process_query(process)
        return None

    captured = bytearray()
    overflow = threading.Event()
    errors: list[OSError | ValueError] = []
    reader = threading.Thread(
        target=_capture_bounded_process_query_stdout,
        args=(process.stdout, captured, output_limit_bytes, overflow, errors),
        name="guard-daemon-process-query",
        daemon=True,
    )
    timed_out = False
    reader_started = False
    deadline = time.monotonic() + timeout_seconds
    try:
        reader.start()
        reader_started = True
        while process.poll() is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            if overflow.wait(min(_GUARD_DAEMON_PROCESS_QUERY_MONITOR_INTERVAL_SECONDS, remaining)):
                break
        if process.poll() is not None and reader.is_alive():
            reader.join(timeout=_GUARD_DAEMON_PROCESS_QUERY_TERMINATE_GRACE_SECONDS)
    except BaseException:
        _terminate_bounded_process_query(process)
        raise
    finally:
        if timed_out or overflow.is_set() or process.poll() is None or reader.is_alive():
            _terminate_bounded_process_query(process)
        if reader_started:
            reader.join(timeout=_GUARD_DAEMON_PROCESS_QUERY_TERMINATE_GRACE_SECONDS)
            if reader.is_alive():
                with suppress(OSError, ValueError):
                    process.stdout.close()
                reader.join(timeout=_GUARD_DAEMON_PROCESS_QUERY_TERMINATE_GRACE_SECONDS)

    if timed_out or overflow.is_set() or errors or reader.is_alive():
        return None
    try:
        returncode = process.wait(timeout=_GUARD_DAEMON_PROCESS_QUERY_TERMINATE_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        _terminate_bounded_process_query(process)
        return None
    if returncode != 0:
        return None
    try:
        return bytes(captured).decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None


def _running_ephemeral_guard_daemon_processes() -> list[tuple[int, Path, float]]:
    if os.name == "nt":
        return []
    ps_path = _trusted_posix_ps_path()
    if ps_path is None:
        return []
    output = _bounded_process_query_stdout([ps_path, "-axo", "pid=,etime=,command="])
    if output is None:
        return []
    processes: list[tuple[int, Path, float]] = []
    for line in output.splitlines():
        match = re.match(r"^\s*(\d+)\s+(\S+)\s+(.*)$", line)
        if match is None:
            continue
        pid = int(match.group(1))
        elapsed_seconds = _elapsed_seconds_from_ps(match.group(2))
        command = match.group(3).strip()
        if not _guard_daemon_command_matches(command):
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
    parts = _split_process_command(command)
    if parts is None:
        return None
    return _guard_home_from_command_parts(parts)


def _guard_home_from_command_parts(parts: list[str]) -> Path | None:
    for index, part in enumerate(parts):
        if part == "--guard-home" and index + 1 < len(parts):
            return Path(parts[index + 1])
    return None


def _guard_daemon_port_from_command(command: str) -> int | None:
    parts = _split_process_command(command)
    if parts is None:
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


def _guard_daemon_command_matches(command: str) -> bool:
    parts = _split_process_command(command)
    if parts is None:
        return False
    return _guard_daemon_command_parts_match(parts)


def _split_process_command(command: str) -> list[str] | None:
    if os.name == "nt":
        return windows_command_line_to_argv(command)
    try:
        return shlex.split(command)
    except ValueError:
        return None


def _guard_daemon_command_parts_match(parts: list[str]) -> bool:
    for index in range(len(parts) - 1):
        prefix = parts[:index]
        if parts[index : index + 2] == ["daemon", "--serve"]:
            if any(part == "codex_plugin_scanner.cli" for part in prefix):
                return True
            if index > 0:
                launcher_name = ntpath.basename(parts[index - 1]).lower()
                if launcher_name in {
                    "hol-guard",
                    "hol-guard.exe",
                    "plugin-guard",
                    "plugin-guard.exe",
                }:
                    return True
            continue
        if parts[index : index + 3] != ["guard", "daemon", "--serve"]:
            continue
        if any(part == "codex_plugin_scanner.cli" for part in prefix):
            return True
        if index == 0:
            continue
        launcher_name = ntpath.basename(parts[index - 1]).lower()
        if launcher_name in {
            "hol-guard",
            "hol-guard.exe",
            "plugin-guard",
            "plugin-guard.exe",
        }:
            return True
    return False


def _guard_daemon_process_inventory_for_guard_home(guard_home: Path) -> list[tuple[int, int]] | None:
    """Return a proven process inventory, or ``None`` when enumeration is unknown."""

    if os.name == "nt":
        powershell_path = _trusted_windows_powershell_path()
        if powershell_path is None:
            return None
        command = [
            powershell_path,
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            (
                "$ErrorActionPreference = 'Stop'; "
                "$utf8 = New-Object System.Text.UTF8Encoding($false); "
                "[Console]::OutputEncoding = $utf8; $OutputEncoding = $utf8; "
                "$items = @(Get-CimInstance Win32_Process | Select-Object ProcessId,CommandLine); "
                "ConvertTo-Json -Compress -InputObject $items"
            ),
        ]
        output = _bounded_process_query_stdout(command)
        if output is None:
            return None
        try:
            raw_entries: object = json.loads(output)
        except json.JSONDecodeError:
            return None
        if not isinstance(raw_entries, list):
            return None
        entries: list[tuple[int, str]] = []
        for entry in raw_entries:
            if not isinstance(entry, dict):
                return None
            pid = entry.get("ProcessId")
            command_line = entry.get("CommandLine")
            if type(pid) is not int or pid < 0 or (command_line is not None and not isinstance(command_line, str)):
                return None
            if pid == 0:
                continue
            if isinstance(command_line, str) and command_line.strip():
                entries.append((pid, command_line.strip()))
    else:
        ps_path = _trusted_posix_ps_path()
        if ps_path is None:
            return None
        output = _bounded_process_query_stdout([ps_path, "-axo", "pid=,command="])
        if output is None:
            return None
        entries = []
        for line in output.splitlines():
            match = re.match(r"^\s*(\d+)\s+(.*)$", line)
            if match is None:
                continue
            entries.append((int(match.group(1)), match.group(2).strip()))

    processes: list[tuple[int, int]] = []
    for pid, command_line in entries:
        parts = _split_process_command(command_line)
        if parts is None:
            lowered = command_line.lower()
            if "codex_plugin_scanner" in lowered or "guard" in lowered:
                return None
            continue
        if not _guard_daemon_command_parts_match(parts):
            continue
        command_guard_home = _guard_home_from_command_parts(parts)
        port = _guard_daemon_port_from_command(command_line)
        if command_guard_home is None or port is None:
            return None
        try:
            matches_home = command_guard_home.resolve() == guard_home.resolve()
        except OSError:
            matches_home = command_guard_home == guard_home
        if matches_home:
            processes.append((pid, port))
    return sorted(processes, key=lambda item: item[1])


def _running_guard_daemon_processes_for_guard_home(guard_home: Path) -> list[tuple[int, int]]:
    inventory = _guard_daemon_process_inventory_for_guard_home(guard_home)
    return inventory if inventory is not None else []


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
    global _runtime_fingerprint_cache
    if _runtime_fingerprint_cache is not None:
        return _runtime_fingerprint_cache
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
    _runtime_fingerprint_cache = digest.hexdigest()
    return _runtime_fingerprint_cache


def current_guard_daemon_runtime_fingerprint() -> str:
    """Return the installed runtime identity used for daemon compatibility."""

    return _current_guard_daemon_runtime_fingerprint()


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


def _guard_daemon_pid_is_proven_dead(pid: int) -> bool:
    if os.name == "nt":
        return windows_process_liveness(pid) is False
    return not _guard_daemon_pid_is_running(pid)


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
    parts = _split_process_command(command)
    if parts is None:
        return None
    if not _guard_daemon_command_parts_match(parts):
        return False
    if expected_guard_home is None:
        return True
    command_guard_home = _guard_home_from_command_parts(parts)
    if command_guard_home is None:
        return None
    try:
        return command_guard_home.resolve() == expected_guard_home.resolve()
    except OSError:
        return command_guard_home == expected_guard_home


def _guard_daemon_command_for_pid(pid: int) -> str | None:
    if os.name == "nt":
        powershell_path = _trusted_windows_powershell_path()
        if powershell_path is None:
            return None
        command = [
            powershell_path,
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            (
                "$utf8 = New-Object System.Text.UTF8Encoding($false); "
                "[Console]::OutputEncoding = $utf8; $OutputEncoding = $utf8; "
                f'(Get-CimInstance Win32_Process -Filter "ProcessId = {pid}").CommandLine'
            ),
        ]
    else:
        ps_path = _trusted_posix_ps_path()
        if ps_path is None:
            return None
        command = [ps_path, "-p", str(pid), "-o", "command="]
    output = _bounded_process_query_stdout(command)
    if output is None:
        return None
    stdout = output.strip()
    return stdout or None


def _retire_guard_daemon_process(payload: dict[str, object]) -> bool:
    pid = payload.get("pid")
    if not isinstance(pid, int) or pid <= 0:
        return False
    guard_home = payload.get("guard_home")
    expected_guard_home = Path(guard_home) if isinstance(guard_home, str) and guard_home.strip() else None
    return _retire_guard_daemon_pid(pid, expected_guard_home=expected_guard_home)


def _terminate_spawned_guard_daemon(process: subprocess.Popen[bytes]) -> bool:
    """Terminate and reap the exact child handle after startup fails."""

    process_stdin = getattr(process, "stdin", None)
    if process_stdin is not None:
        with suppress(OSError, ValueError):
            process_stdin.close()
    if process.poll() is not None:
        return True
    with suppress(OSError):
        process.terminate()
    try:
        process.wait(timeout=1.0)
    except subprocess.TimeoutExpired:
        with suppress(OSError):
            process.kill()
        try:
            process.wait(timeout=1.0)
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


def _retire_guard_daemon_pid(
    pid: int,
    *,
    expected_guard_home: Path | None = None,
    expected_creation_time: int | None = None,
) -> bool:
    if _guard_daemon_pid_is_proven_dead(pid):
        return True
    if os.name == "nt" and expected_creation_time is not None:
        return windows_terminate_process_if_creation_time(pid, expected_creation_time)
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
        return windows_terminate_process_if_creation_time(pid, observed_creation_time)
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


def _prepend_preferred_port(ports: list[int], preferred_port: int | None) -> list[int]:
    if not isinstance(preferred_port, int) or preferred_port <= 0:
        return ports
    ordered: list[int] = [preferred_port]
    seen = {preferred_port}
    for port in ports:
        if port in seen:
            continue
        seen.add(port)
        ordered.append(port)
    return ordered


def _candidate_ports(guard_home: Path, *, preferred_port: int | None = None) -> list[int]:
    configured_port = _configured_port(guard_home)
    if configured_port is None:
        return _prepend_preferred_port([], preferred_port)
    raw_port = os.environ.get("GUARD_DAEMON_PORT")
    if raw_port is not None and raw_port.strip():
        return _prepend_preferred_port([configured_port], preferred_port)
    offset = configured_port - DEFAULT_GUARD_DAEMON_PORT
    ports: list[int] = []
    for step in range(min(25, GUARD_DAEMON_PORT_RANGE)):
        candidate_offset = (offset + step) % GUARD_DAEMON_PORT_RANGE
        ports.append(DEFAULT_GUARD_DAEMON_PORT + candidate_offset)
    return _prepend_preferred_port(ports, preferred_port)


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
