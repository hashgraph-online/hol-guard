"""Minimal launcher for the package-bound Rust resident client.

Python supplies only the verified binary path, private Guard state root, bounded
bytes, and deadline. Rust owns discovery, authentication, framing, restart,
generation state, response binding, and resident lifecycle.
"""

from __future__ import annotations

import atexit
import contextlib
import os
import threading
import time
from collections.abc import Mapping
from contextvars import ContextVar
from pathlib import Path

from .codex_hook_launch_runtime import (
    BoundedHookProcessResult,
)
from .codex_hook_launch_runtime import (
    run_isolated_hook_process as _legacy_run_isolated_hook_process,
)
from .fork_safety import forget_in_child
from .native_approval_errors import NATIVE_RESIDENT_LIFECYCLE_ERROR_CODES
from .native_resident_stream import _PersistentNativeClient, _StreamFailure

# Retain the old runner name as a test seam. Production always leaves this
# binding untouched and uses the persistent Rust client below.
run_isolated_hook_process = _legacy_run_isolated_hook_process

_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_MAX_REQUEST_BYTES = 6 * 1024 * 1024
_MAX_PERSISTENT_CLIENTS = 16
_MAX_PERSISTENT_POOLS = 16
_MAX_FAILURE_CODE_LENGTH = 128
# Shared bounds for probes that must confirm native resident cleanup.
NATIVE_RESIDENT_CLEANUP_TIMEOUT_SECONDS = 10.0
NATIVE_RESIDENT_CLEANUP_RETRY_INTERVAL_SECONDS = 0.25
_LAST_FAILURE_CODE: ContextVar[str | None] = ContextVar(
    "native_resident_client_failure_code",
    default=None,
)
_RESIDENTS_LOCK = threading.Lock()
_RESIDENTS: dict[tuple[Path, Path], Mapping[str, str]] = {}
forget_in_child(_RESIDENTS)


def native_resident_client_failure_code() -> str | None:
    """Return the current context's privacy-safe native failure code."""
    return _LAST_FAILURE_CODE.get()


def record_native_resident_client_failure_code(code: str | None) -> None:
    """Record a privacy-safe failure code for the current native client request."""
    _LAST_FAILURE_CODE.set(code)


def _allowlisted_failure_code(stderr: str) -> str | None:
    for line in stderr.splitlines():
        if len(line) <= _MAX_FAILURE_CODE_LENGTH and line in NATIVE_RESIDENT_LIFECYCLE_ERROR_CODES:
            return line
    return None


def _classify_failure(result: BoundedHookProcessResult) -> str:
    if result.containment_failed:
        return "native_client_containment_failed"
    if result.timed_out:
        return "native_client_timed_out"
    if result.output_limit_exceeded:
        return "native_client_output_limit_exceeded"
    if result.returncode is None:
        return "native_client_status_missing"
    if result.returncode != 0:
        return "native_client_exit_nonzero"
    if not result.stdout:
        return "native_client_output_missing"
    return "native_client_process_failed"


def _record_failure_code(result: BoundedHookProcessResult) -> None:
    _LAST_FAILURE_CODE.set(_allowlisted_failure_code(result.stderr) or _classify_failure(result))


class _PersistentNativeClientPool:
    """Bounded lazy pool of streams for one executable and Guard state root.

    A stream carries one request at a time because its response frames have no
    request identifier. Multiple persistent streams therefore provide bounded
    parallel dispatch without changing the authenticated wire protocol.
    """

    def __init__(self, *, executable: Path, state_dir: Path, environment: Mapping[str, str]) -> None:
        self._executable = executable
        self._state_dir = state_dir
        self._environment = environment
        self._clients: set[_PersistentNativeClient] = set()
        self._retiring: set[_PersistentNativeClient] = set()
        self._idle: list[_PersistentNativeClient] = []
        self._condition = threading.Condition()
        self._closed = False

    def has_idle_client(self) -> bool:
        """True when a live client is parked and can serve without a spawn."""

        with self._condition:
            if self._closed:
                return False
            return any(client._process is not None and client._process.poll() is None for client in self._idle)

    def _lease(self, *, deadline_monotonic: float) -> _PersistentNativeClient | None:
        with self._condition:
            while not self._closed:
                # Timed-out requests may have no teardown budget left. Retain
                # ownership until close confirms containment, but reclaim
                # completed retirees instead of permanently exhausting slots.
                for retiring in tuple(self._retiring):
                    if retiring.close(deadline_monotonic=time.monotonic()):
                        self._retiring.discard(retiring)
                        self._clients.discard(retiring)
                if self._idle:
                    return self._idle.pop()
                if len(self._clients) < _MAX_PERSISTENT_CLIENTS:
                    client = _PersistentNativeClient(
                        executable=self._executable,
                        state_dir=self._state_dir,
                        environment=self._environment,
                        failure_recorder=_LAST_FAILURE_CODE.set,
                    )
                    self._clients.add(client)
                    return client
                remaining = deadline_monotonic - time.monotonic()
                if remaining <= 0:
                    break
                self._condition.wait(timeout=min(remaining, 0.05) if self._retiring else remaining)
        _LAST_FAILURE_CODE.set("native_client_pool_exhausted")
        return None

    def request(self, payload: bytes, *, deadline_monotonic: float) -> bytes | None:
        client = self._lease(deadline_monotonic=deadline_monotonic)
        if client is None:
            return None
        response: bytes | None = None
        try:
            response = client.request(payload, deadline_monotonic=deadline_monotonic)
            return response
        finally:
            close_client = False
            with self._condition:
                if client not in self._clients:
                    close_client = True
                elif self._closed or response is None:
                    self._retiring.add(client)
                    close_client = True
                else:
                    self._idle.append(client)
                self._condition.notify()
            if close_client:
                try:
                    contained = client.close(deadline_monotonic=deadline_monotonic)
                except BaseException:
                    with self._condition:
                        if client in self._clients:
                            self._retiring.add(client)
                    raise
                if contained is not False:
                    with self._condition:
                        self._clients.discard(client)
                        self._retiring.discard(client)
                        self._condition.notify_all()

    def close(self, *, deadline_monotonic: float | None = None) -> bool:
        with self._condition:
            self._closed = True
            clients = tuple(self._clients)
            self._idle.clear()
            self._condition.notify_all()
        for client in clients:
            contained = (
                client.close() if deadline_monotonic is None else client.close(deadline_monotonic=deadline_monotonic)
            )
            if contained is not False:
                with self._condition:
                    self._clients.discard(client)
                    self._retiring.discard(client)
        for client in clients:
            _contain_persistent_resident(client)
        with self._condition:
            return not self._clients


_CLIENTS_LOCK = threading.Lock()
_CLIENT_POOLS: dict[tuple[str, str], _PersistentNativeClientPool] = {}
forget_in_child(_CLIENT_POOLS)


def native_resident_client_ready(executable: Path, guard_home: Path) -> bool:
    """True when a pooled resident for this runtime and home needs no spawn.

    Callers that budget a request tightly have to know whether the cost they
    are bounding is a round trip or a process spawn: the pool starts a client
    lazily, and a resident that a test or an operator killed leaves no idle
    client behind.
    """

    key = (str(executable), str(_pinned_state_dir(guard_home / "native-runtime")))
    with _CLIENTS_LOCK:
        pool = _CLIENT_POOLS.get(key)
    return pool is not None and pool.has_idle_client()


def _client_pool_for(executable: Path, state_dir: Path, environment: Mapping[str, str]) -> _PersistentNativeClientPool:
    normalized_state_dir = _pinned_state_dir(state_dir)
    key = (str(executable), str(normalized_state_dir))
    evicted: _PersistentNativeClientPool | None = None
    with _CLIENTS_LOCK:
        pool = _CLIENT_POOLS.get(key)
        if pool is None:
            forms = _directory_forms(normalized_state_dir)
            for old_key in list(_CLIENT_POOLS):
                if old_key[0] == key[0] and _directory_forms(Path(old_key[1])) & forms:
                    evicted = _CLIENT_POOLS.pop(old_key)
                    break
        if pool is None:
            if len(_CLIENT_POOLS) >= _MAX_PERSISTENT_POOLS:
                evicted_key = next(iter(_CLIENT_POOLS))
                evicted = _CLIENT_POOLS.pop(evicted_key)
            pool = _PersistentNativeClientPool(
                executable=executable,
                state_dir=normalized_state_dir,
                environment=environment,
            )
            _CLIENT_POOLS[key] = pool
    if evicted is not None:
        evicted.close()
    _track_resident(executable, normalized_state_dir, environment)
    return pool


def _is_directory(path: Path) -> bool:
    try:
        return path.is_dir()
    except OSError:
        return False


def _pinned_state_dir(state_dir: Path) -> Path:
    """Pin a runtime directory that exists.

    ``Path.resolve`` of a missing directory is not a stable Windows identity.
    A settings write can start a resident before publication creates
    ``native-runtime`` at its absolute spelling. Caching that guess makes the
    later bind report a missing private ancestor for a directory that exists.
    """

    candidate = state_dir.expanduser()
    if _is_directory(candidate):
        return candidate.resolve()
    absolute = Path(os.path.abspath(candidate))
    if _is_directory(absolute):
        try:
            resolved = absolute.resolve()
        except OSError:
            return absolute
        return resolved if _is_directory(resolved) else absolute
    return absolute


def _directory_forms(path: Path) -> set[str]:
    forms = {str(path), os.path.abspath(path)}
    if _is_directory(path):
        with contextlib.suppress(OSError):
            forms.add(str(path.expanduser().resolve()))
    return {os.path.normcase(form) for form in forms}


def _state_dir_in_guard_home(state_dir: Path, guard_home: Path) -> bool:
    return bool(_directory_forms(state_dir.parent) & _directory_forms(guard_home))


def _state_files(state_dir: Path, *, strict: bool = False) -> tuple[Path, ...]:
    try:
        return tuple(state_dir.glob("resident-v3-*/generation-*.json"))
    except (OSError, RuntimeError):
        if strict:
            raise
        return ()


def _contain_persistent_resident(client: _PersistentNativeClient) -> None:
    """Close one local stream without stopping the shared resident.

    Hook processes and the local daemon share one managed resident. A one-shot
    client exit that sends ``resident-stop`` kills in-flight reviews in other
    processes. Explicit shutdown stays on ``close_native_residents``.
    """
    _ = client


def close_native_resident_clients(guard_home: Path | None = None, *, deadline_monotonic: float | None = None) -> bool:
    """Close persistent Rust clients, optionally limited to one Guard home."""

    resolved_guard_home = guard_home.expanduser().resolve() if guard_home is not None else None

    with _CLIENTS_LOCK:
        selected = [
            (key, pool)
            for key, pool in _CLIENT_POOLS.items()
            if resolved_guard_home is None or _state_dir_in_guard_home(Path(key[1]), resolved_guard_home)
        ]
    first_error: Exception | None = None
    all_contained = True
    for key, pool in selected:
        try:
            contained = (
                pool.close() if deadline_monotonic is None else pool.close(deadline_monotonic=deadline_monotonic)
            )
            if contained is False:
                all_contained = False
            else:
                with _CLIENTS_LOCK:
                    if _CLIENT_POOLS.get(key) is pool:
                        _CLIENT_POOLS.pop(key)
        except Exception as error:
            if first_error is None:
                first_error = error
    if first_error is not None:
        raise first_error
    return all_contained


atexit.register(close_native_resident_clients)


def _track_resident(executable: Path, state_dir: Path, environment: Mapping[str, str]) -> None:
    if not state_dir.is_dir():
        return
    with _RESIDENTS_LOCK:
        _RESIDENTS[(executable, state_dir)] = dict(environment)


def stop_native_resident(
    *,
    executable: Path,
    state_dir: Path,
    environment: Mapping[str, str],
    timeout_seconds: float = 3.0,
    retire_clients: bool = False,
    deadline_monotonic: float | None = None,
) -> bool:
    """Stop one Rust-managed resident and wait for its state retirement."""
    command = [str(executable), "resident-stop", "--state-dir", str(state_dir)]
    if retire_clients:
        command.append("--retire-clients")
    result = run_isolated_hook_process(
        tuple(command),
        input_text="",
        cwd=executable.parent,
        environment=dict(environment),
        timeout_seconds=timeout_seconds,
        deadline_monotonic=deadline_monotonic,
        output_limit=_MAX_RESPONSE_BYTES,
    )
    if result.timed_out or result.containment_failed:
        return False
    try:
        state_files = _state_files(state_dir, strict=True)
    except (OSError, RuntimeError):
        return False
    if result.returncode == 0:
        return not state_files
    # Rust uses this authenticated, idempotent result when no resident state
    # exists. Update retirement also inspects leases, so accept it only after
    # the strict final state scan and only for the update-only command.
    return (
        retire_clients
        and result.returncode == 2
        and result.stderr.strip() == "native_resident_stop_unavailable"
        and not state_files
    )


def retire_native_resident_for_update(
    *,
    executable: Path,
    guard_home: Path,
    environment: Mapping[str, str],
    timeout_seconds: float = 3.0,
) -> bool:
    """Retire any resident before its executable can be replaced in place.

    The resident registry is process-local, so an updater may need to retire a
    resident started by another Guard process. State discovery stays bounded to
    this Guard home, while shutdown still goes through the authenticated Rust
    command and its PID/start-marker/runtime-digest checks.
    """

    resolved_guard_home = guard_home.expanduser().resolve()
    state_dir = resolved_guard_home / "native-runtime"
    try:
        close_native_resident_clients(resolved_guard_home)
        _ = _state_files(state_dir, strict=True)
        return stop_native_resident(
            executable=executable,
            state_dir=state_dir,
            environment=environment,
            timeout_seconds=timeout_seconds,
            retire_clients=True,
        )
    except (OSError, RuntimeError, ValueError):
        return False


def close_native_residents(guard_home: Path | None = None, *, deadline_monotonic: float | None = None) -> bool:
    """Stop this process's residents, optionally limited to one Guard home."""

    resolved_guard_home = guard_home.expanduser().resolve() if guard_home is not None else None
    clients_contained = close_native_resident_clients(guard_home, deadline_monotonic=deadline_monotonic)
    with _RESIDENTS_LOCK:
        residents = [
            (key, environment)
            for key, environment in _RESIDENTS.items()
            if resolved_guard_home is None or _state_dir_in_guard_home(key[1], resolved_guard_home)
        ]
        remaining = {
            key: environment
            for key, environment in _RESIDENTS.items()
            if resolved_guard_home is not None and not _state_dir_in_guard_home(key[1], resolved_guard_home)
        }
    all_contained = clients_contained is not False
    for (executable, state_dir), environment in residents:
        if not _state_files(state_dir):
            continue
        remaining_seconds = 3.0 if deadline_monotonic is None else min(3.0, deadline_monotonic - time.monotonic())
        stopped = remaining_seconds > 0 and stop_native_resident(
            executable=executable,
            state_dir=state_dir,
            environment=environment,
            timeout_seconds=remaining_seconds,
            deadline_monotonic=deadline_monotonic,
        )
        if not stopped:
            remaining[(executable, state_dir)] = environment
            all_contained = False
    with _RESIDENTS_LOCK:
        for key, _environment in residents:
            _RESIDENTS.pop(key, None)
        _RESIDENTS.update(remaining)
    return all_contained


def _legacy_native_resident_client_request(
    *,
    executable: Path,
    guard_home: Path,
    environment: Mapping[str, str],
    payload: bytes,
    timeout_seconds: float | None,
    raw_hook_envelope: bool,
    deadline_monotonic: float | None,
) -> bytes | None:
    """Exercise the former one-shot seam for isolated unit-test fakes only."""
    try:
        input_text = payload.decode("utf-8")
    except UnicodeDecodeError:
        _LAST_FAILURE_CODE.set("native_client_request_invalid")
        return None
    state_dir = guard_home / "native-runtime"
    command = "hook-client" if raw_hook_envelope else "resident-client"
    try:
        if deadline_monotonic is not None:
            result = run_isolated_hook_process(
                (str(executable), command, "--stdin", str(state_dir)),
                input_text=input_text,
                cwd=executable.parent,
                environment=dict(environment),
                timeout_seconds=None,
                deadline_monotonic=deadline_monotonic,
                output_limit=_MAX_RESPONSE_BYTES,
                windows_kill_on_job_close=False,
            )
        else:
            assert timeout_seconds is not None
            result = run_isolated_hook_process(
                (str(executable), command, "--stdin", str(state_dir)),
                input_text=input_text,
                cwd=executable.parent,
                environment=dict(environment),
                timeout_seconds=timeout_seconds,
                output_limit=_MAX_RESPONSE_BYTES,
                windows_kill_on_job_close=False,
            )
    except (OSError, RuntimeError, ValueError):
        _LAST_FAILURE_CODE.set("native_client_launcher_failed")
        return None
    if (
        result.returncode != 0
        or result.timed_out
        or result.output_limit_exceeded
        or result.containment_failed
        or not result.stdout
    ):
        _record_failure_code(result)
        return None
    _track_resident(executable=executable, state_dir=state_dir, environment=environment)
    return result.stdout.encode("utf-8")


def native_resident_client_transport() -> str:
    """Which transport the next request takes: ``"pool"`` or the legacy seam."""

    return "legacy" if run_isolated_hook_process is not _legacy_run_isolated_hook_process else "pool"


def native_resident_client_request(
    *,
    executable: Path,
    guard_home: Path,
    environment: Mapping[str, str],
    payload: bytes,
    timeout_seconds: float | None = None,
    raw_hook_envelope: bool = False,
    deadline_monotonic: float | None = None,
) -> bytes | None:
    """Send bounded bytes through a persistent Rust client stream."""
    _LAST_FAILURE_CODE.set(None)
    if not payload or (deadline_monotonic is None and (timeout_seconds is None or timeout_seconds <= 0)):
        _LAST_FAILURE_CODE.set("native_client_request_invalid")
        return None
    if len(payload) > _MAX_REQUEST_BYTES:
        _LAST_FAILURE_CODE.set("native_client_request_invalid")
        return None
    if run_isolated_hook_process is not _legacy_run_isolated_hook_process:
        return _legacy_native_resident_client_request(
            executable=executable,
            guard_home=guard_home,
            environment=environment,
            payload=payload,
            timeout_seconds=timeout_seconds,
            raw_hook_envelope=raw_hook_envelope,
            deadline_monotonic=deadline_monotonic,
        )
    try:
        payload.decode("utf-8")
    except UnicodeDecodeError:
        _LAST_FAILURE_CODE.set("native_client_request_invalid")
        return None
    del raw_hook_envelope
    deadline = deadline_monotonic
    if deadline is None:
        assert timeout_seconds is not None
        deadline = time.monotonic() + timeout_seconds
    return _client_pool_for(executable, guard_home / "native-runtime", environment).request(
        payload,
        deadline_monotonic=deadline,
    )


__all__ = [
    "_PersistentNativeClient",
    "_StreamFailure",
    "close_native_resident_clients",
    "close_native_residents",
    "native_resident_client_failure_code",
    "native_resident_client_ready",
    "native_resident_client_request",
    "native_resident_client_transport",
    "record_native_resident_client_failure_code",
    "retire_native_resident_for_update",
    "stop_native_resident",
]
