"""Minimal launcher for the package-bound Rust resident client.

Python supplies only the verified binary path, private Guard state root, bounded
bytes, and deadline. Rust owns discovery, authentication, framing, restart,
generation state, response binding, and resident lifecycle.
"""

from __future__ import annotations

import atexit
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
_LAST_FAILURE_CODE: ContextVar[str | None] = ContextVar(
    "native_resident_client_failure_code",
    default=None,
)
_RESIDENTS_LOCK = threading.Lock()
_RESIDENTS: dict[tuple[Path, Path], Mapping[str, str]] = {}


def native_resident_client_failure_code() -> str | None:
    """Return the current context's privacy-safe native failure code."""
    return _LAST_FAILURE_CODE.get()


def record_native_resident_client_failure_code(code: str) -> None:
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
        self._idle: list[_PersistentNativeClient] = []
        self._condition = threading.Condition()
        self._closed = False

    def _lease(self, *, deadline_monotonic: float) -> _PersistentNativeClient | None:
        with self._condition:
            while not self._closed:
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
                self._condition.wait(timeout=remaining)
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
                    self._clients.remove(client)
                    close_client = True
                else:
                    self._idle.append(client)
                self._condition.notify()
            if close_client:
                client.close()

    def close(self) -> None:
        with self._condition:
            self._closed = True
            clients = tuple(self._clients)
            self._clients.clear()
            self._idle.clear()
            self._condition.notify_all()
        for client in clients:
            client.close()
        for client in clients:
            _contain_persistent_resident(client)


_CLIENTS_LOCK = threading.Lock()
_CLIENT_POOLS: dict[tuple[str, str], _PersistentNativeClientPool] = {}


def _client_pool_for(executable: Path, state_dir: Path, environment: Mapping[str, str]) -> _PersistentNativeClientPool:
    normalized_state_dir = state_dir.expanduser().resolve()
    key = (str(executable), str(normalized_state_dir))
    evicted: _PersistentNativeClientPool | None = None
    with _CLIENTS_LOCK:
        pool = _CLIENT_POOLS.get(key)
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
    return pool


def _state_files(state_dir: Path) -> tuple[Path, ...]:
    try:
        return tuple(state_dir.glob("resident-v3-*/generation-*.json"))
    except (OSError, RuntimeError):
        return ()


def _has_client_for_state(state_dir: Path) -> bool:
    state_key = str(state_dir)
    with _CLIENTS_LOCK:
        return any(key[1] == state_key for key in _CLIENT_POOLS)


def _contain_persistent_resident(client: _PersistentNativeClient) -> None:
    """Authenticate shutdown after stream close, then await state retirement.

    A different executable may have adopted the same Guard-home resident. In
    that case its persistent client remains the owner of the shared service,
    so this client only closes its own stream and does not send shutdown.
    """
    state_files = _state_files(client._state_dir)
    if not state_files or _has_client_for_state(client._state_dir):
        return
    stop_native_resident(
        executable=client._executable,
        state_dir=client._state_dir,
        environment=client._environment,
        timeout_seconds=0.5,
    )
    deadline = time.monotonic() + 2.5
    while _state_files(client._state_dir) and time.monotonic() < deadline:
        time.sleep(0.025)


def close_native_resident_clients(guard_home: Path | None = None) -> None:
    """Close persistent Rust clients, optionally limited to one Guard home."""

    resolved_guard_home = guard_home.expanduser().resolve() if guard_home is not None else None

    with _CLIENTS_LOCK:
        selected = [
            (key, pool)
            for key, pool in _CLIENT_POOLS.items()
            if resolved_guard_home is None or Path(key[1]).parent == resolved_guard_home
        ]
        for key, _pool in selected:
            _CLIENT_POOLS.pop(key, None)
    for _key, pool in selected:
        pool.close()


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
) -> bool:
    """Stop one Rust-managed resident and wait for its state retirement."""
    result = run_isolated_hook_process(
        (str(executable), "resident-stop", "--state-dir", str(state_dir)),
        input_text="",
        cwd=executable.parent,
        environment=dict(environment),
        timeout_seconds=timeout_seconds,
        output_limit=_MAX_RESPONSE_BYTES,
    )
    return (
        result.returncode == 0
        and not result.timed_out
        and not result.containment_failed
        and not _state_files(state_dir)
    )


def close_native_residents() -> None:
    """Stop Rust-managed residents created by this Python process."""
    close_native_resident_clients()
    with _RESIDENTS_LOCK:
        residents = list(_RESIDENTS.items())
    remaining: dict[tuple[Path, Path], Mapping[str, str]] = {}
    for (executable, state_dir), environment in residents:
        if _state_files(state_dir) and not stop_native_resident(
            executable=executable,
            state_dir=state_dir,
            environment=environment,
        ):
            remaining[(executable, state_dir)] = environment
    with _RESIDENTS_LOCK:
        _RESIDENTS.clear()
        _RESIDENTS.update(remaining)


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
    "native_resident_client_request",
    "record_native_resident_client_failure_code",
    "stop_native_resident",
]
