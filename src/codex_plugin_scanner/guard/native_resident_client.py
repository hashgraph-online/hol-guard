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
from functools import partial
from pathlib import Path

from .codex_hook_launch_runtime import run_isolated_hook_process
from .fork_safety import forget_in_child
from .native_approval_errors import FINITE_FAILURE_CODES
from .native_resident_client_pool import (
    _LAST_FAILURE_CODE,
    _LAST_HOLD_KEY,
    _PersistentNativeClientPool,
)
from .native_resident_revival import HoldKey
from .native_resident_stream import _PersistentNativeClient, _StreamFailure
from .path_resolution_cache import cached_realpath

_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_MAX_REQUEST_BYTES = 6 * 1024 * 1024
_MAX_PERSISTENT_POOLS = 16
_MAX_FAILURE_CODE_LENGTH = 128
# Shared bounds for probes that must confirm native resident cleanup.
NATIVE_RESIDENT_CLEANUP_TIMEOUT_SECONDS = 10.0
NATIVE_RESIDENT_CLEANUP_RETRY_INTERVAL_SECONDS = 0.25
_RESIDENTS_LOCK = threading.Lock()
_RESIDENTS: dict[tuple[Path, Path], Mapping[str, str]] = {}
forget_in_child(_RESIDENTS)


def native_resident_client_failure_code() -> str | None:
    """Return the current context's privacy-safe native failure code."""
    return _LAST_FAILURE_CODE.get()


def native_resident_client_failure_hold_key() -> HoldKey | None:
    """Return the hold key behind the current context's restart refusal."""
    return _LAST_HOLD_KEY.get()


def record_native_resident_client_failure_code(code: str | None) -> None:
    """Record a privacy-safe failure code for the current native client request."""
    _LAST_FAILURE_CODE.set(code)


def record_native_resident_client_failure_hold_key(key: HoldKey | None) -> None:
    """Record the restart hold the current native client request was refused under."""
    _LAST_HOLD_KEY.set(key)


def record_native_resident_error_frame(decoded: Mapping[str, object]) -> None:
    """Keep the code from a framed resident refusal such as ``{"error": code}``.

    The client stream answers a failed resident round trip with a framed error instead of exiting, so
    the transport succeeds and the code would otherwise be dropped as an unexpected schema.
    """
    code = decoded.get("error")
    if isinstance(code, str) and len(code) <= _MAX_FAILURE_CODE_LENGTH and code in FINITE_FAILURE_CODES:
        _LAST_FAILURE_CODE.set(code)


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


def native_resident_guard_home_containing(executable: Path, paths: tuple[Path, ...]) -> Path | None:
    """The Guard home of a resident this process already talks to that holds every path.

    Only homes with a client pool for `executable` count, and the lookup
    starts nothing; a caller with no pool of its own for the home keeps its
    own route.
    """

    with _CLIENTS_LOCK:
        state_dirs = [Path(state_dir) for runtime, state_dir in _CLIENT_POOLS if runtime == str(executable)]
    for state_dir in state_dirs:
        if native_resident_home_holds(state_dir.parent, paths):
            return state_dir.parent
    return None


def native_resident_home_holds(guard_home: Path, paths: tuple[Path, ...]) -> bool:
    """Whether every path is ``guard_home`` itself or inside it."""

    home = os.path.normcase(os.path.abspath(guard_home)).rstrip("\\/")
    targets = [os.path.normcase(os.path.abspath(path)) for path in paths]
    return all(target == home or target.startswith(home + os.sep) for target in targets)


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
        return Path(cached_realpath(os.fspath(candidate)))
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


def tracked_native_resident_state_dirs(guard_home: Path) -> tuple[Path, ...]:
    """State roots of residents this process has used for ``guard_home`` and not stopped."""

    resolved = guard_home.expanduser().resolve()
    with _RESIDENTS_LOCK:
        return tuple(
            state_dir for (_executable, state_dir) in _RESIDENTS if _state_dir_in_guard_home(state_dir, resolved)
        )


def resident_state_files(state_dir: Path) -> tuple[Path, ...]:
    """Published resident generation files under one native state root."""

    return _state_files(state_dir)


def stop_native_resident(
    *,
    executable: Path,
    state_dir: Path,
    environment: Mapping[str, str],
    timeout_seconds: float = 3.0,
    retire_clients: bool = False,
    install_lock_home: Path | None = None,
    deadline_monotonic: float | None = None,
) -> bool:
    """Stop one Rust-managed resident and wait for its state retirement.

    With ``install_lock_home`` the Rust stop holds that Guard home's
    installation lock across the stop, so an install holding its lease
    finishes first and none can start while the resident goes.
    """
    command = [str(executable), "resident-stop", "--state-dir", str(state_dir)]
    if retire_clients:
        command.append("--retire-clients")
        if install_lock_home is not None:
            command.extend(("--hold-install-lock", str(install_lock_home)))
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
    hold_install_lock: bool = False,
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
        # A persistent client that could not be contained is still a live
        # native process. Stopping the shared resident does not make that true.
        if close_native_resident_clients(resolved_guard_home) is False:
            return False
        _ = _state_files(state_dir, strict=True)
        return stop_native_resident(
            executable=executable,
            state_dir=state_dir,
            environment=environment,
            timeout_seconds=timeout_seconds,
            retire_clients=True,
            install_lock_home=resolved_guard_home if hold_install_lock else None,
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


def native_resident_client_request(
    *,
    executable: Path,
    guard_home: Path,
    environment: Mapping[str, str],
    payload: bytes,
    timeout_seconds: float | None = None,
    raw_hook_envelope: bool = False,
    deadline_monotonic: float | None = None,
    diagnostic: bool = False,
    idle_only: bool = False,
    idle_wait_seconds: float = 0.0,
) -> bytes | None:
    """Send bounded bytes through a persistent Rust client stream.

    ``diagnostic`` marks a question about the resident rather than work for it.
    A diagnostic leaves the hook path exactly as it found it: the restart hold
    is neither armed nor cleared, and the failure code and hold key a hook
    request left behind are restored before returning.

    ``idle_only`` borrows only an existing live idle client, without waiting
    for pool capacity or spawning a Python-owned client process. Rust still
    owns resident recovery behind a live client stream. ``idle_wait_seconds``
    lets an idle-only caller wait that long for a stream the pool has in use to
    be parked; it never waits when the pool has no stream in use.
    """
    previous_failure = _LAST_FAILURE_CODE.get() if diagnostic else None
    previous_hold_key = _LAST_HOLD_KEY.get() if diagnostic else None
    try:
        return _resident_client_request(
            executable=executable,
            guard_home=guard_home,
            environment=environment,
            payload=payload,
            timeout_seconds=timeout_seconds,
            raw_hook_envelope=raw_hook_envelope,
            deadline_monotonic=deadline_monotonic,
            diagnostic=diagnostic,
            idle_only=idle_only,
            idle_wait_seconds=idle_wait_seconds,
        )
    finally:
        if diagnostic:
            # Every path above, the rejections included, writes these. Restore
            # them whichever one ran, so a question answers only its caller.
            _LAST_FAILURE_CODE.set(previous_failure)
            _LAST_HOLD_KEY.set(previous_hold_key)


def _resident_client_request(
    *,
    executable: Path,
    guard_home: Path,
    environment: Mapping[str, str],
    payload: bytes,
    timeout_seconds: float | None,
    raw_hook_envelope: bool,
    deadline_monotonic: float | None,
    diagnostic: bool,
    idle_only: bool = False,
    idle_wait_seconds: float = 0.0,
) -> bytes | None:
    _LAST_FAILURE_CODE.set(None)
    _LAST_HOLD_KEY.set(None)
    if not payload or (deadline_monotonic is None and (timeout_seconds is None or timeout_seconds <= 0)):
        _LAST_FAILURE_CODE.set("native_client_request_invalid")
        return None
    if len(payload) > _MAX_REQUEST_BYTES:
        _LAST_FAILURE_CODE.set("native_client_request_invalid")
        return None
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
    if idle_only:
        key = (str(executable), str(_pinned_state_dir(guard_home / "native-runtime")))
        with _CLIENTS_LOCK:
            pool = _CLIENT_POOLS.get(key)
        if pool is None:
            return None
    else:
        pool = _client_pool_for(executable, guard_home / "native-runtime", environment)
    return pool.request(
        payload,
        deadline_monotonic=deadline,
        diagnostic=diagnostic,
        idle_only=idle_only,
        idle_wait_seconds=idle_wait_seconds,
    )


native_resident_client_request_if_idle = partial(native_resident_client_request, idle_only=True)


__all__ = [
    "_PersistentNativeClient",
    "_StreamFailure",
    "close_native_resident_clients",
    "close_native_residents",
    "native_resident_client_failure_code",
    "native_resident_client_failure_hold_key",
    "native_resident_client_ready",
    "native_resident_client_request",
    "native_resident_client_request_if_idle",
    "native_resident_guard_home_containing",
    "native_resident_home_holds",
    "record_native_resident_client_failure_code",
    "record_native_resident_client_failure_hold_key",
    "record_native_resident_error_frame",
    "resident_state_files",
    "retire_native_resident_for_update",
    "stop_native_resident",
    "tracked_native_resident_state_dirs",
]
