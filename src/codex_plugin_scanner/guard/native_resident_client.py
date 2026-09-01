"""Minimal launcher for the package-bound Rust resident client.

Python supplies only the verified binary path, private Guard state root, bounded
bytes, and deadline. Rust owns discovery, authentication, framing, restart,
generation state, response binding, and resident lifecycle.
"""

from __future__ import annotations

import atexit
import re
import struct
import subprocess
import threading
import time
from collections.abc import Mapping
from contextlib import suppress
from contextvars import ContextVar
from pathlib import Path
from queue import Empty, Full, Queue

from .codex_hook_launch_runtime import (
    BoundedHookProcessResult,
    isolated_hook_environment,
)
from .codex_hook_launch_runtime import (
    run_isolated_hook_process as _legacy_run_isolated_hook_process,
)

# Keep the former runner as a test seam. Production always uses the framed
# stream below; tests can replace this binding with a bounded fake.
run_isolated_hook_process = _legacy_run_isolated_hook_process

_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_MAX_REQUEST_BYTES = 6 * 1024 * 1024
_STREAM_FRAME_HEADER_BYTES = 4
_CLIENT_CLOSE_TIMEOUT_SECONDS = 0.5
_CLIENT_RETIRE_TIMEOUT_SECONDS = 2.5
_MAX_PERSISTENT_CLIENTS = 16
_MAX_FAILURE_CODE_LENGTH = 128
_FAILURE_CODE_PATTERN = re.compile(r"native_[a-z0-9_]+")
_LAST_FAILURE_CODE: ContextVar[str | None] = ContextVar(
    "native_resident_client_failure_code",
    default=None,
)
_RESIDENTS_LOCK = threading.Lock()
_RESIDENTS: dict[tuple[Path, Path], Mapping[str, str]] = {}


def native_resident_client_failure_code() -> str | None:
    """Return the current context's privacy-safe native failure code."""
    return _LAST_FAILURE_CODE.get()


def _allowlisted_failure_code(stderr: str) -> str | None:
    for line in stderr.splitlines():
        if len(line) <= _MAX_FAILURE_CODE_LENGTH and _FAILURE_CODE_PATTERN.fullmatch(line):
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


class _StreamFailure:
    """Sentinel for a Rust stream that exited before returning a frame."""


class _PersistentNativeClient:
    """One bounded Rust client process with a serialized framed stream."""

    def __init__(
        self,
        *,
        executable: Path,
        state_dir: Path,
        environment: Mapping[str, str],
    ) -> None:
        self._executable = executable
        self._state_dir = state_dir
        self._environment = isolated_hook_environment(environment)
        self._process: subprocess.Popen[bytes] | None = None
        self._responses: Queue[bytes | _StreamFailure] = Queue(maxsize=1)
        self._reader: threading.Thread | None = None
        self._lock = threading.Lock()

    def _start(self) -> bool:
        if self._process is not None and self._process.poll() is None:
            return True
        if self._process is not None:
            self._close_locked()
        while True:
            try:
                self._responses.get_nowait()
            except Empty:
                break
        try:
            self._process = subprocess.Popen(
                (
                    str(self._executable),
                    "resident-client-stream",
                    "--stdin",
                    str(self._state_dir),
                ),
                cwd=self._executable.parent,
                env=self._environment,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        except OSError:
            self._process = None
            return False
        self._reader = threading.Thread(
            target=self._read_responses,
            name="hol-guard-native-client",
            daemon=True,
        )
        self._reader.start()
        return True

    def _read_responses(self) -> None:
        process = self._process
        stdout = process.stdout if process is not None else None
        if stdout is None:
            return
        try:
            while True:
                header = stdout.read(_STREAM_FRAME_HEADER_BYTES)
                if not header:
                    break
                if len(header) != _STREAM_FRAME_HEADER_BYTES:
                    break
                length = struct.unpack(">I", header)[0]
                if length <= 0 or length > _MAX_RESPONSE_BYTES:
                    break
                response = stdout.read(length)
                if len(response) != length:
                    break
                try:
                    self._responses.put_nowait(response)
                except Full:
                    break
        except (OSError, ValueError):
            pass
        with suppress(Exception):
            self._responses.put_nowait(_StreamFailure())

    def request(self, payload: bytes, *, deadline_monotonic: float) -> bytes | None:
        if not payload or len(payload) > _MAX_REQUEST_BYTES:
            _LAST_FAILURE_CODE.set("native_client_request_invalid")
            return None
        with self._lock:
            if not self._start():
                _LAST_FAILURE_CODE.set("native_client_start_failed")
                return None
            process = self._process
            stdin = process.stdin if process is not None else None
            if stdin is None:
                _LAST_FAILURE_CODE.set("native_client_stdin_unavailable")
                return None
            try:
                stdin.write(struct.pack(">I", len(payload)))
                stdin.write(payload)
                stdin.flush()
            except OSError:
                self._close_locked()
                _LAST_FAILURE_CODE.set("native_client_frame_write_failed")
                return None
            remaining = deadline_monotonic - time.monotonic()
            if remaining <= 0:
                self._close_locked()
                _LAST_FAILURE_CODE.set("native_client_timed_out")
                return None
            try:
                response = self._responses.get(timeout=remaining)
            except Empty:
                self._close_locked()
                _LAST_FAILURE_CODE.set("native_client_timed_out")
                return None
            if isinstance(response, _StreamFailure):
                self._close_locked()
                _LAST_FAILURE_CODE.set("native_client_stream_failed")
                return None
            return response

    def _close_locked(self) -> None:
        process = self._process
        reader = self._reader
        self._process = None
        self._reader = None
        if process is None:
            return
        if process.poll() is None:
            with suppress(OSError):
                process.terminate()
            try:
                process.wait(timeout=_CLIENT_CLOSE_TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired:
                with suppress(OSError):
                    process.kill()
                with suppress(subprocess.TimeoutExpired):
                    process.wait(timeout=_CLIENT_CLOSE_TIMEOUT_SECONDS)
        for stream in (process.stdin, process.stdout):
            if stream is not None:
                with suppress(OSError, ValueError):
                    stream.close()
        if reader is not None and reader is not threading.current_thread():
            reader.join(timeout=_CLIENT_CLOSE_TIMEOUT_SECONDS)

    def close(self) -> None:
        with self._lock:
            self._close_locked()

    def close_and_contain(self) -> None:
        """Close the stream and retire only its managed resident state."""
        self.close()
        _contain_persistent_resident(self)


_CLIENTS_LOCK = threading.Lock()
_CLIENTS: dict[tuple[str, str], _PersistentNativeClient] = {}


def _client_for(
    executable: Path,
    state_dir: Path,
    environment: Mapping[str, str],
) -> _PersistentNativeClient:
    key = (str(executable), str(state_dir))
    evicted: _PersistentNativeClient | None = None
    with _CLIENTS_LOCK:
        client = _CLIENTS.get(key)
        if client is None:
            if len(_CLIENTS) >= _MAX_PERSISTENT_CLIENTS:
                evicted_key = next(iter(_CLIENTS))
                evicted = _CLIENTS.pop(evicted_key)
            client = _PersistentNativeClient(
                executable=executable,
                state_dir=state_dir,
                environment=environment,
            )
            _CLIENTS[key] = client
    if evicted is not None:
        evicted.close_and_contain()
    return client


def _state_files(state_dir: Path) -> tuple[Path, ...]:
    try:
        return tuple(state_dir.glob("resident-v3-*/generation-*.json"))
    except (OSError, RuntimeError):
        return ()


def _has_client_for_state(state_dir: Path) -> bool:
    state_key = str(state_dir)
    with _CLIENTS_LOCK:
        return any(key[1] == state_key for key in _CLIENTS)


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
        timeout_seconds=_CLIENT_CLOSE_TIMEOUT_SECONDS,
    )
    deadline = time.monotonic() + _CLIENT_RETIRE_TIMEOUT_SECONDS
    while _state_files(client._state_dir) and time.monotonic() < deadline:
        time.sleep(0.025)


def close_native_resident_clients(guard_home: Path | None = None) -> None:
    """Close persistent Rust clients, optionally limited to one Guard home."""
    resolved_guard_home = guard_home.expanduser() if guard_home is not None else None

    def belongs_to_guard_home(key: tuple[str, str]) -> bool:
        if resolved_guard_home is None:
            return True
        state_parent = Path(key[1]).parent
        try:
            return state_parent.samefile(resolved_guard_home)
        except OSError:
            return state_parent == resolved_guard_home

    with _CLIENTS_LOCK:
        selected = [(key, client) for key, client in _CLIENTS.items() if belongs_to_guard_home(key)]
        for key, _client in selected:
            _CLIENTS.pop(key, None)
    for _key, client in selected:
        client.close()
    for _key, client in selected:
        _contain_persistent_resident(client)


atexit.register(close_native_resident_clients)


def _track_resident(executable: Path, state_dir: Path, environment: Mapping[str, str]) -> None:
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
        and not list(state_dir.glob("resident-v3-*/generation-*.json"))
    )


def close_native_residents() -> None:
    """Stop Rust-managed residents created by this Python process."""
    close_native_resident_clients()
    with _RESIDENTS_LOCK:
        residents = list(_RESIDENTS.items())
    remaining: dict[tuple[Path, Path], Mapping[str, str]] = {}
    for (executable, state_dir), environment in residents:
        state_files = list(state_dir.glob("resident-v3-*/generation-*.json"))
        if state_files and not stop_native_resident(
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
    timeout_seconds: float | None = None,
    raw_hook_envelope: bool = False,
    deadline_monotonic: float | None = None,
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
    return _client_for(executable, guard_home / "native-runtime", environment).request(
        payload,
        deadline_monotonic=deadline,
    )


__all__ = [
    "close_native_resident_clients",
    "close_native_residents",
    "native_resident_client_failure_code",
    "native_resident_client_request",
    "stop_native_resident",
]
