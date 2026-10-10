"""Persistent stream transport for the package-bound Rust resident client.

The parent module owns the process-wide pool and failure context. This module
owns one bounded framed client so the pool registry remains small and testable.
"""

from __future__ import annotations

import logging
import os
import re
import stat
import struct
import subprocess
import threading
import time
from _thread import LockType
from collections import deque
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager, suppress
from pathlib import Path
from queue import Empty, Full, Queue
from typing import Protocol

from .codex_hook_launch_runtime import isolated_hook_environment
from .native_mode import non_production_diagnostic_enabled
from .native_resident_reap import reap_exited_client
from .native_resident_transport import write_frame

logger = logging.getLogger(__name__)

_MAX_REQUEST_BYTES = 6 * 1024 * 1024
_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_STREAM_FRAME_HEADER_BYTES = 4
_CLIENT_CLOSE_TIMEOUT_SECONDS = 0.5
_MAX_DIAGNOSTIC_BYTES = 64 * 1024
_NATIVE_DIAGNOSTIC_LINE = re.compile(
    rb"native_resident_phase phase=("
    rb"stream_lease|stream_dispatch|stream_response_write|"
    rb"client_prepare|client_discovery|client_identity|client_startup_lock|"
    rb"client_startup_wait|client_spawn|client_spawn_wait|"
    rb"client_connect|client_authenticate|client_request_write|client_response_read|"
    rb"resident_startup|resident_authenticate|resident_header_read|resident_payload_read|resident_dispatch_wait|"
    rb"resident_evaluate|resident_response_write|context_digest|"
    rb"context_runtime_executable_identity|context_runtime_launch_identity|"
    rb"context_runtime_launch_identity_matches|executable_digest"
    rb") status=(start|ok|error) elapsed_ms=[0-9]{1,20}"
)


class _TimedLock(Protocol):
    def acquire(self, blocking: bool = True, timeout: float = -1) -> bool: ...
    def release(self) -> None: ...


@contextmanager
def _hold_until(lock: _TimedLock, deadline: float | None) -> Iterator[bool]:
    acquired = lock.acquire() if deadline is None else lock.acquire(timeout=max(0.0, deadline - time.monotonic()))
    try:
        yield acquired
    finally:
        if acquired:
            lock.release()


def _is_directory(path: Path) -> bool:
    try:
        return path.is_dir()
    except OSError:
        return False


def _existing_state_dir(state_dir: Path) -> Path:
    """Launch against a spelling that exists.

    A pool may have pinned ``resolve()`` before ``native-runtime`` existed.
    Publication creates the absolute spelling. Opening the missing pin makes
    Windows report a missing private ancestor.
    """

    if _is_directory(state_dir):
        return state_dir
    absolute = Path(os.path.abspath(state_dir))
    if not _is_directory(absolute):
        return state_dir
    try:
        resolved = absolute.resolve()
    except OSError:
        return absolute
    return resolved if _is_directory(resolved) else absolute


class _StreamFailure:
    """Sentinel for a client stream that exited before returning a frame."""


class _PersistentNativeClient:
    """One bounded Rust client process with a persistent stdin/stdout stream."""

    def __init__(
        self,
        *,
        executable: Path,
        state_dir: Path,
        environment: Mapping[str, str],
        failure_recorder: Callable[[str], object] | None = None,
    ) -> None:
        self._executable = executable
        self._state_dir = state_dir
        self._environment = isolated_hook_environment(environment)
        self._record_failure = failure_recorder or (lambda _code: None)
        self._process: subprocess.Popen[bytes] | None = None
        self._responses: Queue[bytes | _StreamFailure] = Queue(maxsize=1)
        self._reader: threading.Thread | None = None
        self._writer: threading.Thread | None = None
        self._diagnostic_reader: threading.Thread | None = None
        self._diagnostic_lines: deque[bytes] | None = None
        self._diagnostic_lock: LockType | None = None
        self._diagnostic_tail = b""
        self._closing = False
        self._retiring: subprocess.Popen[bytes] | None = None
        self._lock = threading.Lock()
        # Keep process teardown out of the response wait.  The process-state
        # lock protects snapshots; this lock protects the response queue and
        # process snapshot until the response is consumed. Writes stay
        # outside it so close() can interrupt a blocked platform pipe writer.
        self._lifecycle_lock = threading.RLock()
        self._request_lock = threading.Lock()

    def _record_phase_failure(self, code: str, phase: str) -> None:
        """Keep optional timeout diagnostics separate from stable failure codes."""
        self._record_failure(code)
        if code == "native_client_timed_out":
            # A diagnostic handler must not change fail-closed transport results.
            with suppress(Exception):
                if non_production_diagnostic_enabled():
                    logger.warning("native_client_timed_out phase=%s", phase)
                    for source in (self._read_diagnostic_tail(), self._read_managed_diagnostics()):
                        for line in source.splitlines()[-64:]:
                            if _NATIVE_DIAGNOSTIC_LINE.fullmatch(line):
                                logger.warning("%s", line.decode("ascii"))

    def _read_diagnostic_tail(self) -> bytes:
        lines, lock = self._diagnostic_lines, self._diagnostic_lock
        if lines is not None and lock is not None:
            with lock:
                return b"\n".join(lines)
        return self._diagnostic_tail

    def _read_managed_diagnostics(self) -> bytes:
        """Read bounded shared evidence without creating or repairing state."""
        state_dir = _existing_state_dir(self._state_dir)
        path = state_dir / "managed-resident-phases.v1.log"
        with suppress(Exception):
            if os.name == "nt":
                from . import native_policy_snapshot

                if native_policy_snapshot._windows_path_has_reparse_component(path):
                    return b""
                return (
                    native_policy_snapshot._windows_read_snapshot_bytes(path, maximum_bytes=_MAX_DIAGNOSTIC_BYTES)
                    or b""
                )
            flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
            directory = os.open(state_dir, flags | os.O_DIRECTORY)
            try:
                metadata = os.fstat(directory)
                binding = state_dir.lstat()
                if (
                    not stat.S_ISDIR(metadata.st_mode)
                    or (metadata.st_dev, metadata.st_ino) != (binding.st_dev, binding.st_ino)
                    or metadata.st_uid != os.geteuid()
                    or metadata.st_mode & 0o077
                ):
                    return b""
                descriptor = os.open(path.name, flags, dir_fd=directory)
                try:
                    metadata = os.fstat(descriptor)
                    binding = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
                    if (
                        not stat.S_ISREG(metadata.st_mode)
                        or (metadata.st_dev, metadata.st_ino) != (binding.st_dev, binding.st_ino)
                        or metadata.st_nlink != 1
                        or metadata.st_uid != os.geteuid()
                        or metadata.st_mode & 0o077
                        or not 0 < metadata.st_size <= _MAX_DIAGNOSTIC_BYTES
                    ):
                        return b""
                    payload = bytearray()
                    while len(payload) <= _MAX_DIAGNOSTIC_BYTES:
                        chunk = os.read(descriptor, _MAX_DIAGNOSTIC_BYTES + 1 - len(payload))
                        if not chunk:
                            break
                        payload.extend(chunk)
                    if len(payload) <= _MAX_DIAGNOSTIC_BYTES:
                        return bytes(payload)
                finally:
                    os.close(descriptor)
            finally:
                os.close(directory)
        return b""

    def _close_diagnostic_output(self) -> None:
        self._diagnostic_tail = self._read_diagnostic_tail()
        self._diagnostic_lines = None
        self._diagnostic_lock = None
        self._diagnostic_reader = None

    @staticmethod
    def _read_diagnostics(process: subprocess.Popen[bytes], lines: deque[bytes], lock: LockType) -> None:
        stderr = process.stderr
        if stderr is None:
            return
        discarding = False
        with suppress(OSError, ValueError):
            while raw := stderr.readline(193):
                complete = raw.endswith(b"\n")
                if discarding or not complete:
                    discarding = not complete
                    continue
                line = raw.rstrip(b"\r\n")
                if _NATIVE_DIAGNOSTIC_LINE.fullmatch(line):
                    with lock:
                        lines.append(line)

    def _start(self, *, deadline_monotonic: float | None = None) -> bool:
        if self._closing:
            return False
        if self._process is not None:
            if self._process.poll() is None:
                return True
            # Reap/close the previous generation before replacing its process
            # and response queue. Its reader may still be draining EOF.
            if not self._close_locked(deadline_monotonic=deadline_monotonic):
                self._closing = True
                return False
        responses: Queue[bytes | _StreamFailure] = Queue(maxsize=1)
        self._responses = responses
        if deadline_monotonic is not None and time.monotonic() >= deadline_monotonic:
            return False
        self._diagnostic_tail = b""
        diagnostics = non_production_diagnostic_enabled()
        if diagnostics:
            self._diagnostic_lines = deque(maxlen=64)
            self._diagnostic_lock = threading.Lock()
        try:
            process = subprocess.Popen(
                (
                    str(self._executable),
                    "resident-client-stream",
                    "--stdin",
                    str(_existing_state_dir(self._state_dir)),
                ),
                cwd=self._executable.parent,
                env=self._environment,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE if diagnostics else subprocess.DEVNULL,
                start_new_session=True,
            )
        except OSError:
            self._process = None
            self._close_diagnostic_output()
            return False
        self._process = process
        if self._diagnostic_lines is not None and self._diagnostic_lock is not None:
            self._diagnostic_reader = threading.Thread(
                target=self._read_diagnostics,
                args=(process, self._diagnostic_lines, self._diagnostic_lock),
                name="hol-guard-native-diagnostics",
                daemon=True,
            )
            self._diagnostic_reader.start()
        self._reader = threading.Thread(
            target=self._read_responses,
            args=(process, responses),
            name="hol-guard-native-client",
            daemon=True,
        )
        self._reader.start()
        return True

    def _read_responses(
        self,
        process: subprocess.Popen[bytes],
        responses: Queue[bytes | _StreamFailure],
    ) -> None:
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
                    responses.put_nowait(response)
                except Full:
                    break
        except (OSError, ValueError):
            pass
        # Decide before the failure is visible: a request that sees it may start closing.
        retired = self._closing or self._retiring is process
        with suppress(Exception):
            responses.put_nowait(_StreamFailure())
        reap_exited_client(process, retired=retired)

    @staticmethod
    def _write_frame(
        stdin: object,
        frame: bytes,
        *,
        deadline_monotonic: float,
        launch_worker: Callable[[threading.Thread], bool] | None = None,
    ) -> bool:
        return write_frame(
            stdin,
            frame,
            deadline_monotonic=deadline_monotonic,
            launch_worker=launch_worker,
        )

    def _launch_writer(
        self,
        worker: threading.Thread,
        process: subprocess.Popen[bytes],
        *,
        deadline_monotonic: float,
    ) -> bool:
        with _hold_until(self._lock, deadline_monotonic) as state:
            if (
                not state
                or self._closing
                or self._process is not process
                or process.poll() is not None
                or time.monotonic() >= deadline_monotonic
            ):
                return False
            if self._writer is not None and self._writer.is_alive():
                return False
            # Registration and launch are atomic with respect to teardown.
            self._writer = worker
            worker.start()
            return True

    def _request_snapshot(
        self,
        *,
        deadline_monotonic: float | None = None,
    ) -> tuple[subprocess.Popen[bytes], object, Queue[bytes | _StreamFailure]] | None:
        with _hold_until(self._lifecycle_lock, deadline_monotonic) as lifecycle:
            if not lifecycle:
                self._record_phase_failure("native_client_timed_out", "snapshot_lifecycle_lock")
                return None
            with _hold_until(self._lock, deadline_monotonic) as state:
                if not state:
                    self._record_phase_failure("native_client_timed_out", "snapshot_state_lock")
                    return None
                return self._snapshot_locked(deadline_monotonic=deadline_monotonic)

    def _snapshot_locked(
        self,
        *,
        deadline_monotonic: float | None,
    ) -> tuple[subprocess.Popen[bytes], object, Queue[bytes | _StreamFailure]] | None:
        if not self._start(deadline_monotonic=deadline_monotonic):
            self._record_phase_failure(
                "native_client_timed_out"
                if deadline_monotonic is not None and time.monotonic() >= deadline_monotonic
                else "native_client_start_failed",
                "snapshot_start",
            )
            return None
        process = self._process
        stdin = process.stdin if process is not None else None
        if stdin is None or process is None:
            self._record_failure("native_client_stdin_unavailable")
            return None
        return process, stdin, self._responses

    def request(self, payload: bytes, *, deadline_monotonic: float) -> bytes | None:
        if not payload or len(payload) > _MAX_REQUEST_BYTES:
            self._record_failure("native_client_request_invalid")
            return None
        with _hold_until(self._request_lock, deadline_monotonic) as acquired:
            if not acquired:
                self._record_phase_failure("native_client_timed_out", "request_lock")
                return None
            if time.monotonic() >= deadline_monotonic:
                self._record_phase_failure("native_client_timed_out", "request_deadline")
                return None
            snapshot = self._request_snapshot(deadline_monotonic=deadline_monotonic)
            if snapshot is None:
                return None
            if time.monotonic() >= deadline_monotonic:
                self.close(deadline_monotonic=deadline_monotonic)
                self._record_phase_failure("native_client_timed_out", "post_snapshot_deadline")
                return None
            process, stdin, responses = snapshot
            if not self._request_is_current(process, responses, deadline_monotonic=deadline_monotonic):
                self._record_current_failure(deadline_monotonic)
                return None
            frame = struct.pack(">I", len(payload)) + payload
            if not self._write_frame(
                stdin,
                frame,
                deadline_monotonic=deadline_monotonic,
                launch_worker=lambda worker: self._launch_writer(
                    worker,
                    process,
                    deadline_monotonic=deadline_monotonic,
                ),
            ):
                self.close(deadline_monotonic=deadline_monotonic)
                self._record_phase_failure(
                    "native_client_timed_out"
                    if time.monotonic() >= deadline_monotonic
                    else "native_client_frame_write_failed",
                    "frame_write",
                )
                return None
            if not self._request_is_current(process, responses, deadline_monotonic=deadline_monotonic):
                self._record_current_failure(deadline_monotonic)
                return None
            # A pool teardown may call close() while this request waits for
            # its response. Hold the lifecycle lock for that wait so teardown
            # cannot close the captured process or queue mid-read. The lock is
            # intentionally acquired after the write, allowing close() to
            # interrupt a blocked write on platforms that need a stoppable
            # writer fallback.
            with _hold_until(self._lifecycle_lock, deadline_monotonic) as lifecycle:
                if not lifecycle:
                    self._record_phase_failure("native_client_timed_out", "response_lifecycle_lock")
                    return None
                if not self._request_is_current(process, responses, deadline_monotonic=deadline_monotonic):
                    self._record_current_failure(deadline_monotonic)
                    return None
                remaining = deadline_monotonic - time.monotonic()
                if remaining <= 0:
                    self.close(deadline_monotonic=deadline_monotonic)
                    self._record_phase_failure("native_client_timed_out", "response_deadline")
                    return None
                try:
                    response = responses.get(timeout=remaining)
                except Empty:
                    self.close(deadline_monotonic=deadline_monotonic)
                    self._record_phase_failure("native_client_timed_out", "response_wait")
                    return None
                if isinstance(response, _StreamFailure):
                    self.close(deadline_monotonic=deadline_monotonic)
                    self._record_failure("native_client_stream_failed")
                    return None
                return response

    def _record_current_failure(self, deadline_monotonic: float) -> None:
        self._record_phase_failure(
            "native_client_timed_out" if time.monotonic() >= deadline_monotonic else "native_client_stream_failed",
            "current_snapshot",
        )

    def _request_is_current(
        self,
        process: subprocess.Popen[bytes],
        responses: Queue[bytes | _StreamFailure],
        *,
        deadline_monotonic: float | None = None,
    ) -> bool:
        """Reject a snapshot invalidated by concurrent client teardown."""

        with _hold_until(self._lifecycle_lock, deadline_monotonic) as lifecycle:
            if not lifecycle:
                self._record_phase_failure("native_client_timed_out", "current_lifecycle_lock")
                return False
            with _hold_until(self._lock, deadline_monotonic) as state:
                if not state:
                    self._record_phase_failure("native_client_timed_out", "current_state_lock")
                    return False
                return (
                    not self._closing
                    and self._process is process
                    and self._responses is responses
                    and process.poll() is None
                )

    def _close_locked(self, *, deadline_monotonic: float | None = None) -> bool:
        process = self._process
        reader = self._reader
        writer = self._writer
        diagnostic_reader = self._diagnostic_reader
        responses = self._responses
        if process is None:
            return True
        deadline = (
            time.monotonic() + 3 * _CLIENT_CLOSE_TIMEOUT_SECONDS if deadline_monotonic is None else deadline_monotonic
        )

        def remaining() -> float:
            return min(_CLIENT_CLOSE_TIMEOUT_SECONDS, max(0.0, deadline - time.monotonic()))

        self._retiring = process
        with suppress(Full):
            responses.put_nowait(_StreamFailure())
        if process.poll() is None:
            with suppress(OSError):
                process.terminate()
            try:
                process.wait(timeout=remaining())
            except subprocess.TimeoutExpired:
                with suppress(OSError):
                    process.kill()
                with suppress(subprocess.TimeoutExpired):
                    process.wait(timeout=remaining())
        if reader is not None and reader is not threading.current_thread():
            reader.join(timeout=remaining())
        if writer is not None and writer is not threading.current_thread():
            writer.join(timeout=remaining())
        if diagnostic_reader is not None and diagnostic_reader is not threading.current_thread():
            diagnostic_reader.join(timeout=remaining())
        if (
            process.poll() is None
            or (reader is not None and reader.is_alive())
            or (writer is not None and writer.is_alive())
            or (diagnostic_reader is not None and diagnostic_reader.is_alive())
        ):
            # Keep ownership for a later close; do not block on a buffered
            # stream lock held by the unfinished reader or reuse its generation.
            return False
        for stream in (process.stdin, process.stdout):
            if stream is not None:
                with suppress(OSError, ValueError):
                    stream.close()
        if diagnostic_reader is not None and process.stderr is not None:
            with suppress(OSError, ValueError):
                process.stderr.close()
        self._close_diagnostic_output()
        self._process = None
        self._reader = None
        self._writer = None
        return True

    def close(self, *, deadline_monotonic: float | None = None) -> bool:
        deadline = (
            time.monotonic() + 3 * _CLIENT_CLOSE_TIMEOUT_SECONDS if deadline_monotonic is None else deadline_monotonic
        )
        # Mark retirement and wake an in-flight response wait before acquiring
        # its lifecycle lock. A contended lock cannot consume a new budget.
        self._closing = True
        with suppress(Full):
            self._responses.put_nowait(_StreamFailure())
        if not self._lifecycle_lock.acquire(timeout=max(0.0, deadline - time.monotonic())):
            return False
        try:
            if not self._lock.acquire(timeout=max(0.0, deadline - time.monotonic())):
                return False
            try:
                return self._close_locked(deadline_monotonic=deadline)
            finally:
                self._lock.release()
        finally:
            self._lifecycle_lock.release()


__all__ = ["_PersistentNativeClient", "_StreamFailure"]
