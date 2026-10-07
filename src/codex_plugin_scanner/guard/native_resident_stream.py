"""Persistent stream transport for the package-bound Rust resident client.

The parent module owns the process-wide pool and failure context. This module
owns one bounded framed client so the pool registry remains small and testable.
"""

from __future__ import annotations

import os
import struct
import subprocess
import threading
import time
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager, suppress
from pathlib import Path
from queue import Empty, Full, Queue
from typing import Protocol

from .codex_hook_launch_runtime import isolated_hook_environment
from .native_resident_transport import write_frame

_MAX_REQUEST_BYTES = 6 * 1024 * 1024
_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_STREAM_FRAME_HEADER_BYTES = 4
_CLIENT_CLOSE_TIMEOUT_SECONDS = 0.5


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
        self._closing = False
        self._lock = threading.Lock()
        # Keep process teardown out of the response wait.  The process-state
        # lock protects snapshots; this lock protects the response queue and
        # process snapshot until the response is consumed. Writes stay
        # outside it so close() can interrupt a blocked platform pipe writer.
        self._lifecycle_lock = threading.RLock()
        self._request_lock = threading.Lock()

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
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
        except OSError:
            self._process = None
            return False
        self._process = process
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
        with suppress(Exception):
            responses.put_nowait(_StreamFailure())

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
                self._record_failure("native_client_timed_out")
                return None
            with _hold_until(self._lock, deadline_monotonic) as state:
                if not state:
                    self._record_failure("native_client_timed_out")
                    return None
                return self._snapshot_locked(deadline_monotonic=deadline_monotonic)

    def _snapshot_locked(
        self,
        *,
        deadline_monotonic: float | None,
    ) -> tuple[subprocess.Popen[bytes], object, Queue[bytes | _StreamFailure]] | None:
        if not self._start(deadline_monotonic=deadline_monotonic):
            self._record_failure(
                "native_client_timed_out"
                if deadline_monotonic is not None and time.monotonic() >= deadline_monotonic
                else "native_client_start_failed"
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
                self._record_failure("native_client_timed_out")
                return None
            if time.monotonic() >= deadline_monotonic:
                self._record_failure("native_client_timed_out")
                return None
            snapshot = self._request_snapshot(deadline_monotonic=deadline_monotonic)
            if snapshot is None:
                return None
            if time.monotonic() >= deadline_monotonic:
                self.close(deadline_monotonic=deadline_monotonic)
                self._record_failure("native_client_timed_out")
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
                self._record_failure(
                    "native_client_timed_out"
                    if time.monotonic() >= deadline_monotonic
                    else "native_client_frame_write_failed"
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
                    self._record_failure("native_client_timed_out")
                    return None
                if not self._request_is_current(process, responses, deadline_monotonic=deadline_monotonic):
                    self._record_current_failure(deadline_monotonic)
                    return None
                remaining = deadline_monotonic - time.monotonic()
                if remaining <= 0:
                    self.close(deadline_monotonic=deadline_monotonic)
                    self._record_failure("native_client_timed_out")
                    return None
                try:
                    response = responses.get(timeout=remaining)
                except Empty:
                    self.close(deadline_monotonic=deadline_monotonic)
                    self._record_failure("native_client_timed_out")
                    return None
                if isinstance(response, _StreamFailure):
                    self.close(deadline_monotonic=deadline_monotonic)
                    self._record_failure("native_client_stream_failed")
                    return None
                return response

    def _record_current_failure(self, deadline_monotonic: float) -> None:
        self._record_failure(
            "native_client_timed_out" if time.monotonic() >= deadline_monotonic else "native_client_stream_failed"
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
                self._record_failure("native_client_timed_out")
                return False
            with _hold_until(self._lock, deadline_monotonic) as state:
                if not state:
                    self._record_failure("native_client_timed_out")
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
        responses = self._responses
        if process is None:
            return True
        deadline = (
            time.monotonic() + 3 * _CLIENT_CLOSE_TIMEOUT_SECONDS if deadline_monotonic is None else deadline_monotonic
        )

        def remaining() -> float:
            return min(_CLIENT_CLOSE_TIMEOUT_SECONDS, max(0.0, deadline - time.monotonic()))

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
        if (
            process.poll() is None
            or (reader is not None and reader.is_alive())
            or (writer is not None and writer.is_alive())
        ):
            # Keep ownership for a later close; do not block on a buffered
            # stream lock held by the unfinished reader or reuse its generation.
            return False
        for stream in (process.stdin, process.stdout):
            if stream is not None:
                with suppress(OSError, ValueError):
                    stream.close()
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
