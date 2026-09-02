"""Persistent stream transport for the package-bound Rust resident client.

The parent module owns the process-wide pool and failure context. This module
owns one bounded framed client so the pool registry remains small and testable.
"""

from __future__ import annotations

import struct
import subprocess
import threading
import time
from collections.abc import Callable, Mapping
from contextlib import suppress
from pathlib import Path
from queue import Empty, Full, Queue

from .codex_hook_launch_runtime import isolated_hook_environment
from .native_resident_transport import write_frame

_MAX_REQUEST_BYTES = 6 * 1024 * 1024
_MAX_RESPONSE_BYTES = 2 * 1024 * 1024
_STREAM_FRAME_HEADER_BYTES = 4
_CLIENT_CLOSE_TIMEOUT_SECONDS = 0.5


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
        self._lock = threading.Lock()
        # Keep process teardown out of the response wait.  The process-state
        # lock protects snapshots; this lock protects the response queue and
        # process snapshot until the response is consumed. Writes stay
        # outside it so close() can interrupt a blocked platform pipe writer.
        self._lifecycle_lock = threading.RLock()
        self._request_lock = threading.Lock()

    def _start(self) -> bool:
        if self._process is not None:
            if self._process.poll() is None:
                return True
            # Reap/close the previous generation before replacing its process
            # and response queue. Its reader may still be draining EOF.
            self._close_locked()
        responses: Queue[bytes | _StreamFailure] = Queue(maxsize=1)
        self._responses = responses
        try:
            process = subprocess.Popen(
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
    ) -> bool:
        return write_frame(
            stdin,
            frame,
            deadline_monotonic=deadline_monotonic,
        )

    def _request_snapshot(
        self,
    ) -> tuple[subprocess.Popen[bytes], object, Queue[bytes | _StreamFailure]] | None:
        with self._lifecycle_lock, self._lock:
            if not self._start():
                self._record_failure("native_client_start_failed")
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
        with self._request_lock:
            spawn_started = time.monotonic()
            snapshot = self._request_snapshot()
            if snapshot is None:
                return None
            # Starting the helper process is setup, not request budget.
            deadline_monotonic += max(0.0, time.monotonic() - spawn_started)
            process, stdin, responses = snapshot
            if not self._request_is_current(process, responses):
                self._record_failure("native_client_stream_failed")
                return None
            frame = struct.pack(">I", len(payload)) + payload
            if not self._write_frame(stdin, frame, deadline_monotonic=deadline_monotonic):
                self.close()
                self._record_failure(
                    "native_client_timed_out"
                    if time.monotonic() >= deadline_monotonic
                    else "native_client_frame_write_failed"
                )
                return None
            if not self._request_is_current(process, responses):
                self._record_failure("native_client_stream_failed")
                return None
            # A pool teardown may call close() while this request waits for
            # its response. Hold the lifecycle lock for that wait so teardown
            # cannot close the captured process or queue mid-read. The lock is
            # intentionally acquired after the write, allowing close() to
            # interrupt a blocked write on platforms that need a stoppable
            # writer fallback.
            with self._lifecycle_lock:
                if not self._request_is_current(process, responses):
                    self._record_failure("native_client_stream_failed")
                    return None
                remaining = deadline_monotonic - time.monotonic()
                if remaining <= 0:
                    self.close()
                    self._record_failure("native_client_timed_out")
                    return None
                try:
                    response = responses.get(timeout=remaining)
                except Empty:
                    self.close()
                    self._record_failure("native_client_timed_out")
                    return None
                if isinstance(response, _StreamFailure):
                    self.close()
                    self._record_failure("native_client_stream_failed")
                    return None
                return response

    def _request_is_current(
        self,
        process: subprocess.Popen[bytes],
        responses: Queue[bytes | _StreamFailure],
    ) -> bool:
        """Reject a snapshot invalidated by concurrent client teardown."""

        with self._lifecycle_lock, self._lock:
            return self._process is process and self._responses is responses and process.poll() is None

    def _close_locked(self) -> None:
        process = self._process
        reader = self._reader
        responses = self._responses
        self._process = None
        self._reader = None
        if process is None:
            return
        with suppress(Full):
            responses.put_nowait(_StreamFailure())
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
        with self._lifecycle_lock, self._lock:
            self._close_locked()


__all__ = ["_PersistentNativeClient", "_StreamFailure"]
