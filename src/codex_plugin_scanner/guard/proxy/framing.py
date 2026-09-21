"""Bounded JSON-lines transport primitives for the local MCP proxies.

One reader owns each stream, including partial lines across quiet polls. POSIX
pipes use nonblocking byte reads; a ready descriptor never leads to a blocking
``readline``. Other streams retain at most one bounded reader/writer worker.
An ambiguous write poisons that stream permanently and must end the session.
"""

from __future__ import annotations

import contextvars
import io
import json
import math
import os
import queue
import select
import threading
import time
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager, suppress
from functools import wraps
from typing import Any, ParamSpec, TypeVar, cast

MAX_LINE_BYTES = 4 * 1024 * 1024
MAX_QUEUED_FRAMES = 64
MAX_QUEUED_BYTES = 16 * 1024 * 1024
MAX_BUFFERED_RESPONSES = 64
MAX_BUFFERED_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_OPERATION_FRAMES = 4096
MAX_OPERATION_DEPTH = 16
FRAME_ASSEMBLY_SECONDS = 30.0
_CHUNK_BYTES = 64 * 1024
_STATE_LOCK = threading.Lock()


class ProxyIoTimeoutError(TimeoutError):
    def __init__(self, *, source: str, timeout_seconds: float) -> None:
        super().__init__(f"timeout waiting for {source}")
        self.source = source
        self.timeout_seconds = timeout_seconds
        self.reason = "deadline_exceeded"


class ProxyIoLimitError(RuntimeError):
    def __init__(self, *, source: str, reason: str) -> None:
        super().__init__(f"guard_proxy_{reason}")
        self.source = source
        self.reason = reason


IO_FAILURES = (ProxyIoTimeoutError, ProxyIoLimitError)


class _Budget:
    def __init__(self, deadline: float) -> None:
        self.deadline = deadline
        self.frames = 0
        self.depth = 0


_BUDGET: contextvars.ContextVar[_Budget | None] = contextvars.ContextVar("guard_mcp_io_budget", default=None)


def remaining_timeout(timeout_seconds: float, *, source: str) -> float:
    budget = _BUDGET.get()
    remaining = timeout_seconds if budget is None else min(timeout_seconds, budget.deadline - time.monotonic())
    if remaining <= 0:
        raise ProxyIoTimeoutError(source=source, timeout_seconds=max(0.0, timeout_seconds))
    return remaining


def count_frame(*, source: str) -> None:
    budget = _BUDGET.get()
    if budget is not None:
        budget.frames += 1
        if budget.frames > MAX_OPERATION_FRAMES:
            raise ProxyIoLimitError(source=source, reason="operation_frame_limit")


@contextmanager
def operation_budget(timeout_seconds: float, *, source: str) -> Iterator[None]:
    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        raise ProxyIoTimeoutError(source=source, timeout_seconds=0)
    parent = _BUDGET.get()
    budget = parent or _Budget(time.monotonic() + timeout_seconds)
    previous = budget.deadline
    budget.deadline = min(previous, time.monotonic() + timeout_seconds)
    budget.depth += 1
    token = _BUDGET.set(budget)
    try:
        if budget.depth > MAX_OPERATION_DEPTH:
            raise ProxyIoLimitError(source=source, reason="operation_depth_limit")
        yield
    finally:
        budget.depth -= 1
        budget.deadline = previous
        _BUDGET.reset(token)


P = ParamSpec("P")
R = TypeVar("R")


def bounded_operation(timeout: Callable[[Any], float], *, source: str) -> Callable[[Callable[P, R]], Callable[P, R]]:
    def decorate(function: Callable[P, R]) -> Callable[P, R]:
        @wraps(function)
        def call(*args: P.args, **kwargs: P.kwargs) -> R:
            with operation_budget(timeout(args[0]), source=source):
                return function(*args, **kwargs)

        return call

    return decorate


def stream_fileno(stream: Any) -> int | None:
    try:
        descriptor = stream.fileno()
    except (AttributeError, OSError, ValueError, io.UnsupportedOperation):
        return None
    return descriptor if isinstance(descriptor, int) and descriptor >= 0 else None


def encoded_line(payload: Mapping[str, Any]) -> bytes:
    # iterencode bounds the aggregate before materializing a second full JSON
    # string. A single input string is itself bounded at the framing boundary.
    parts: list[bytes] = []
    total = 1
    try:
        for part in json.JSONEncoder(ensure_ascii=False, separators=(",", ":"), allow_nan=False).iterencode(payload):
            encoded = part.encode("utf-8")
            total += len(encoded)
            if total > MAX_LINE_BYTES:
                raise ProxyIoLimitError(source="write", reason="line_bytes_limit")
            parts.append(encoded)
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise ProxyIoLimitError(source="write", reason="invalid_json_frame") from exc
    return b"".join(parts) + b"\n"


class _LineReader:
    def __init__(self, stream: Any) -> None:
        self.descriptor = stream_fileno(stream)
        self.pending = bytearray()
        self.started: float | None = None
        self.eof = False
        self.error: ProxyIoLimitError | None = None
        self.lock = threading.Lock()
        self.worker_result: queue.Queue[str | BaseException] | None = None
        self.chunk_results: queue.Queue[bytes | BaseException] | None = None
        self.stopped = threading.Event()
        self.original_blocking: bool | None = None

    def close(self) -> None:
        self.stopped.set()
        if self.descriptor is not None and self.original_blocking is not None:
            with suppress(OSError, ValueError):
                os.set_blocking(self.descriptor, self.original_blocking)
        self.error = ProxyIoLimitError(source="read", reason="stream_retired")

    def _take_line(self, *, source: str) -> str | None:
        newline = self.pending.find(b"\n")
        if newline >= 0:
            raw = bytes(self.pending[: newline + 1])
            del self.pending[: newline + 1]
            self.started = time.monotonic() if self.pending else None
        elif self.eof:
            if self.pending:
                raise ProxyIoLimitError(source=source, reason="unterminated_frame")
            return ""
        else:
            return None
        if len(raw) > MAX_LINE_BYTES:
            raise ProxyIoLimitError(source=source, reason="line_bytes_limit")
        try:
            return raw.decode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise ProxyIoLimitError(source=source, reason="invalid_utf8") from exc

    def readline(self, stream: Any, timeout_seconds: float | None, *, source: str, allow_background_wait: bool) -> str:
        with self.lock:
            if self.error is not None:
                raise self.error
            try:
                return self._readline(
                    stream, timeout_seconds, source=source, allow_background_wait=allow_background_wait
                )
            except ProxyIoLimitError as exc:
                self.error = exc
                raise

    def _readline(self, stream: Any, timeout_seconds: float | None, *, source: str, allow_background_wait: bool) -> str:
        if isinstance(stream, io.StringIO):
            line = stream.readline(MAX_LINE_BYTES + 1)
            if len(line.encode("utf-8")) > MAX_LINE_BYTES:
                raise ProxyIoLimitError(source=source, reason="line_bytes_limit")
            return line
        if self.descriptor is None or os.name == "nt":
            if not allow_background_wait and self.descriptor is None:
                raise ProxyIoTimeoutError(source=source, timeout_seconds=timeout_seconds or 0)
            if self.descriptor is not None:
                return self._worker_pipe_readline(timeout_seconds, source=source)
            return self._worker_readline(stream, timeout_seconds, source=source)
        if self.original_blocking is None:
            self.original_blocking = os.get_blocking(self.descriptor)
            os.set_blocking(self.descriptor, False)
        deadline = None if timeout_seconds is None else time.monotonic() + max(0.0, timeout_seconds)
        attempted = False
        while True:
            line = self._take_line(source=source)
            if line is not None:
                return line
            now = time.monotonic()
            if deadline is not None and now >= deadline and (attempted or bool(timeout_seconds)):
                raise ProxyIoTimeoutError(source=source, timeout_seconds=timeout_seconds or 0)
            if self.started is not None and now - self.started >= FRAME_ASSEMBLY_SECONDS:
                raise ProxyIoLimitError(source=source, reason="frame_assembly_deadline")
            wait = None if deadline is None else max(0.0, deadline - now)
            if self.started is not None:
                frame_wait = max(0.0, self.started + FRAME_ASSEMBLY_SECONDS - now)
                wait = frame_wait if wait is None else min(wait, frame_wait)
            try:
                ready, _, _ = select.select([self.descriptor], [], [], wait)
            except (OSError, ValueError) as exc:
                raise ProxyIoTimeoutError(source=source, timeout_seconds=timeout_seconds or 0) from exc
            if not ready:
                if self.started is not None and time.monotonic() - self.started >= FRAME_ASSEMBLY_SECONDS:
                    raise ProxyIoLimitError(source=source, reason="frame_assembly_deadline")
                raise ProxyIoTimeoutError(source=source, timeout_seconds=timeout_seconds or 0)
            try:
                chunk = os.read(self.descriptor, min(_CHUNK_BYTES, MAX_LINE_BYTES + 1 - len(self.pending)))
            except BlockingIOError:
                continue
            except OSError as exc:
                raise ProxyIoLimitError(source=source, reason="stream_read_failed") from exc
            attempted = True
            if not chunk:
                self.eof = True
                continue
            if not self.pending:
                self.started = time.monotonic()
            self.pending.extend(chunk)
            if len(self.pending) > MAX_LINE_BYTES and b"\n" not in self.pending[:MAX_LINE_BYTES]:
                raise ProxyIoLimitError(source=source, reason="line_bytes_limit")

    def _worker_pipe_readline(self, timeout_seconds: float | None, *, source: str) -> str:
        if self.chunk_results is None:
            chunks: queue.Queue[bytes | BaseException] = queue.Queue(maxsize=2)
            self.chunk_results = chunks
            descriptor = self.descriptor
            assert descriptor is not None
            descriptor = os.dup(descriptor)

            def read_chunks() -> None:
                try:
                    while not self.stopped.is_set():
                        try:
                            chunk: bytes | BaseException = os.read(descriptor, _CHUNK_BYTES)
                        except BaseException as exc:
                            chunk = exc
                        while not self.stopped.is_set():
                            try:
                                chunks.put(chunk, timeout=0.05)
                                break
                            except queue.Full:
                                continue
                        if not chunk or isinstance(chunk, BaseException):
                            return
                finally:
                    os.close(descriptor)

            threading.Thread(target=read_chunks, name="guard-mcp-bounded-pipe-reader", daemon=True).start()
        deadline = None if timeout_seconds is None else time.monotonic() + max(0.0, timeout_seconds)
        attempted = False
        while True:
            line = self._take_line(source=source)
            if line is not None:
                return line
            now = time.monotonic()
            if deadline is not None and now >= deadline and (attempted or bool(timeout_seconds)):
                raise ProxyIoTimeoutError(source=source, timeout_seconds=timeout_seconds or 0)
            wait = None if deadline is None else max(0.0, deadline - now)
            if self.started is not None:
                frame_wait = max(0.0, self.started + FRAME_ASSEMBLY_SECONDS - now)
                if frame_wait == 0:
                    raise ProxyIoLimitError(source=source, reason="frame_assembly_deadline")
                wait = frame_wait if wait is None else min(wait, frame_wait)
            try:
                chunk = self.chunk_results.get(timeout=wait)
            except queue.Empty as exc:
                if self.started is not None and time.monotonic() - self.started >= FRAME_ASSEMBLY_SECONDS:
                    raise ProxyIoLimitError(source=source, reason="frame_assembly_deadline") from exc
                raise ProxyIoTimeoutError(source=source, timeout_seconds=timeout_seconds or 0) from exc
            attempted = True
            if isinstance(chunk, BaseException):
                raise ProxyIoLimitError(source=source, reason="stream_read_failed") from chunk
            if not chunk:
                self.eof = True
                continue
            if not self.pending:
                self.started = time.monotonic()
            self.pending.extend(chunk)
            if len(self.pending) > MAX_LINE_BYTES and b"\n" not in self.pending[:MAX_LINE_BYTES]:
                raise ProxyIoLimitError(source=source, reason="line_bytes_limit")

    def _worker_readline(self, stream: Any, timeout_seconds: float | None, *, source: str) -> str:
        # A timeout reuses the one outstanding read. It never creates another
        # consumer or discards a late result. Session owners retire the stream.
        if self.worker_result is None:
            results: queue.Queue[str | BaseException] = queue.Queue(maxsize=1)
            self.worker_result = results

            def read() -> None:
                try:
                    result = stream.readline(MAX_LINE_BYTES + 1)
                except BaseException as exc:
                    result = exc
                results.put_nowait(result)

            threading.Thread(target=read, name="guard-mcp-bounded-reader", daemon=True).start()
        try:
            line = self.worker_result.get(timeout=timeout_seconds)
        except queue.Empty as exc:
            raise ProxyIoTimeoutError(source=source, timeout_seconds=timeout_seconds or 0) from exc
        self.worker_result = None
        if isinstance(line, BaseException):
            raise ProxyIoLimitError(source=source, reason="stream_read_failed") from line
        if not isinstance(line, str) or len(line.encode("utf-8")) > MAX_LINE_BYTES:
            raise ProxyIoLimitError(source=source, reason="line_bytes_limit")
        if line and not line.endswith("\n"):
            raise ProxyIoLimitError(source=source, reason="unterminated_frame")
        return line


def read_line(stream: Any, timeout_seconds: float | None, *, source: str, allow_background_wait: bool = True) -> str:
    if timeout_seconds is not None and timeout_seconds > 0:
        timeout_seconds = remaining_timeout(timeout_seconds, source=source)
    with _STATE_LOCK:
        reader = getattr(stream, "_guard_mcp_line_reader", None)
        if reader is None:
            reader = _LineReader(stream)
            try:
                stream._guard_mcp_line_reader = reader
            except (AttributeError, TypeError) as exc:
                raise ProxyIoLimitError(source=source, reason="stream_ownership_unavailable") from exc
    return reader.readline(stream, timeout_seconds, source=source, allow_background_wait=allow_background_wait)


def retire_reader(stream: Any) -> None:
    reader = getattr(stream, "_guard_mcp_line_reader", None)
    if reader is not None:
        reader.close()


def write_timeout_reply(stream: Any, payload: Mapping[str, Any]) -> None:
    """Deliver only a JSON-RPC timeout error after the request budget expires.

    This bounded control reply cannot reset the caller's semantic operation or
    carry another request. It preserves MCP nested-request cancellation.
    """

    if "method" in payload or "result" in payload or not isinstance(error := payload.get("error"), Mapping):
        raise ProxyIoLimitError(source="timeout_reply", reason="invalid_control_reply")
    if not isinstance(data := error.get("data"), Mapping) or data.get("guard_timeout") is not True:
        raise ProxyIoLimitError(source="timeout_reply", reason="invalid_control_reply")
    token = _BUDGET.set(None)
    try:
        write_message(stream, payload, timeout_seconds=0.25, source="timeout_reply")
    finally:
        _BUDGET.reset(token)


def write_message(stream: Any, payload: Mapping[str, Any], *, timeout_seconds: float, source: str) -> None:
    if getattr(stream, "_guard_mcp_write_failed", False):
        raise ProxyIoLimitError(source=source, reason="stream_retired")
    data = encoded_line(payload)
    _write_encoded_line(stream, data, timeout_seconds=timeout_seconds, source=source)


def _write_encoded_line(stream: Any, data: bytes, *, timeout_seconds: float, source: str) -> None:
    """Write already encoded private bytes without re-reading mutable inputs."""

    if getattr(stream, "_guard_mcp_write_failed", False):
        raise ProxyIoLimitError(source=source, reason="stream_retired")
    if type(data) is not bytes or len(data) > MAX_LINE_BYTES or not data.endswith(b"\n"):
        raise ProxyIoLimitError(source=source, reason="invalid_json_frame")
    timeout_seconds = remaining_timeout(timeout_seconds, source=source)
    deadline = time.monotonic() + timeout_seconds
    descriptor = stream_fileno(stream)
    try:
        if isinstance(stream, io.StringIO):
            stream.write(data.decode("utf-8"))
            return
        if descriptor is not None and os.name != "nt":
            original = os.get_blocking(descriptor)
            os.set_blocking(descriptor, False)
            try:
                offset = 0
                while offset < len(data):
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise ProxyIoTimeoutError(source=source, timeout_seconds=timeout_seconds)
                    _, ready, _ = select.select([], [descriptor], [], remaining)
                    if not ready:
                        raise ProxyIoTimeoutError(source=source, timeout_seconds=timeout_seconds)
                    try:
                        written = os.write(descriptor, memoryview(data)[offset:])
                    except BlockingIOError:
                        continue
                    if written <= 0:
                        raise OSError("write did not advance")
                    offset += written
            finally:
                with suppress(OSError, ValueError):
                    os.set_blocking(descriptor, original)
            return
        finished = threading.Event()
        cancelled = threading.Event()
        failures: list[BaseException] = []

        def write() -> None:
            try:
                if descriptor is not None:
                    offset = 0
                    while offset < len(data) and not cancelled.is_set():
                        written = os.write(descriptor, data[offset : offset + _CHUNK_BYTES])
                        if written <= 0:
                            raise OSError("incomplete pipe write")
                        offset += written
                    return
                text = data.decode("utf-8")
                count = stream.write(text)
                if count is not None and count != len(text):
                    raise OSError("incomplete text write")
                stream.flush()
            except BaseException as exc:
                failures.append(exc)
            finally:
                finished.set()

        threading.Thread(target=write, name="guard-mcp-bounded-writer", daemon=True).start()
        if not finished.wait(max(0.0, deadline - time.monotonic())):
            cancelled.set()
            # Do not synchronously close a buffered object held by the worker:
            # close may wait for its lock indefinitely. The session quarantines
            # the child, and this stream can never accept another write.
            raise ProxyIoTimeoutError(source=source, timeout_seconds=timeout_seconds)
        if failures:
            raise ProxyIoLimitError(source=source, reason="stream_write_failed") from failures[0]
    except (ProxyIoTimeoutError, ProxyIoLimitError, OSError, ValueError) as exc:
        cast(Any, stream)._guard_mcp_write_failed = True
        if isinstance(exc, IO_FAILURES):
            raise
        raise ProxyIoLimitError(source=source, reason="stream_write_failed") from exc


T = TypeVar("T")


class ByteBoundedQueue(queue.Queue[T]):
    """Nonblocking admission with both frame and byte ceilings."""

    def __init__(self, size: Callable[[T], int]) -> None:
        super().__init__(maxsize=MAX_QUEUED_FRAMES)
        self._size = size
        self.bytes_queued = 0

    def put(self, item: T, block: bool = True, timeout: float | None = None) -> None:
        del block, timeout
        super().put(item, block=False)

    def _put(self, item: T) -> None:
        cost = self._size(item)
        if cost > MAX_LINE_BYTES or self.bytes_queued + cost > MAX_QUEUED_BYTES:
            raise ProxyIoLimitError(source="child_output", reason="queue_bytes_limit")
        self.bytes_queued += cost
        super()._put(item)

    def _get(self) -> T:
        item = super()._get()
        self.bytes_queued -= self._size(item)
        return item


def admit_response(buffers: dict[str, list[dict[str, Any]]], key: str, payload: dict[str, Any]) -> None:
    count = 0
    size = len(encoded_line(payload))
    for responses in buffers.values():
        count += len(responses)
        if count >= MAX_BUFFERED_RESPONSES:
            raise ProxyIoLimitError(source="response_buffer", reason="response_count_limit")
        for response in responses:
            size += len(encoded_line(response))
            if size > MAX_BUFFERED_RESPONSE_BYTES:
                raise ProxyIoLimitError(source="response_buffer", reason="response_bytes_limit")
    if size > MAX_BUFFERED_RESPONSE_BYTES:
        raise ProxyIoLimitError(source="response_buffer", reason="response_bytes_limit")
    buffers.setdefault(key, []).append(payload)
