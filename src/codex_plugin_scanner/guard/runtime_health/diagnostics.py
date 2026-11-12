"""Asynchronous, bounded diagnostic logging for the local Guard daemon."""

from __future__ import annotations

import json
import logging
import os
import queue
import sys
import threading
from collections.abc import Callable
from contextlib import suppress
from datetime import datetime, timezone
from pathlib import Path
from types import TracebackType
from typing import Final, Literal, final

from typing_extensions import override

_DAEMON_LOG_DIRECTORY: Final = "logs"
_DAEMON_LOG_FILENAME: Final = "daemon.log"
_DEFAULT_QUEUE_CAPACITY: Final = 256
_MAX_RECORDED_EXCEPTION_NAMES: Final = 3
_OWNER_ONLY_DIRECTORY_MODE: Final = 0o700


@final
class _DaemonLogFormatter(logging.Formatter):
    @override
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "timestamp": datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
            "level": record.levelname.lower(),
            "event": getattr(record, "guard_event", record.getMessage()),
        }
        detail = getattr(record, "guard_detail", None)
        if isinstance(detail, str) and detail:
            payload["detail"] = detail
        if record.exc_info is not None:
            names = _exception_names(record.exc_info)
            if names:
                payload["exception"] = names
        return json.dumps(payload, ensure_ascii=True, separators=(",", ":"))


def _exception_names(
    exc_info: tuple[type[BaseException], BaseException, TracebackType | None] | tuple[None, None, None],
) -> str:
    """Reduce a failure to a bounded chain of exception class names.

    `daemon.log` is the artifact an operator hands over, so no record may carry
    an absolute path, a username or anything a caller was holding. A formatted
    traceback carries all three: every frame names a file under the install,
    the source line is printed verbatim, and an exception message repeats what
    it was given - the path an `OSError` could not open, or the URL a client
    was told to reach. The class names answer the question the log is read for,
    which is what failed and what it failed under, and nothing else about the
    machine is recoverable from them. A caller with more to say passes a
    bounded, path-free `detail`.
    """

    names: list[str] = []
    exception: BaseException | None = exc_info[1]
    while exception is not None and len(names) < _MAX_RECORDED_EXCEPTION_NAMES:
        names.append(type(exception).__name__)
        following = exception.__cause__
        if following is None and not exception.__suppress_context__:
            following = exception.__context__
        exception = following
    return " <- ".join(names)


def _secure_directory(path: Path) -> None:
    if path.is_symlink():
        raise OSError("daemon diagnostic directory cannot be a symbolic link")
    path.mkdir(mode=_OWNER_ONLY_DIRECTORY_MODE, parents=True, exist_ok=True)
    with suppress(OSError):
        os.chmod(path, _OWNER_ONLY_DIRECTORY_MODE)


@final
class DaemonDiagnostics:
    """Queue daemon diagnostics so hook and request threads never perform file I/O.

    Records are appended when the caller closes. The native daemon owns daily
    rotation and retention of ``daemon.log``, so a writer here never renames
    the live log out from under it.
    """

    def __init__(self, guard_home: Path, *, queue_capacity: int = _DEFAULT_QUEUE_CAPACITY) -> None:
        self.log_directory = guard_home / _DAEMON_LOG_DIRECTORY
        self.log_path = self.log_directory / _DAEMON_LOG_FILENAME
        self._queue: queue.Queue[logging.LogRecord] = queue.Queue(maxsize=max(1, queue_capacity))
        self._closed = True
        self._close_lock = threading.Lock()
        self._handler: logging.Handler | None = None
        try:
            _secure_directory(self.log_directory)
            if self.log_path.is_symlink():
                raise OSError("daemon diagnostic log cannot be a symbolic link")
            # Opened on first write, so records land in whichever file the
            # daemon's rotation left live.
            self._handler = logging.FileHandler(self.log_path, mode="a", encoding="utf-8", delay=True)
            self._handler.setFormatter(_DaemonLogFormatter())
        except Exception:
            return
        self._closed = False

    def record(self, event: str, *, detail: str | None = None) -> bool:
        return self._enqueue(self._record(logging.INFO, event, detail=detail))

    def record_phase(self, event: str, detail: str) -> bool:
        """Positional adapter so startup phase timing can use this as a sink."""

        return self.record(event, detail=detail)

    def record_background(self, event: str, detail: str) -> bool:
        """Positional error adapter for background workers with no daemon handle.

        The caller passes an already-bounded, path-free detail line, so this
        records no ``exc_info`` at all: the detail is the whole of what these
        records disclose.
        """

        return self._enqueue(self._record(logging.ERROR, event, detail=detail))

    def record_background_notice(self, event: str, detail: str) -> bool:
        """Positional info adapter for an expected background state."""

        return self.record(event, detail=detail)

    def record_exception(
        self,
        event: str,
        *,
        detail: str | None = None,
        exc_info: tuple[type[BaseException], BaseException, TracebackType | None] | Literal[False] | None = None,
    ) -> bool:
        # As in `logging`, False asks for no exception at all. The caller has
        # already reduced the failure to a bounded, path-free line and has
        # nothing to add. True is not accepted: a caller that wants the live
        # exception passes nothing, and what reaches the log is its class name
        # chain, never its message or traceback - see `_exception_names`.
        recorded: tuple[type[BaseException], BaseException, TracebackType | None] | None = exc_info or None
        if exc_info is None:
            exception_type, exception, traceback = sys.exc_info()
            if exception_type is not None and exception is not None:
                recorded = (exception_type, exception, traceback)
        return self._enqueue(self._record(logging.ERROR, event, detail=detail, exc_info=recorded))

    def close(self, *, timeout_seconds: float = 1.0) -> bool:
        from .background_diagnostics import release_sink
        from .startup_phase import release_default_sink

        release_default_sink(self.record_phase)
        release_sink(self.record_background)
        with self._close_lock:
            if self._handler is None or self._closed:
                return True
            self._closed = True
        # A stalled write must not hold the fail-closed hook response. The
        # drain is daemon-threaded so the timeout bounds that write, and a
        # fast disk still finishes before close returns.
        drained = threading.Thread(
            target=self._finish_pending,
            daemon=True,
            name="guard-daemon-diagnostics-drain",
        )
        drained.start()
        drained.join(timeout=max(0.0, timeout_seconds))
        return not drained.is_alive()

    def _record(
        self,
        level: int,
        event: str,
        *,
        detail: str | None,
        exc_info: tuple[type[BaseException], BaseException, TracebackType | None] | None = None,
    ) -> logging.LogRecord:
        record = logging.LogRecord("hol_guard.daemon", level, __file__, 0, event, (), exc_info)
        record.guard_event = event
        record.guard_detail = detail
        return record

    def _finish_pending(self) -> None:
        if not self._queue.empty():
            # The log is owner-only from its first byte; the handler opens it
            # only after this.
            with suppress(OSError):
                os.close(os.open(self.log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600))
            with suppress(OSError):
                os.chmod(self.log_path, 0o600)
        self._drain_pending()
        if self._handler is not None:
            self._handler.close()

    def _drain_pending(self) -> None:
        """Write every queued record.

        Closing the handler with records still queued is how a fail-closed
        deny could reach a harness with nothing written to the log.
        """

        handler = self._handler
        if handler is None:
            return
        while True:
            try:
                record = self._queue.get_nowait()
            except queue.Empty:
                return
            try:
                handler.emit(record)
            except Exception:
                continue
            finally:
                self._queue.task_done()

    def _enqueue(self, record: logging.LogRecord) -> bool:
        if self._closed:
            return False
        try:
            self._queue.put_nowait(record)
        except queue.Full:
            return False
        return True


def background_log_sinks(
    guard_home: Path,
) -> tuple[Callable[[str, str], bool], Callable[[str, str], bool]]:
    """Error and notice sinks that append each background record to ``daemon.log`` at once.

    For a long-lived process that keeps no diagnostics open: a record queued
    until shutdown would be lost to a crash and unread while it mattered. Each
    call opens, writes and closes the log, which only background threads pay.
    """

    def write(event: str, detail: str, *, notice: bool) -> bool:
        diagnostics = DaemonDiagnostics(guard_home)
        record = diagnostics.record_background_notice if notice else diagnostics.record_background
        taken = record(event, detail)
        return diagnostics.close() and taken

    def error(event: str, detail: str) -> bool:
        return write(event, detail, notice=False)

    def notice(event: str, detail: str) -> bool:
        return write(event, detail, notice=True)

    return error, notice
