"""Asynchronous, bounded diagnostic logging for the local Guard daemon."""

from __future__ import annotations

import json
import logging
import os
import queue
import sys
import threading
import time
from contextlib import suppress
from datetime import datetime, timezone
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path
from types import TracebackType
from typing import Final, Literal, final

from typing_extensions import override

_DAEMON_LOG_DIRECTORY: Final = "logs"
_DAEMON_LOG_FILENAME: Final = "daemon.log"
_DAEMON_LOG_RETENTION_SECONDS: Final = 7 * 24 * 60 * 60
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


def cleanup_expired_daemon_logs(log_directory: Path, *, now: float | None = None) -> None:
    """Delete rotated daemon logs older than the fixed local retention period."""

    cutoff = (time.time() if now is None else now) - _DAEMON_LOG_RETENTION_SECONDS
    for candidate in log_directory.glob(f"{_DAEMON_LOG_FILENAME}.*"):
        try:
            if candidate.lstat().st_mtime < cutoff:
                candidate.unlink()
        except OSError:
            continue


@final
class DaemonDiagnostics:
    """Queue daemon diagnostics so hook and request threads never perform file I/O."""

    def __init__(
        self,
        guard_home: Path,
        *,
        queue_capacity: int = _DEFAULT_QUEUE_CAPACITY,
        start_worker: bool = True,
        rotate: bool = True,
    ) -> None:
        self.log_directory = guard_home / _DAEMON_LOG_DIRECTORY
        self.log_path = self.log_directory / _DAEMON_LOG_FILENAME
        self._queue: queue.Queue[logging.LogRecord] = queue.Queue(maxsize=max(1, queue_capacity))
        self._closed = True
        self._close_lock = threading.Lock()
        self._stop_requested = threading.Event()
        self._handler: logging.Handler | None = None
        self._thread: threading.Thread | None = None
        try:
            _secure_directory(self.log_directory)
            # The long-running daemon owns retention. A one-shot hook must not
            # scan and unlink rotated logs on the fail-closed path.
            if rotate:
                cleanup_expired_daemon_logs(self.log_directory)
            if self.log_path.is_symlink():
                raise OSError("daemon diagnostic log cannot be a symbolic link")
            # The long-running daemon owns midnight rotation. A one-shot CLI
            # hook that opens the same file with its own rotating handler can
            # rename the live log out from under the daemon, and on Windows
            # that rename fails into the hook's stderr.
            if rotate:
                self._handler = TimedRotatingFileHandler(
                    self.log_path,
                    when="midnight",
                    interval=1,
                    backupCount=7,
                    encoding="utf-8",
                    utc=True,
                )
            else:
                self._handler = logging.FileHandler(self.log_path, mode="a", encoding="utf-8")
            self._handler.setFormatter(_DaemonLogFormatter())
            with suppress(OSError):
                os.chmod(self.log_path, 0o600)
        except Exception:
            return
        self._closed = False
        if start_worker:
            self._thread = threading.Thread(target=self._run, daemon=True, name="guard-daemon-diagnostics")
            self._thread.start()

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
            if self._handler is None:
                return True
            if self._closed:
                return self._thread is None or not self._thread.is_alive()
            self._closed = True
            if self._thread is None:
                # A stalled write must not hold the fail-closed hook response.
                # The drain is daemon-threaded so the timeout bounds that write,
                # and a fast disk still finishes before close returns.
                drained = threading.Thread(
                    target=self._finish_pending,
                    daemon=True,
                    name="guard-daemon-diagnostics-drain",
                )
                drained.start()
                drained.join(timeout=max(0.0, timeout_seconds))
                return not drained.is_alive()
            self._stop_requested.set()
        self._thread.join(timeout=max(0.0, timeout_seconds))
        return not self._thread.is_alive()

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
        self._drain_pending()
        if self._handler is not None:
            self._handler.close()

    def _drain_pending(self) -> None:
        """Write queued records when no worker thread owns the handler.

        Callers that run without a worker (one-shot CLI hooks) would otherwise
        close the handler with their records still in the queue, which is how a
        fail-closed deny can reach a harness with nothing written to the log.
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

    def _run(self) -> None:
        try:
            while not self._stop_requested.is_set() or not self._queue.empty():
                try:
                    item = self._queue.get(timeout=0.05)
                except queue.Empty:
                    continue
                try:
                    handler = self._handler
                    if handler is not None:
                        handler.emit(item)
                except Exception:
                    continue
                finally:
                    self._queue.task_done()
        finally:
            if self._handler is not None:
                self._handler.close()
