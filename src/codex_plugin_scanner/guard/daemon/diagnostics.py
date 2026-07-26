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
from typing import Final, final

from typing_extensions import override

_DAEMON_LOG_DIRECTORY: Final = "logs"
_DAEMON_LOG_FILENAME: Final = "daemon.log"
_DAEMON_LOG_RETENTION_SECONDS: Final = 7 * 24 * 60 * 60
_DEFAULT_QUEUE_CAPACITY: Final = 256
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
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=True, separators=(",", ":"))


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
    ) -> None:
        self.log_directory = guard_home / _DAEMON_LOG_DIRECTORY
        self.log_path = self.log_directory / _DAEMON_LOG_FILENAME
        self._queue: queue.Queue[logging.LogRecord] = queue.Queue(maxsize=max(1, queue_capacity))
        self._closed = True
        self._close_lock = threading.Lock()
        self._stop_requested = threading.Event()
        self._handler: TimedRotatingFileHandler | None = None
        self._thread: threading.Thread | None = None
        try:
            _secure_directory(self.log_directory)
            cleanup_expired_daemon_logs(self.log_directory)
            if self.log_path.is_symlink():
                raise OSError("daemon diagnostic log cannot be a symbolic link")
            self._handler = TimedRotatingFileHandler(
                self.log_path,
                when="midnight",
                interval=1,
                backupCount=7,
                encoding="utf-8",
                utc=True,
            )
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

    def record_exception(
        self,
        event: str,
        *,
        detail: str | None = None,
        exc_info: tuple[type[BaseException], BaseException, TracebackType | None] | None = None,
    ) -> bool:
        if exc_info is None:
            exception_type, exception, traceback = sys.exc_info()
            if exception_type is not None and exception is not None:
                exc_info = (exception_type, exception, traceback)
        return self._enqueue(self._record(logging.ERROR, event, detail=detail, exc_info=exc_info))

    def close(self, *, timeout_seconds: float = 1.0) -> bool:
        with self._close_lock:
            if self._handler is None:
                return True
            if self._closed:
                return self._thread is None or not self._thread.is_alive()
            self._closed = True
            if self._thread is None:
                self._handler.close()
                return True
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
