"""Opt-in absolute deadlines for one off-hook SQLite maintenance operation.

Ordinary connections are unchanged. A bound connection retains its deadline
through its entire lifetime, including after the context that created it exits.
Rollback and close remain available after expiry; neither implies that an
already committed operation was undone.
"""

from __future__ import annotations

import math
import sqlite3
import time
from collections.abc import Generator, Iterable, Iterator
from contextlib import closing, contextmanager
from contextvars import ContextVar
from types import TracebackType
from typing import Any, Literal

from .sqlite_constants import SQLITE_CACHE_SIZE_KIB, SQLITE_MMAP_SIZE_BYTES

_DEADLINE: ContextVar[float | None] = ContextVar("guard_sqlite_maintenance_deadline", default=None)


class SQLiteDeadlineExceededError(TimeoutError):
    """The maintenance operation has exhausted its original deadline."""


class SQLiteDeadlineUnsupportedError(RuntimeError):
    """A connection operation is outside the bounded maintenance interface."""


def sqlite_deadline_monotonic() -> float | None:
    return _DEADLINE.get()


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise SQLiteDeadlineExceededError("SQLite maintenance deadline exceeded")
    return remaining


def sqlite_deadline_timeout(timeout_seconds: float) -> float:
    deadline = _DEADLINE.get()
    return timeout_seconds if deadline is None else min(timeout_seconds, _remaining(deadline))


@contextmanager
def sqlite_maintenance_deadline(deadline_monotonic: float) -> Generator[None]:
    if type(deadline_monotonic) not in (int, float):
        raise ValueError("SQLite maintenance deadline must be finite")
    try:
        finite = math.isfinite(deadline_monotonic)
    except OverflowError:
        finite = False
    if not finite:
        raise ValueError("SQLite maintenance deadline must be finite")
    current = _DEADLINE.get()
    deadline = deadline_monotonic if current is None else min(current, deadline_monotonic)
    _remaining(deadline)
    token = _DEADLINE.set(deadline)
    try:
        yield
        _remaining(deadline)
    finally:
        _DEADLINE.reset(token)


class DeadlineConnection(sqlite3.Connection):
    """An explicit-transaction maintenance connection with owned lock waits.

    Only begin_immediate() and commit() may wait for locks. VM-bearing SQL
    cannot start a fresh busy wait after computation; writes require an
    explicit transaction. SQLite authorizer actions enforce this before step.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        deadline = _DEADLINE.get()
        if deadline is None:
            raise SQLiteDeadlineUnsupportedError("SQLite deadline connection requires an active scope")
        _remaining(deadline)
        self._deadline = deadline
        self._timeout_ceiling = float(args[1] if len(args) > 1 else kwargs.get("timeout", 5.0))
        # Authorization depends on the current transaction. Never reuse a
        # statement authorized in a different transaction context.
        if len(args) > 6:
            args = (*args[:6], 0, *args[7:])
        else:
            kwargs["cached_statements"] = 0
        super().__init__(*args, **kwargs)
        if self.isolation_level is None or getattr(self, "autocommit", -1) != -1:
            super().close()
            raise SQLiteDeadlineUnsupportedError("Implicit autocommit is unavailable in a SQLite deadline scope")
        self._deadline_initialized = True
        self._transaction_control: str | None = None
        self._internal_pragma = False
        self._unsupported = False
        self._interrupted = False
        self._deadline_closed = False
        sqlite3.Connection.set_progress_handler(self, self._progress, 1)
        sqlite3.Connection.set_authorizer(self, self._authorize)

    def __setattr__(self, name: str, value: Any) -> None:
        if name in {"isolation_level", "autocommit"} and getattr(self, "_deadline_initialized", False):
            raise SQLiteDeadlineUnsupportedError("SQLite transaction ownership cannot be changed")
        super().__setattr__(name, value)

    def __delattr__(self, name: str) -> None:
        if name in {"isolation_level", "autocommit"}:
            raise SQLiteDeadlineUnsupportedError("SQLite transaction ownership cannot be changed")
        super().__delattr__(name)

    def _authorize(
        self, action: int, first: str | None, second: str | None, database: str | None, source: str | None
    ) -> int:
        del source
        allowed = False
        if action == sqlite3.SQLITE_TRANSACTION:
            allowed = first == self._transaction_control
        elif action == sqlite3.SQLITE_PRAGMA:
            name = (first or "").lower()
            allowed = (
                (self._internal_pragma and name == "busy_timeout")
                or (name in {"busy_timeout", "journal_mode"} and second is None)
                or (name == "synchronous" and second is not None and second.lower() == "normal")
                or (name == "cache_size" and second == str(-SQLITE_CACHE_SIZE_KIB))
                or (name == "mmap_size" and second == str(SQLITE_MMAP_SIZE_BYTES))
            )
        elif action in {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_FUNCTION, sqlite3.SQLITE_RECURSIVE}:
            allowed = database in {None, "main", "temp"} and not (
                action == sqlite3.SQLITE_FUNCTION and second == "load_extension"
            )
        elif action in {
            sqlite3.SQLITE_INSERT,
            sqlite3.SQLITE_UPDATE,
            sqlite3.SQLITE_DELETE,
            sqlite3.SQLITE_CREATE_INDEX,
            sqlite3.SQLITE_CREATE_TABLE,
            sqlite3.SQLITE_CREATE_TRIGGER,
            sqlite3.SQLITE_CREATE_VIEW,
            sqlite3.SQLITE_DROP_INDEX,
            sqlite3.SQLITE_DROP_TABLE,
            sqlite3.SQLITE_DROP_TRIGGER,
            sqlite3.SQLITE_DROP_VIEW,
            sqlite3.SQLITE_ALTER_TABLE,
            sqlite3.SQLITE_REINDEX,
            sqlite3.SQLITE_ANALYZE,
        }:
            allowed = self.in_transaction and database == "main"
        if not allowed:
            self._unsupported = True
        return sqlite3.SQLITE_OK if allowed else sqlite3.SQLITE_DENY

    def set_authorizer(self, authorizer_callback: Any) -> None:
        raise SQLiteDeadlineUnsupportedError("SQLite deadline authorizer ownership cannot be replaced")

    def backup(self, *args: Any, **kwargs: Any) -> None:
        raise SQLiteDeadlineUnsupportedError("SQLite backup is outside the maintenance interface")

    def blobopen(self, *args: Any, **kwargs: Any) -> Any:
        raise SQLiteDeadlineUnsupportedError("SQLite blob handles are outside the maintenance interface")

    def deserialize(self, *args: Any, **kwargs: Any) -> None:
        raise SQLiteDeadlineUnsupportedError("SQLite database replacement is outside the maintenance interface")

    def enable_load_extension(self, enabled: bool) -> None:
        raise SQLiteDeadlineUnsupportedError("SQLite extensions are outside the maintenance interface")

    def load_extension(self, *args: Any, **kwargs: Any) -> None:
        raise SQLiteDeadlineUnsupportedError("SQLite extensions are outside the maintenance interface")

    def create_function(self, *args: Any, **kwargs: Any) -> None:
        raise SQLiteDeadlineUnsupportedError("SQLite callbacks are outside the maintenance interface")

    def create_aggregate(self, *args: Any, **kwargs: Any) -> None:
        raise SQLiteDeadlineUnsupportedError("SQLite callbacks are outside the maintenance interface")

    def create_window_function(self, *args: Any, **kwargs: Any) -> None:
        raise SQLiteDeadlineUnsupportedError("SQLite callbacks are outside the maintenance interface")

    def create_collation(self, *args: Any, **kwargs: Any) -> None:
        raise SQLiteDeadlineUnsupportedError("SQLite callbacks are outside the maintenance interface")

    def set_trace_callback(self, trace_callback: Any) -> None:
        raise SQLiteDeadlineUnsupportedError("SQLite callbacks are outside the maintenance interface")

    def _bound_deadline(self) -> float:
        current = _DEADLINE.get()
        return self._deadline if current is None else min(self._deadline, current)

    def _progress(self) -> int:
        if time.monotonic() >= self._bound_deadline():
            self._interrupted = True
            return 1
        return 0

    def set_progress_handler(self, progress_handler: Any, n: int) -> None:
        raise SQLiteDeadlineUnsupportedError("SQLite deadline progress ownership cannot be replaced")

    @contextmanager
    def _operation(self, *, wait_for_lock: bool = False) -> Iterator[None]:
        self._interrupted = False
        self._unsupported = False
        try:
            self._prepare(wait_for_lock=wait_for_lock)
            yield
            self._completed()
        except sqlite3.DatabaseError:
            if self._unsupported:
                raise SQLiteDeadlineUnsupportedError("SQL operation is outside the maintenance interface") from None
            if self._interrupted or time.monotonic() >= self._bound_deadline():
                raise SQLiteDeadlineExceededError("SQLite maintenance deadline exceeded") from None
            raise

    def _set_busy_timeout(self, timeout_ms: int) -> None:
        self._internal_pragma = True
        try:
            # Connection.execute re-enters cursor overrides on Python 3.10.
            with closing(sqlite3.Connection.cursor(self, sqlite3.Cursor)) as cursor:
                cursor.execute(f"pragma busy_timeout={timeout_ms}")
        finally:
            self._internal_pragma = False

    def _prepare(self, *, wait_for_lock: bool = False) -> None:
        remaining = _remaining(self._bound_deadline())
        timeout_ms = int(min(self._timeout_ceiling, remaining) * 1000) if wait_for_lock else 0
        self._set_busy_timeout(timeout_ms)

    def begin_immediate(self) -> None:
        self._transaction_control = "BEGIN"
        try:
            with (
                self._operation(wait_for_lock=True),
                closing(sqlite3.Connection.cursor(self, sqlite3.Cursor)) as cursor,
            ):
                cursor.execute("begin immediate")
        finally:
            self._transaction_control = None

    def _completed(self) -> None:
        _remaining(self._bound_deadline())

    def cursor(self, factory: Any = None) -> DeadlineCursor:
        if factory is not None and factory is not DeadlineCursor:
            raise SQLiteDeadlineUnsupportedError("Custom cursors are unavailable in a SQLite deadline scope")
        self._completed()
        return super().cursor(DeadlineCursor)

    def execute(self, sql: str, parameters: Any = (), /) -> DeadlineCursor:
        return self.cursor().execute(sql, parameters)

    def executemany(self, sql: str, parameters: Iterable[Any], /) -> DeadlineCursor:
        return self.cursor().executemany(sql, parameters)

    def executescript(self, sql_script: str, /) -> DeadlineCursor:
        raise SQLiteDeadlineUnsupportedError("SQL scripts are unavailable in a SQLite deadline scope")

    def commit(self) -> None:
        self._transaction_control = "COMMIT"
        try:
            with self._operation(wait_for_lock=True):
                super().commit()
        finally:
            self._transaction_control = None

    def rollback(self) -> None:
        # Cleanup remains possible on expiry without opening a fresh wait or
        # allowing the expired VM handler to interrupt rollback itself.
        sqlite3.Connection.set_progress_handler(self, None, 0)
        self._transaction_control = "ROLLBACK"
        try:
            self._set_busy_timeout(0)
            super().rollback()
        finally:
            self._transaction_control = None
            sqlite3.Connection.set_progress_handler(self, self._progress, 1)

    def close(self) -> None:
        if self._deadline_closed:
            return
        sqlite3.Connection.set_progress_handler(self, None, 0)
        super().close()
        self._deadline_closed = True

    def __enter__(self) -> DeadlineConnection:
        self._completed()
        _ = super().__enter__()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> Literal[False]:
        if exc_type is not None:
            self.rollback()
            return super().__exit__(exc_type, exc_value, traceback)
        try:
            self.commit()
            return False
        except Exception:
            self.rollback()
            raise


class DeadlineCursor(sqlite3.Cursor):
    def _owner(self) -> DeadlineConnection:
        connection = self.connection
        if not isinstance(connection, DeadlineConnection):
            raise SQLiteDeadlineUnsupportedError("SQLite deadline cursor requires its bound connection")
        return connection

    def execute(self, sql: str, parameters: Any = (), /) -> DeadlineCursor:
        owner = self._owner()
        with owner._operation():
            super().execute(sql, parameters)
        return self

    def executemany(self, sql: str, parameters: Iterable[Any], /) -> DeadlineCursor:
        owner = self._owner()

        def bounded_parameters() -> Iterator[Any]:
            for values in parameters:
                owner._prepare()
                yield values

        with owner._operation():
            super().executemany(sql, bounded_parameters())
        return self

    def executescript(self, sql_script: str, /) -> DeadlineCursor:
        raise SQLiteDeadlineUnsupportedError("SQL scripts are unavailable in a SQLite deadline scope")

    def fetchone(self) -> Any:
        with self._owner()._operation():
            return super().fetchone()

    def fetchmany(self, size: int | None = None) -> list[Any]:
        with self._owner()._operation():
            return super().fetchmany() if size is None else super().fetchmany(size)

    def fetchall(self) -> list[Any]:
        with self._owner()._operation():
            return super().fetchall()

    def __next__(self) -> Any:
        with self._owner()._operation():
            return super().__next__()
