"""Enforce operation clocks on SQLite statements and query progress."""

from __future__ import annotations

import sqlite3
import time
from collections.abc import Callable, Generator, Iterable, Iterator
from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path
from types import TracebackType
from typing import Any, Literal, cast

from .sqlite_tuning import sqlite_connect_timeout_seconds, sqlite_operation_deadline_monotonic


def connect_sqlite_with_deadline(
    database: str | Path,
    *,
    timeout_seconds: float,
    uri: bool = False,
) -> sqlite3.Connection:
    """Open recovery storage with the same remaining budget as its caller."""

    timeout = min(timeout_seconds, sqlite_connect_timeout_seconds())
    if timeout <= 0:
        raise TimeoutError("Guard storage operation deadline expired.")
    factory = sqlite3.Connection if sqlite_operation_deadline_monotonic() is None else DeadlineConnection
    return sqlite3.connect(database, timeout=timeout, uri=uri, factory=factory)


class DeadlineConnection(sqlite3.Connection):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._deadline = sqlite_operation_deadline_monotonic()
        original_timeout = sqlite3.Connection.execute(self, "pragma busy_timeout").fetchone()
        # Preserve the constructor's local cap (including shorter recovery
        # probes); the operation deadline may only reduce it.
        self._timeout_cap = min(
            sqlite_connect_timeout_seconds(),
            int(original_timeout[0]) / 1000 if original_timeout else 0.0,
        )
        self._caller_progress: Callable[[], int | None] | None = None
        self._caller_interval = 0
        self._progress_steps = 0
        self._script_depth = 0
        self._script_trace_update = False
        self._caller_trace: Callable[[str], object] | None = None
        self._install_progress()

    def _effective_deadline(self) -> float | None:
        current = sqlite_operation_deadline_monotonic()
        if self._deadline is None:
            return current
        return self._deadline if current is None else min(self._deadline, current)

    def _prepare_statement(self) -> None:
        deadline = self._effective_deadline()
        if deadline is None:
            return
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("Guard storage operation deadline expired.")
        # Use the base method to avoid recursively entering this wrapper.
        _ = sqlite3.Connection.execute(self, f"pragma busy_timeout={int(min(self._timeout_cap, remaining) * 1000)}")

    def _install_progress(self) -> None:
        maximum = 1 if self._script_depth else 1000
        interval = min(self._caller_interval, maximum) if self._caller_interval > 0 else maximum

        def progress() -> int | None:
            deadline = self._effective_deadline()
            if deadline is not None and time.monotonic() >= deadline:
                return 1
            self._progress_steps += interval
            if self._caller_progress is not None and self._progress_steps >= self._caller_interval:
                self._progress_steps = 0
                return self._caller_progress()
            return 0

        sqlite3.Connection.set_progress_handler(self, progress, interval)

    def set_trace_callback(self, trace_callback: Callable[[str], object] | None) -> None:
        self._caller_trace = trace_callback
        self._install_trace()

    def _install_trace(self) -> None:
        sqlite3.Connection.set_trace_callback(
            self,
            self._script_trace if self._script_depth else self._caller_trace,
        )

    def _script_trace(self, sql: str) -> None:
        if self._script_trace_update:
            return

        def update_wait() -> None:
            deadline = self._effective_deadline()
            if deadline is not None:
                remaining = max(0.0, deadline - time.monotonic())
                self._script_trace_update = True
                try:
                    _ = sqlite3.Connection.execute(
                        self,
                        f"pragma busy_timeout={int(min(self._timeout_cap, remaining) * 1000)}",
                    )
                finally:
                    self._script_trace_update = False

        update_wait()
        try:
            if self._caller_trace is not None:
                self._caller_trace(sql)
        finally:
            # A caller's trace callback can itself consume the budget. SQLite
            # swallows trace exceptions, so the per-opcode progress guard also
            # fences expired short statements before they execute.
            update_wait()

    @contextmanager
    def _script_statements(self) -> Generator[None, None, None]:
        self._script_depth += 1
        self._install_trace()
        self._install_progress()
        try:
            yield
        finally:
            self._script_depth -= 1
            self._install_trace()
            self._install_progress()

    def set_progress_handler(self, progress_handler: Callable[[], int | None] | None, n: int) -> None:
        self._caller_progress = progress_handler if n > 0 else None
        self._caller_interval = max(n, 0)
        self._progress_steps = 0
        self._install_progress()

    def cursor(self, factory: Any = None) -> sqlite3.Cursor:
        if factory is None:
            return super().cursor(DeadlineCursor)
        if isinstance(factory, type) and issubclass(factory, sqlite3.Cursor):
            return super().cursor(_deadline_cursor_class(factory))

        def owned_factory(connection: sqlite3.Connection) -> sqlite3.Cursor:
            cursor = factory(connection)
            if not isinstance(cursor, sqlite3.Cursor):
                raise TypeError("SQLite cursor factory must return a Cursor")
            if not isinstance(cursor, DeadlineCursor):
                # Preserve the factory's object identity and custom state.
                # Incompatible native layouts fail before any statement is
                # handed back with an unenforced deadline.
                cursor.__class__ = _deadline_cursor_class(type(cursor))
            return cursor

        return super().cursor(owned_factory)

    def execute(self, *args: Any, **kwargs: Any) -> sqlite3.Cursor:
        return self.cursor().execute(*args, **kwargs)

    def executemany(self, *args: Any, **kwargs: Any) -> sqlite3.Cursor:
        return self.cursor().executemany(*args, **kwargs)

    def executescript(self, *args: Any, **kwargs: Any) -> sqlite3.Cursor:
        return self.cursor().executescript(*args, **kwargs)

    def commit(self) -> None:
        self._prepare_statement()
        super().commit()

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> Literal[False]:
        if exc_type is None:
            try:
                self._prepare_statement()
            except BaseException as failure:
                try:
                    self.rollback()
                except BaseException as cleanup:
                    raise failure from cleanup
                raise
            return super().__exit__(exc_type, exc_value, traceback)
        # The base context exit owns rollback on an exceptional path. Do not
        # let the elapsed deadline prevent that cleanup or mask its cause.
        sqlite3.Connection.set_progress_handler(self, None, 0)
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        except BaseException as cleanup:
            if exc_value is not None:
                raise exc_value from cleanup
            raise
        finally:
            self._install_progress()

    def rollback(self) -> None:
        # Deadline refusal must still permit transaction cleanup.
        sqlite3.Connection.set_progress_handler(self, None, 0)
        try:
            super().rollback()
        finally:
            self._install_progress()


class DeadlineCursor(sqlite3.Cursor):
    __slots__ = ()

    def _prepare(self) -> None:
        connection = self.connection
        if isinstance(connection, DeadlineConnection):
            connection._prepare_statement()

    def execute(self, *args: Any, **kwargs: Any) -> sqlite3.Cursor:
        self._prepare()
        return super().execute(*args, **kwargs)

    def executemany(self, sql: str, seq_of_parameters: Iterable[Any], /) -> sqlite3.Cursor:
        self._prepare()

        def parameters() -> Iterator[Any]:
            for row in seq_of_parameters:
                # Parameter production can itself consume time. Check after
                # it returns and before SQLite binds/steps this next row.
                self._prepare()
                yield row

        return super().executemany(sql, parameters())

    def executescript(self, *args: Any, **kwargs: Any) -> sqlite3.Cursor:
        self._prepare()
        if isinstance(self.connection, DeadlineConnection):
            with self.connection._script_statements():
                return super().executescript(*args, **kwargs)
        return super().executescript(*args, **kwargs)

    def _refuse_if_expired(self) -> None:
        connection = self.connection
        if not isinstance(connection, DeadlineConnection):
            return
        deadline = connection._effective_deadline()
        if deadline is not None and time.monotonic() >= deadline:
            raise TimeoutError("Guard storage operation deadline expired.")

    def fetchone(self) -> Any:
        self._refuse_if_expired()
        return super().fetchone()

    def fetchmany(self, *args: Any, **kwargs: Any) -> Any:
        self._refuse_if_expired()
        return super().fetchmany(*args, **kwargs)

    def fetchall(self) -> Any:
        self._refuse_if_expired()
        return super().fetchall()

    def __next__(self) -> Any:
        self._refuse_if_expired()
        return super().__next__()


@lru_cache(maxsize=32)
def _deadline_cursor_class(factory: type[sqlite3.Cursor]) -> type[sqlite3.Cursor]:
    if factory is DeadlineCursor:
        return factory
    if factory is sqlite3.Cursor:
        return DeadlineCursor
    # The original class stays first to retain its native layout and state.
    # Entry guards run before its callbacks; the DeadlineCursor tail checks
    # again if those callbacks consume time before calling SQLite.
    bases = (factory,) if issubclass(factory, DeadlineCursor) else (factory, DeadlineCursor)
    cursor_type = type("DeadlineCustomCursor", bases, {"__module__": __name__, "__slots__": ()})
    for name in ("execute", "executemany", "executescript", "fetchone", "fetchmany", "fetchall", "__next__"):
        setattr(cursor_type, name, _guarded_cursor_method(cursor_type, name))
    return cursor_type


def _guarded_cursor_method(cursor_type: type[sqlite3.Cursor], name: str) -> Callable[..., Any]:
    def guarded(cursor: sqlite3.Cursor, *args: Any, **kwargs: Any) -> Any:
        if name in {"fetchone", "fetchmany", "fetchall", "__next__"}:
            DeadlineCursor._refuse_if_expired(cast(DeadlineCursor, cursor))
        else:
            DeadlineCursor._prepare(cast(DeadlineCursor, cursor))
        if name == "executescript" and isinstance(cursor.connection, DeadlineConnection):
            # A custom cursor may call sqlite3.Cursor directly instead of
            # using its MRO tail. Own the whole callback/SQLite script scope.
            with cursor.connection._script_statements():
                return getattr(super(cursor_type, cursor), name)(*args, **kwargs)
        return getattr(super(cursor_type, cursor), name)(*args, **kwargs)

    return guarded
