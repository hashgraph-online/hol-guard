"""Connections shared by one operation without sharing method transactions."""

from __future__ import annotations

import sqlite3
import threading
import time
from contextlib import contextmanager, suppress
from typing import TYPE_CHECKING

from . import store_review_event_outbox_schema
from .sqlite_deadline_connection import DeadlineConnection
from .sqlite_profile import sqlite_error_is_busy_locked
from .sqlite_recovery import sqlite_error_is_io
from .sqlite_tuning import sqlite_operation_deadline_monotonic
from .store_base import SQLITE_CACHE_SIZE_KIB, SQLITE_MMAP_SIZE_BYTES, sqlite_connect_timeout_seconds

if TYPE_CHECKING:
    from collections.abc import Iterator

    from .store import GuardStore

_local = threading.local()


def owns_scope(store: GuardStore) -> bool:
    return getattr(_local, "owner", None) == id(store)


@contextmanager
def connection_scope(store: GuardStore) -> Iterator[None]:
    if owns_scope(store):
        yield
        return
    previous = tuple(
        getattr(_local, name, default)
        for name, default in (("owner", None), ("connection", None), ("failure", None), ("transaction_depth", 0))
    )
    with store._connect(connection_only=True) as connection:
        _local.owner = id(store)
        _local.connection = connection
        _local.failure = None
        _local.transaction_depth = 0
        try:
            yield
        finally:
            failure = _local.failure
            _local.owner, _local.connection, _local.failure, _local.transaction_depth = previous
            if failure is not None:
                # Caught failures still poison the operation and reach recovery.
                raise failure


@contextmanager
def scoped_connection(store: GuardStore) -> Iterator[sqlite3.Connection]:
    """Nested methods use separate connections to isolate pending writes."""
    if _local.failure is not None:
        raise _local.failure
    depth = _local.transaction_depth
    _local.transaction_depth += 1
    try:
        with store._hold_storage_gate(exclusive=False):
            method_transaction = (
                store._connection_transaction(_local.connection) if depth == 0 else store._connect_once()
            )
            with method_transaction as connection:
                yield connection
    except sqlite3.DatabaseError as error:
        if store._is_fatal_sqlite_error(error) or sqlite_error_is_io(error):
            _local.failure = error
        raise
    finally:
        _local.transaction_depth -= 1


@contextmanager
def open_connection(store: GuardStore) -> Iterator[sqlite3.Connection]:
    """Record connection cost; individual methods own transaction metrics."""
    with store._hold_storage_gate(exclusive=False), _open_connection(store) as connection:
        yield connection


@contextmanager
def _open_connection(store: GuardStore) -> Iterator[sqlite3.Connection]:
    timeout = sqlite_connect_timeout_seconds()
    if timeout <= 0:
        raise TimeoutError("Guard storage operation deadline expired.")
    profiler = store._sqlite_profiler()
    started = time.monotonic()
    try:
        factory = DeadlineConnection if sqlite_operation_deadline_monotonic() is not None else sqlite3.Connection
        connection = sqlite3.connect(store.path, timeout=timeout, factory=factory)
    except sqlite3.OperationalError as error:
        profiler.record_connect((time.monotonic() - started) * 1000)
        if sqlite_error_is_busy_locked(error):
            profiler.record_busy_locked()
        raise
    profiler.record_connect((time.monotonic() - started) * 1000)
    connection.row_factory = sqlite3.Row
    try:
        try:
            connection.execute(f"pragma busy_timeout={int(timeout * 1000)}")
            journal_mode = connection.execute("pragma journal_mode").fetchone()
            if journal_mode is not None and str(journal_mode[0]).lower() == "wal":
                connection.execute("pragma synchronous=NORMAL")
            connection.execute(f"pragma cache_size=-{SQLITE_CACHE_SIZE_KIB}")
            connection.execute(f"pragma mmap_size={SQLITE_MMAP_SIZE_BYTES}")
        except sqlite3.OperationalError as error:
            if sqlite_error_is_busy_locked(error):
                profiler.record_busy_locked()
            raise
        yield connection
    finally:
        connection.close()
        store._repair_store_permissions()


@contextmanager
def transaction(store: GuardStore, connection: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    profiler = store._sqlite_profiler()
    started = time.monotonic()
    initial_changes = connection.total_changes
    notification: dict[str, object] | None = None
    try:
        yield connection
        store_review_event_outbox_schema.finalize_review_event_payload_hashes(connection)
        outbox_generation = store_review_event_outbox_schema.commit_review_event_transaction(
            connection, initial_changes, profiler.record_commit
        )
        notification = store._take_policy_integrity_state_notification(connection)
    except BaseException as error:
        if isinstance(error, sqlite3.OperationalError) and sqlite_error_is_busy_locked(error):
            profiler.record_busy_locked()
        # Earlier method commits remain durable; this failed method rolls back.
        with suppress(sqlite3.DatabaseError):
            connection.rollback()
        store._take_policy_integrity_state_notification(connection)
        raise
    finally:
        profiler.record_transaction((time.monotonic() - started) * 1000)
    store_review_event_outbox_schema.notify_review_event_wake(store.path, outbox_generation)
    if notification is not None:
        store._publish_policy_integrity_state_notification(notification)
