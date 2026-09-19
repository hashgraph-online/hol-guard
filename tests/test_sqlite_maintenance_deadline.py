from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import sqlite_deadline as deadline_module
from codex_plugin_scanner.guard.sqlite_deadline import (
    DeadlineConnection,
    SQLiteDeadlineExceededError,
    SQLiteDeadlineUnsupportedError,
    sqlite_deadline_monotonic,
    sqlite_maintenance_deadline,
)
from codex_plugin_scanner.guard.sqlite_profile import sqlite_error_is_busy_locked
from codex_plugin_scanner.guard.sqlite_tuning import sqlite_connect_timeout_override, sqlite_connect_timeout_seconds


def _connection(path: str | Path = ":memory:") -> DeadlineConnection:
    return sqlite3.connect(path, timeout=sqlite_connect_timeout_seconds(), factory=DeadlineConnection)


def test_nested_deadlines_and_scalar_overrides_never_extend_outer_budget(monkeypatch):
    clock = [10.0]
    monkeypatch.setattr(deadline_module.time, "monotonic", lambda: clock[0])
    assert sqlite_connect_timeout_seconds({}) == 30.0
    with pytest.raises(SQLiteDeadlineExceededError), sqlite_maintenance_deadline(12.0):
        assert sqlite_connect_timeout_seconds({}) == 2.0
        with sqlite_maintenance_deadline(30.0), sqlite_connect_timeout_override(20.0):
            assert sqlite_deadline_monotonic() == 12.0
            assert sqlite_connect_timeout_seconds() == 2.0
        with sqlite_maintenance_deadline(11.0):
            assert sqlite_connect_timeout_seconds() == 1.0
        assert sqlite_deadline_monotonic() == 12.0
        clock[0] = 12.0
        with pytest.raises(SQLiteDeadlineExceededError):
            sqlite_connect_timeout_seconds()
    assert sqlite_deadline_monotonic() is None
    assert sqlite_connect_timeout_seconds({}) == 30.0


def test_no_context_does_not_read_a_clock(monkeypatch):
    monkeypatch.setattr(deadline_module.time, "monotonic", lambda: pytest.fail("unscoped clock read"))
    assert sqlite_connect_timeout_seconds({}) == 30.0
    with sqlite_connect_timeout_override(0.01):
        assert sqlite_connect_timeout_seconds({}) == 0.01
    assert sqlite_connect_timeout_seconds({"HOL_GUARD_INTERNAL_HOOK_SQLITE_TIMEOUT_MS": "1000"}) == 0.25


def test_retained_connection_and_cursor_keep_their_original_deadline(monkeypatch):
    clock = [10.0]
    monkeypatch.setattr(deadline_module.time, "monotonic", lambda: clock[0])
    with sqlite_maintenance_deadline(12.0):
        connection = _connection()
        cursor = connection.execute("select 1")
    assert sqlite_deadline_monotonic() is None
    try:
        clock[0] = 12.0
        for operation in (
            lambda: connection.execute("select 2"),
            lambda: cursor.execute("select 2"),
            lambda: cursor.fetchone(),
            connection.commit,
        ):
            with pytest.raises(SQLiteDeadlineExceededError):
                operation()
        connection.rollback()
    finally:
        connection.close()


def test_each_statement_refreshes_remaining_busy_timeout(monkeypatch):
    clock = [10.0]
    monkeypatch.setattr(deadline_module.time, "monotonic", lambda: clock[0])
    with sqlite_maintenance_deadline(12.0):
        connection = _connection()
        try:
            assert connection.execute("pragma busy_timeout").fetchone() == (0,)
            clock[0] = 11.5
            assert connection.cursor().execute("pragma busy_timeout").fetchone() == (0,)
            with pytest.raises(SQLiteDeadlineUnsupportedError):
                connection.execute("pragma busy_timeout=999999")
            assert connection.execute("pragma busy_timeout").fetchone() == (0,)
        finally:
            connection.close()


def test_executemany_refreshes_each_parameter_row_and_empty_input(monkeypatch):
    clock = [10.0]
    monkeypatch.setattr(deadline_module.time, "monotonic", lambda: clock[0])
    with sqlite_maintenance_deadline(12.0):
        connection = _connection()
        try:
            connection.begin_immediate()
            connection.execute("create table items(value integer)")
            connection.executemany("insert into items values (?)", ())
            connection.commit()

            def rows():
                yield (1,)
                clock[0] = 12.0
                yield (2,)

            connection.begin_immediate()
            with pytest.raises(SQLiteDeadlineExceededError):
                connection.cursor().executemany("insert into items values (?)", rows())
            connection.rollback()
            clock[0] = 11.0
            assert connection.execute("select count(*) from items").fetchone() == (0,)
        finally:
            connection.close()


def test_connection_context_rolls_back_when_commit_deadline_expires(monkeypatch, tmp_path):
    clock = [10.0]
    monkeypatch.setattr(deadline_module.time, "monotonic", lambda: clock[0])
    path = tmp_path / "store.db"
    with sqlite3.connect(path) as plain:
        plain.execute("create table items(value integer)")
    with pytest.raises(SQLiteDeadlineExceededError), sqlite_maintenance_deadline(12.0):
        connection = _connection(path)
        try:
            with pytest.raises(SQLiteDeadlineExceededError), connection:
                connection.begin_immediate()
                connection.execute("insert into items values (1)")
                clock[0] = 12.0
        finally:
            connection.close()
    with sqlite3.connect(path) as plain:
        assert plain.execute("select count(*) from items").fetchone() == (0,)


def test_scripts_and_custom_cursor_factories_cannot_bypass_scope():
    with sqlite_maintenance_deadline(time.monotonic() + 1):
        connection = _connection()
        try:
            for operation in (
                lambda: connection.executescript("select 1; select 2;"),
                lambda: connection.cursor().executescript("select 1;"),
                lambda: connection.cursor(sqlite3.Cursor),
            ):
                with pytest.raises(SQLiteDeadlineUnsupportedError):
                    operation()
        finally:
            connection.close()


def test_actual_busy_waits_share_one_deadline(tmp_path):
    path = tmp_path / "store.db"
    with sqlite3.connect(path) as initial:
        initial.execute("create table items(value integer)")
    requested = threading.Event()
    locked = threading.Event()
    finished = threading.Event()
    release = threading.Event()

    def locker():
        try:
            with sqlite3.connect(path) as other:
                for attempt in range(2):
                    assert requested.wait(2)
                    requested.clear()
                    other.execute("begin immediate")
                    locked.set()
                    if attempt == 0:
                        time.sleep(0.12)
                    else:
                        assert release.wait(2)
                    other.commit()
        finally:
            finished.set()

    thread = threading.Thread(target=locker, daemon=True)
    thread.start()
    deadline = time.monotonic() + 0.20
    outcomes = []
    try:
        with pytest.raises(SQLiteDeadlineExceededError), sqlite_maintenance_deadline(deadline):
            connection = _connection(path)
            try:
                requested.set()
                assert locked.wait(1)
                locked.clear()
                connection.begin_immediate()
                connection.commit()
                outcomes.append("first_wait_completed")
                requested.set()
                assert locked.wait(1)
                with pytest.raises(SQLiteDeadlineExceededError):
                    while True:
                        assert connection._bound_deadline() == deadline
                        try:
                            connection.begin_immediate()
                        except sqlite3.OperationalError as error:
                            # SQLite accepts only whole milliseconds. Its busy
                            # handler can return just before the absolute
                            # deadline; a fresh admission gets only that remainder.
                            assert sqlite_error_is_busy_locked(error)
                        else:
                            pytest.fail("Second transaction admitted while the competing lock was held")
                outcomes.append("remaining_deadline_exhausted")
            finally:
                connection.close()
    finally:
        release.set()
        requested.set()
        assert finished.wait(2)
        thread.join(1)
    assert not thread.is_alive()
    assert outcomes == ["first_wait_completed", "remaining_deadline_exhausted"]


def test_store_uses_bound_factory_only_inside_scope(tmp_path):
    from codex_plugin_scanner.guard.store import GuardStore

    store = GuardStore(tmp_path / "guard")
    with store._connect() as ordinary:
        assert type(ordinary) is sqlite3.Connection
    with sqlite_maintenance_deadline(time.monotonic() + 2), store._connect() as bound:
        assert type(bound) is DeadlineConnection
        assert bound.execute("select 1").fetchone()[0] == 1
    with store._connect() as ordinary:
        assert type(ordinary) is sqlite3.Connection


def test_reentrant_store_gate_cannot_bypass_expiry(tmp_path, monkeypatch):
    from codex_plugin_scanner.guard.store import GuardStore

    store = GuardStore(tmp_path / "guard")
    clock = [10.0]
    monkeypatch.setattr(deadline_module.time, "monotonic", lambda: clock[0])
    with (
        pytest.raises(SQLiteDeadlineExceededError),
        sqlite_maintenance_deadline(12.0),
        store._hold_storage_gate(exclusive=False),
    ):
        clock[0] = 12.0
        with pytest.raises(SQLiteDeadlineExceededError), store._hold_storage_gate(exclusive=False):
            pytest.fail("expired gate admitted")


@pytest.mark.parametrize("value", [True, float("nan"), float("inf"), 10**1000])
def test_deadline_requires_finite_exact_scalar(value):
    with pytest.raises(ValueError), sqlite_maintenance_deadline(value):
        pytest.fail("invalid deadline admitted")


def test_actual_long_vm_statement_interrupts_and_rollback_remains_available(tmp_path):
    path = tmp_path / "store.db"
    with sqlite3.connect(path) as plain:
        plain.execute("create table items(value integer)")
    started = time.monotonic()
    with pytest.raises(SQLiteDeadlineExceededError), sqlite_maintenance_deadline(started + 0.06):
        connection = _connection(path)
        try:
            connection.begin_immediate()
            connection.execute("insert into items values (1)")
            with pytest.raises(SQLiteDeadlineExceededError):
                connection.execute(
                    "with recursive n(x) as (values(1) union all select x+1 from n where x<100000000) "
                    "select sum(x) from n"
                ).fetchone()
            connection.rollback()
        finally:
            connection.close()
    assert time.monotonic() - started < 0.5
    with sqlite3.connect(path) as plain:
        assert plain.execute("select count(*) from items").fetchone() == (0,)


def test_bound_connection_cannot_disable_its_progress_handler():
    with sqlite_maintenance_deadline(time.monotonic() + 1):
        connection = _connection()
        try:
            with pytest.raises(SQLiteDeadlineUnsupportedError):
                connection.set_progress_handler(None, 0)
            with pytest.raises(SQLiteDeadlineUnsupportedError):
                connection.set_progress_handler(lambda: 0, 1000000)
        finally:
            connection.close()


def test_expiry_after_actual_commit_is_not_misreported_as_rollback(tmp_path, monkeypatch):
    clock = [10.0]
    monkeypatch.setattr(deadline_module.time, "monotonic", lambda: clock[0])
    path = tmp_path / "store.db"
    with sqlite3.connect(path) as plain:
        plain.execute("create table items(value integer)")
    with pytest.raises(SQLiteDeadlineExceededError), sqlite_maintenance_deadline(12.0):
        connection = _connection(path)
        try:
            connection.begin_immediate()
            connection.execute("insert into items values (1)")
            connection.commit()
            clock[0] = 12.0
        finally:
            connection.close()
            connection.close()
    with sqlite3.connect(path) as plain:
        assert plain.execute("select count(*) from items").fetchone() == (1,)
    assert sqlite_deadline_monotonic() is None


def test_expired_outbox_finalization_rolls_back_store_and_never_recovers(tmp_path, monkeypatch):
    from codex_plugin_scanner.guard import store_review_event_outbox_schema as outbox
    from codex_plugin_scanner.guard.store import GuardStore

    store = GuardStore(tmp_path / "guard")
    original = store.get_device_metadata()
    clock = [10.0]
    real_finalize = outbox.finalize_review_event_payload_hashes

    def finalize(connection):
        real_finalize(connection)
        clock[0] = 12.0

    monkeypatch.setattr(deadline_module.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(outbox, "finalize_review_event_payload_hashes", finalize)
    monkeypatch.setattr(
        store, "_recover_fatal_sqlite_store", lambda *a, **kw: pytest.fail("deadline triggered recovery")
    )
    with pytest.raises(SQLiteDeadlineExceededError), sqlite_maintenance_deadline(12.0), store._connect() as connection:
        assert isinstance(connection, DeadlineConnection)
        connection.begin_immediate()
        connection.execute("update guard_devices set installation_id = 'candidate'")
    monkeypatch.setattr(outbox, "finalize_review_event_payload_hashes", real_finalize)
    assert store.get_device_metadata() == original


def test_store_long_vm_timeout_is_not_classified_as_corruption(tmp_path, monkeypatch):
    from codex_plugin_scanner.guard.store import GuardStore

    store = GuardStore(tmp_path / "guard")
    monkeypatch.setattr(
        store, "_recover_fatal_sqlite_store", lambda *a, **kw: pytest.fail("deadline triggered recovery")
    )
    with (
        pytest.raises(SQLiteDeadlineExceededError),
        sqlite_maintenance_deadline(time.monotonic() + 0.06),
        store._connect() as connection,
    ):
        connection.execute(
            "with recursive n(x) as (values(1) union all select x+1 from n where x<100000000) select sum(x) from n"
        ).fetchone()
    with store._connect() as ordinary:
        assert ordinary.execute("pragma quick_check").fetchone()[0] == "ok"


def test_existing_connection_respects_a_tighter_nested_scope(monkeypatch):
    clock = [10.0]
    monkeypatch.setattr(deadline_module.time, "monotonic", lambda: clock[0])
    with sqlite_maintenance_deadline(14.0):
        connection = _connection()
        try:
            with pytest.raises(SQLiteDeadlineExceededError), sqlite_maintenance_deadline(12.0):
                assert connection.execute("pragma busy_timeout").fetchone() == (0,)
                clock[0] = 12.0
                connection.execute("select 1")
            assert connection.execute("select 1").fetchone() == (1,)
        finally:
            connection.close()


@pytest.mark.parametrize(
    "sql",
    [
        "insert into items values (2)",
        "/* prefix */ update items set value=2",
        "with rows(value) as (values(2)) insert into items select value from rows",
        "create table copied as select * from items",
        "begin",
        "begin immediate",
        "end",
        "commit",
        "rollback",
        "savepoint point",
        "release point",
        "attach database ':memory:' as other",
        "pragma journal_mode=WAL",
        "pragma user_version=1",
    ],
)
def test_sqlite_authorizer_refuses_implicit_writes_and_unowned_controls(tmp_path, sql):
    path = tmp_path / "data.db"
    with sqlite3.connect(path) as initial:
        initial.execute("create table items(value integer)")
        initial.execute("insert into items values (1)")
    with sqlite_maintenance_deadline(time.monotonic() + 1):
        connection = _connection(path)
        try:
            with pytest.raises(SQLiteDeadlineUnsupportedError):
                connection.execute(sql)
            assert connection.execute("select value from items").fetchall() == [(1,)]
            assert not connection.in_transaction
        finally:
            connection.close()


@pytest.mark.parametrize("kwargs", [{"isolation_level": None}, {"autocommit": True}, {"autocommit": False}])
def test_implicit_autocommit_connection_modes_are_refused(kwargs):
    if "autocommit" in kwargs and not hasattr(sqlite3, "LEGACY_TRANSACTION_CONTROL"):
        pytest.skip("autocommit constructor option requires Python3.12")
    with sqlite_maintenance_deadline(time.monotonic() + 1), pytest.raises(SQLiteDeadlineUnsupportedError):
        sqlite3.connect(":memory:", factory=DeadlineConnection, **kwargs)


def test_transaction_mode_mutation_cannot_implicitly_commit(tmp_path):
    path = tmp_path / "data.db"
    with sqlite3.connect(path) as initial:
        initial.execute("create table items(value integer)")
    with sqlite_maintenance_deadline(time.monotonic() + 1):
        connection = _connection(path)
        try:
            connection.begin_immediate()
            connection.execute("insert into items values (1)")
            for name, value in (("isolation_level", None), ("isolation_level", ""), ("autocommit", True)):
                with pytest.raises(SQLiteDeadlineUnsupportedError):
                    setattr(connection, name, value)
                assert connection.in_transaction
            connection.rollback()
        finally:
            connection.close()
    with sqlite3.connect(path) as plain:
        assert plain.execute("select count(*) from items").fetchone() == (0,)


def test_statement_reuse_cannot_keep_transaction_authorization_after_commit():
    with sqlite_maintenance_deadline(time.monotonic() + 1):
        connection = _connection()
        try:
            connection.begin_immediate()
            connection.execute("create table items(value integer)")
            connection.execute("insert into items values (1)")
            connection.commit()
            with pytest.raises(SQLiteDeadlineUnsupportedError):
                connection.execute("insert into items values (1)")
            assert connection.execute("select count(*) from items").fetchone() == (1,)
        finally:
            connection.close()


def test_unwrapped_mutation_and_authorizer_apis_are_explicitly_unsupported():
    with sqlite_maintenance_deadline(time.monotonic() + 1):
        connection = _connection()
        try:
            for operation in (
                lambda: connection.set_authorizer(None),
                lambda: connection.backup(connection),
                lambda: connection.blobopen("items", "value", 1),
                lambda: connection.deserialize(b"data"),
                lambda: connection.enable_load_extension(True),
                lambda: connection.load_extension("extension"),
                lambda: connection.create_function("callback", 0, lambda: 0),
                lambda: connection.create_aggregate("callback", 0, object),
                lambda: connection.create_window_function("callback", 0, object),
                lambda: connection.create_collation("callback", lambda a, b: 0),
                lambda: connection.set_trace_callback(lambda sql: None),
            ):
                with pytest.raises(SQLiteDeadlineUnsupportedError):
                    operation()
        finally:
            connection.close()


def test_actual_explicit_commit_waits_for_transient_reader_contention(tmp_path):
    path = tmp_path / "data.db"
    with sqlite3.connect(path) as initial:
        initial.execute("create table items(value integer)")
        initial.execute("insert into items values (1)")
    reader = sqlite3.connect(path, check_same_thread=False)
    reader.execute("begin")
    reader.execute("select value from items").fetchone()
    released = threading.Event()

    def release():
        time.sleep(0.06)
        reader.rollback()
        released.set()

    thread = threading.Thread(target=release)
    with sqlite_maintenance_deadline(time.monotonic() + 1):
        connection = _connection(path)
        try:
            connection.begin_immediate()
            connection.execute("update items set value=2")
            thread.start()
            connection.commit()
            assert released.is_set()
        finally:
            connection.close()
            thread.join(1)
            reader.close()
    with sqlite3.connect(path) as plain:
        assert plain.execute("select value from items").fetchone() == (2,)


def test_actual_vm_work_then_explicit_commit_uses_only_remaining_budget(tmp_path):
    path = tmp_path / "data.db"
    with sqlite3.connect(path) as initial:
        initial.execute("create table items(value integer)")
        initial.executemany("insert into items values (?)", ((value,) for value in range(10000)))
    reader = sqlite3.connect(path)
    reader.execute("begin")
    reader.execute("select count(*) from items").fetchone()
    began = time.monotonic()
    try:
        try:
            with sqlite_maintenance_deadline(began + 0.2):
                connection = _connection(path)
                try:
                    connection.begin_immediate()
                    connection.execute("update items set value=value+1")
                    assert connection.execute("pragma busy_timeout").fetchone() == (0,)
                    with pytest.raises((SQLiteDeadlineExceededError, sqlite3.OperationalError)):
                        connection.commit()
                    connection.rollback()
                finally:
                    connection.close()
        except SQLiteDeadlineExceededError:
            pass
    finally:
        reader.rollback()
        reader.close()
    assert time.monotonic() - began < 0.3
    with sqlite3.connect(path) as plain:
        assert plain.execute("select min(value), max(value) from items").fetchone() == (0, 9999)


def test_trigger_writes_remain_inside_the_owned_transaction():
    with sqlite_maintenance_deadline(time.monotonic() + 1):
        connection = _connection()
        try:
            connection.begin_immediate()
            connection.execute("create table items(value integer)")
            connection.execute("create table copies(value integer)")
            connection.execute(
                "create trigger copy after insert on items begin insert into copies values(new.value); end"
            )
            connection.execute("insert into items values(1)")
            connection.commit()
            assert connection.execute("select value from copies").fetchall() == [(1,)]
            with pytest.raises(SQLiteDeadlineUnsupportedError):
                connection.executemany("insert into items values(?)", [(2,)])
            assert connection.execute("select value from copies").fetchall() == [(1,)]
        finally:
            connection.close()
