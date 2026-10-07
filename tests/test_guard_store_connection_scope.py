"""Operation-scoped connections preserve transaction and recovery boundaries."""

import sqlite3
import threading
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import store_review_event_outbox_schema
from codex_plugin_scanner.guard.store import GuardStore


def fixture_store(tmp_path: Path) -> GuardStore:
    store = GuardStore(tmp_path / "guard", prime_policy_integrity=False)
    with store._connect() as connection:
        connection.execute("create table scope_fixture (value integer)")
    return store


@pytest.mark.parametrize("unrelated_connections", [0, 4])
def test_scope_reuses_connection_only_within_one_operation(
    tmp_path: Path, monkeypatch, unrelated_connections: int
) -> None:
    store = fixture_store(tmp_path)
    opened = []
    original_connect = sqlite3.connect

    def connect(database, *args, **kwargs):
        connection = original_connect(database, *args, **kwargs)
        if database in (store.path, str(store.path)):
            opened.append(connection)
        return connection

    monkeypatch.setattr(sqlite3, "connect", connect)
    for _ in range(unrelated_connections):
        with sqlite3.connect(tmp_path / "unrelated.db") as unrelated:
            unrelated.execute("select 1").fetchone()
        unrelated.close()
    for _ in range(2):
        with store.connection_scope():
            with store._connect() as first:
                first.execute("select count(*) from scope_fixture").fetchone()
            with store.connection_scope(), store._connect() as second:
                assert second is first
                second.execute("select count(*) from scope_fixture").fetchone()
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            first.execute("select 1")
    assert len(opened) == 2


def test_committed_claim_survives_later_scope_failure(tmp_path: Path) -> None:
    store = fixture_store(tmp_path)
    with pytest.raises(RuntimeError, match="later failure"), store.connection_scope():
        with store._connect() as connection:
            connection.execute("insert into scope_fixture values (1)")
        with sqlite3.connect(store.path) as observer:
            assert observer.execute("select value from scope_fixture").fetchall() == [(1,)]
        raise RuntimeError("later failure")
    with store._connect() as connection:
        assert connection.execute("select value from scope_fixture").fetchone()[0] == 1


def test_failed_transaction_rolls_back_before_next_method(tmp_path: Path) -> None:
    store = fixture_store(tmp_path)
    with store.connection_scope():
        with pytest.raises(RuntimeError, match="abort"), store._connect() as connection:
            connection.execute("insert into scope_fixture values (2)")
            raise RuntimeError("abort")
        with store._connect() as connection:
            assert connection.in_transaction is False
            assert connection.execute("select count(*) from scope_fixture").fetchone()[0] == 0


def test_commit_failure_rolls_back_discards_notification_and_records_contention(
    tmp_path: Path, monkeypatch
) -> None:
    store = fixture_store(tmp_path)
    before = store.sqlite_profile()
    original_commit = store_review_event_outbox_schema.commit_review_event_transaction
    fail_commit = [True]
    published: list[dict[str, object]] = []

    def commit_review_event_transaction(connection, initial_changes, record_commit):
        if fail_commit:
            fail_commit.pop()
            raise sqlite3.OperationalError("database is locked")
        return original_commit(connection, initial_changes, record_commit)

    monkeypatch.setattr(
        store_review_event_outbox_schema,
        "commit_review_event_transaction",
        commit_review_event_transaction,
    )
    monkeypatch.setattr(store, "_publish_policy_integrity_state_notification", published.append)

    with store.connection_scope():
        with pytest.raises(sqlite3.OperationalError, match="locked"), store._connect() as connection:
            connection.execute("insert into scope_fixture values (2)")
            store._queue_policy_integrity_state_notification(connection, {"state": "test"})
        with store._connect() as connection:
            assert connection.in_transaction is False
            assert connection.execute("select count(*) from scope_fixture").fetchone()[0] == 0

    assert published == []
    assert store.sqlite_profile()["busy_locked"] == before["busy_locked"] + 1


def test_nested_method_cannot_commit_its_callers_pending_writes(tmp_path: Path) -> None:
    store = fixture_store(tmp_path)
    with store.connection_scope():
        with pytest.raises(RuntimeError, match="abort outer"), store._connect() as outer:
            outer.execute("insert into scope_fixture values (4)")
            with store._connect() as inner:
                assert inner is not outer
                assert inner.execute("select count(*) from scope_fixture").fetchone()[0] == 0
            assert outer.in_transaction is True
            raise RuntimeError("abort outer")
        with store._connect() as connection:
            assert connection.execute("select count(*) from scope_fixture").fetchone()[0] == 0


def test_scope_does_not_retain_read_snapshot_across_methods(tmp_path: Path) -> None:
    store = fixture_store(tmp_path)
    with store.connection_scope():
        with store._connect() as connection:
            connection.execute("begin deferred")
            assert connection.execute("select count(*) from scope_fixture").fetchone()[0] == 0
        with sqlite3.connect(store.path) as writer:
            writer.execute("insert into scope_fixture values (3)")
        with store._connect() as connection:
            assert connection.execute("select value from scope_fixture").fetchone()[0] == 3


def test_scopes_are_thread_local(tmp_path: Path) -> None:
    store = fixture_store(tmp_path)
    connections = []
    failures = []

    def read() -> None:
        try:
            with store.connection_scope(), store._connect() as connection:
                connections.append(connection)
                connection.execute("select count(*) from scope_fixture").fetchone()
        except Exception as error:
            failures.append(error)

    with store.connection_scope(), store._connect() as main_connection:
        reader = threading.Thread(target=read)
        reader.start()
        reader.join(timeout=5)
        assert not reader.is_alive()
        assert not failures
        assert connections[0] is not main_connection


def test_nested_different_stores_restore_the_original_scope(tmp_path: Path) -> None:
    first_store = fixture_store(tmp_path / "first")
    second_store = fixture_store(tmp_path / "second")
    with first_store.connection_scope():
        with first_store._connect() as first:
            first.execute("insert into scope_fixture values (1)")
        with second_store.connection_scope(), second_store._connect() as second:
            assert second is not first
            assert second.execute("select count(*) from scope_fixture").fetchone()[0] == 0
        with first_store._connect() as restored:
            assert restored is first
            assert restored.execute("select value from scope_fixture").fetchone()[0] == 1


@pytest.mark.parametrize("failure", ["database disk image is malformed", "disk I/O error"])
def test_caught_fatal_error_still_fails_the_scope_and_reaches_recovery(
    tmp_path: Path,
    monkeypatch,
    failure: str,
) -> None:
    store = fixture_store(tmp_path)
    failures = []
    monkeypatch.setattr(store, "_recover_fatal_sqlite_store", lambda error, **kwargs: failures.append(error))
    with pytest.raises(sqlite3.DatabaseError, match=failure), store.connection_scope():
        try:
            with store._connect():
                raise sqlite3.DatabaseError(failure)
        except sqlite3.DatabaseError:
            pass
        with pytest.raises(sqlite3.DatabaseError, match=failure), store._connect():
            pytest.fail("A failed connection must not be reused")
    assert len(failures) == 1
    with store.connection_scope(), store._connect() as connection:
        assert connection.execute("select count(*) from scope_fixture").fetchone()[0] == 0


def test_scopes_keep_the_storage_gate_until_connection_closes(tmp_path: Path) -> None:
    store = fixture_store(tmp_path)
    with store.connection_scope(), store._try_hold_storage_gate(exclusive=True) as acquired:
        # Same-thread upgrade is rejected rather than replacing a live DB.
        assert acquired is False


def test_scope_counts_only_method_transactions_and_commits(tmp_path: Path) -> None:
    store = fixture_store(tmp_path)
    before = store.sqlite_profile()
    with store.connection_scope():
        opened = store.sqlite_profile()
        assert opened["connects"] == before["connects"] + 1
        assert opened["transactions"] == before["transactions"]
        assert opened["commits"] == before["commits"]
        with store._connect() as connection:
            connection.execute("insert into scope_fixture values (1)")
        with store._connect() as connection:
            assert connection.execute("select count(*) from scope_fixture").fetchone()[0] == 1
        inner = store.sqlite_profile()
        assert inner["transactions"] == before["transactions"] + 2
        assert inner["commits"] == before["commits"] + 2
    assert store.sqlite_profile() == inner


def test_scope_records_pragma_contention_and_closes_failed_connection(tmp_path: Path, monkeypatch) -> None:
    store = fixture_store(tmp_path)
    before = store.sqlite_profile()
    opened = []
    failures = [True]
    original_connect = sqlite3.connect

    class PragmaConnection(sqlite3.Connection):
        def execute(self, statement, *args, **kwargs):
            if statement.startswith("pragma busy_timeout") and failures:
                failures.pop()
                raise sqlite3.OperationalError("database is locked")
            return super().execute(statement, *args, **kwargs)

    def connect(*args, **kwargs):
        kwargs["factory"] = PragmaConnection
        connection = original_connect(*args, **kwargs)
        opened.append(connection)
        return connection

    monkeypatch.setattr(sqlite3, "connect", connect)
    with store.connection_scope(), store._connect() as connection:
        assert connection.execute("select count(*) from scope_fixture").fetchone()[0] == 0
    assert len(opened) == 2
    assert store.sqlite_profile()["busy_locked"] == before["busy_locked"] + 1
    for connection in opened:
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            connection.execute("select 1")


def test_extended_io_error_code_poisoning_does_not_depend_on_error_text(tmp_path: Path, monkeypatch) -> None:
    store = fixture_store(tmp_path)
    recovered = []
    error = sqlite3.DatabaseError("opaque native failure")
    error.sqlite_errorcode = sqlite3.SQLITE_IOERR_WRITE
    monkeypatch.setattr(store, "_recover_fatal_sqlite_store", lambda failure, **kwargs: recovered.append(failure))
    with pytest.raises(sqlite3.DatabaseError, match="opaque native failure"), store.connection_scope():
        try:
            with store._connect():
                raise error
        except sqlite3.DatabaseError:
            pass
        with pytest.raises(sqlite3.DatabaseError, match="opaque native failure"), store._connect():
            pytest.fail("An I/O-failed connection must not be reused")
    assert recovered == [error]


def test_poisoned_scope_preserves_the_later_exception_context(tmp_path: Path, monkeypatch) -> None:
    store = fixture_store(tmp_path)
    later = RuntimeError("later operation failed")
    monkeypatch.setattr(store, "_recover_fatal_sqlite_store", lambda *args, **kwargs: None)
    with pytest.raises(sqlite3.DatabaseError, match="malformed") as raised, store.connection_scope():
        try:
            with store._connect():
                raise sqlite3.DatabaseError("database disk image is malformed")
        except sqlite3.DatabaseError:
            pass
        raise later
    assert raised.value.__context__ is later
