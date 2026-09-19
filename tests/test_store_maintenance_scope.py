from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import review_event_wake as wake
from codex_plugin_scanner.guard.native_policy_control_transport import run_native_control_worker
from codex_plugin_scanner.guard.sqlite_deadline import (
    DeadlineConnection,
    SQLiteDeadlineExceededError,
    SQLiteDeadlineUnsupportedError,
)
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_maintenance import capture_store_maintenance_lookup, store_maintenance_scope


def _lookup(store):
    return capture_store_maintenance_lookup(
        store.path, cancelled=threading.Event(), deadline_monotonic=time.monotonic() + 1
    )


def _held(lock):
    entered = threading.Event()
    release = threading.Event()

    def hold():
        with lock:
            entered.set()
            assert release.wait(2)

    worker = threading.Thread(target=hold)
    worker.start()
    assert entered.wait(1)
    return (release, worker)


def test_scoped_store_starts_explicit_transaction_and_finalizes_pending_hash(tmp_path):
    store = GuardStore(tmp_path / "guard")
    with sqlite3.connect(store.path) as raw:
        raw.execute(
            "insert into guard_review_outbox_events "
            "(event_id,local_request_id,request_sequence,event_type,event_schema_version,"
            "payload_json,payload_hash,occurred_at,binding_status) "
            "values ('test-event','test-request',1,'test',1,'{}','','test','quarantined')"
        )
    with (
        store_maintenance_scope(store.path, _lookup(store), deadline_monotonic=time.monotonic() + 1),
        store._connect() as connection,
    ):
        assert isinstance(connection, DeadlineConnection)
        assert connection.in_transaction
        assert connection.execute("select payload_hash from guard_review_outbox_events").fetchone()[0] == ""
    with sqlite3.connect(store.path) as raw:
        assert len(raw.execute("select payload_hash from guard_review_outbox_events").fetchone()[0]) == 64


@pytest.mark.parametrize("which", ["registry", "condition"])
def test_actual_postcommit_wake_timeout_does_not_rollback(tmp_path, which):
    store = GuardStore(tmp_path / "guard")
    signal = wake.review_event_wake_signal(store.path)
    lookup = _lookup(store)
    release, worker = _held(wake._SIGNALS_LOCK if which == "registry" else signal._condition)
    began = time.monotonic()
    try:
        with (
            pytest.raises(SQLiteDeadlineExceededError),
            store_maintenance_scope(store.path, lookup, deadline_monotonic=began + 0.05),
            store._connect() as connection,
        ):
            connection.execute("update guard_devices set installation_id='committed'")
        assert time.monotonic() - began < 0.15
    finally:
        release.set()
        worker.join(1)
    assert store.get_device_metadata()["installation_id"] == "committed"


def test_scoped_final_wake_never_resolves_a_fresh_path(tmp_path, monkeypatch):
    store = GuardStore(tmp_path / "guard")
    lookup = _lookup(store)
    signal = wake.review_event_wake_signal(store.path)
    before = signal.generation()
    original = Path.resolve
    monkeypatch.setattr(Path, "resolve", lambda *a, **k: pytest.fail("fresh finalization resolve"))
    with (
        store_maintenance_scope(store.path, lookup, deadline_monotonic=time.monotonic() + 1),
        store._connect() as connection,
    ):
        connection.execute("update guard_devices set installation_id='changed'")
    assert signal.generation() == before + 1
    monkeypatch.setattr(Path, "resolve", original)


def test_lookup_cannot_be_borrowed_by_another_store(tmp_path):
    first = GuardStore(tmp_path / "first")
    second = GuardStore(tmp_path / "second")
    lookup = _lookup(first)
    with (
        pytest.raises(SQLiteDeadlineUnsupportedError),
        store_maintenance_scope(second.path, lookup, deadline_monotonic=time.monotonic() + 1),
    ):
        pytest.fail("mismatched scope entered")
    with (
        store_maintenance_scope(first.path, lookup, deadline_monotonic=time.monotonic() + 1),
        pytest.raises(SQLiteDeadlineUnsupportedError),
        second._connect(),
    ):
        pytest.fail("another Store entered")


@pytest.mark.parametrize("transaction", ["begin immediate", "begin"])
def test_actual_transient_begin_or_commit_contention_succeeds(tmp_path, transaction):
    store = GuardStore(tmp_path / "guard")
    with sqlite3.connect(store.path) as raw:
        raw.execute("pragma journal_mode=delete")
    held = threading.Event()

    def contend():
        with sqlite3.connect(store.path) as raw:
            raw.execute(transaction)
            raw.execute("select installation_id from guard_devices").fetchone()
            held.set()
            time.sleep(0.05)

    worker = threading.Thread(target=contend)
    worker.start()
    assert held.wait(1)
    try:
        with (
            store_maintenance_scope(store.path, _lookup(store), deadline_monotonic=time.monotonic() + 1),
            store._connect() as connection,
        ):
            connection.execute("update guard_devices set installation_id='changed'")
    finally:
        worker.join(1)
    assert store.get_device_metadata()["installation_id"] == "changed"


def test_nested_scoped_connection_cannot_extend_outer_deadline(tmp_path):
    store = GuardStore(tmp_path / "guard")
    lookup = _lookup(store)
    old = store.get_device_metadata()["installation_id"]
    begin = time.monotonic()
    with (
        pytest.raises(SQLiteDeadlineExceededError),
        store_maintenance_scope(store.path, lookup, deadline_monotonic=begin + 0.05),
        store._connect() as connection,
    ):
        connection.execute("update guard_devices set installation_id='uncommitted'")
        with store._connect():
            pytest.fail("second writer entered")
    assert time.monotonic() - begin < 0.15
    assert store.get_device_metadata()["installation_id"] == old


def test_delayed_lookup_returns_no_late_hint(tmp_path, monkeypatch):
    store = GuardStore(tmp_path / "guard")
    original = Path.resolve
    finished = threading.Event()

    def resolve(path, *a, **k):
        try:
            time.sleep(0.1)
            return original(path, *a, **k)
        finally:
            finished.set()

    monkeypatch.setattr(Path, "resolve", resolve)
    deadline = time.monotonic() + 0.03
    assert (
        run_native_control_worker(
            lambda cancelled: capture_store_maintenance_lookup(
                store.path, cancelled=cancelled, deadline_monotonic=deadline
            ),
            deadline_monotonic=deadline,
        )
        is None
    )
    assert finished.wait(1)


def test_store_gate_receives_original_deadline_and_default_call_stays_unchanged(tmp_path, monkeypatch):
    from codex_plugin_scanner.guard import store_connection_schema as schema

    store = GuardStore(tmp_path / "guard")
    lookup = _lookup(store)
    original = schema.hold_storage_file_lock
    observed = []

    def hold(*args, **kwargs):
        observed.append(kwargs)
        return original(*args, **kwargs)

    monkeypatch.setattr(schema, "hold_storage_file_lock", hold)
    deadline = time.monotonic() + 1
    with store_maintenance_scope(store.path, lookup, deadline_monotonic=deadline), store._connect():
        pass
    assert observed[-1]["deadline_monotonic"] == deadline
    with store._connect():
        pass
    assert "deadline_monotonic" not in observed[-1]
