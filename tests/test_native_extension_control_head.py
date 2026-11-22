"""The extension-control head and transition reads, answered by the native store."""

from __future__ import annotations

import sqlite3
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.native_extension_control_head import (
    SnapshotHead,
    extension_control_recovery_transition,
    extension_control_snapshot_head,
    extension_control_transition_committed,
)
from codex_plugin_scanner.guard.runtime.extension_control_authority import ExtensionControlAuthorityError


def answered(answer):
    calls = []

    def call(method, args):
        calls.append((method, dict(args)))
        return answer

    return SimpleNamespace(_native_store_call=call), calls


def test_the_head_is_read_as_stored():
    store, calls = answered({"snapshot": {"revision": 4, "snapshot_digest": "s", "catalog_digest": "c"}})
    assert extension_control_snapshot_head(store) == SnapshotHead(4, "s", "c")
    assert calls == [("extension_control_snapshot_head", {})]


def test_no_snapshot_row_has_no_head():
    store, _ = answered({"snapshot": None})
    assert extension_control_snapshot_head(store) is None


@pytest.mark.parametrize(
    "snapshot",
    [
        {"revision": None, "snapshot_digest": "s", "catalog_digest": "c"},
        {"revision": True, "snapshot_digest": "s", "catalog_digest": "c"},
        {"revision": 4, "snapshot_digest": None, "catalog_digest": "c"},
        {"revision": 4, "snapshot_digest": "s", "catalog_digest": None},
    ],
)
def test_a_row_of_the_wrong_type_is_an_invalid_authority_row(snapshot):
    store, _ = answered({"snapshot": snapshot})
    with pytest.raises(ExtensionControlAuthorityError, match="invalid extension control authority row"):
        extension_control_snapshot_head(store)


@pytest.mark.parametrize(
    "answer",
    [
        None,
        {},
        {"snapshot": None, "extra": 1},
        {"snapshot": "row"},
        {"snapshot": {"revision": 4, "snapshot_digest": "s"}},
    ],
)
def test_a_malformed_head_answer_is_refused(answer):
    store, _ = answered(answer)
    with pytest.raises(sqlite3.DatabaseError, match="extension_control_snapshot_head"):
        extension_control_snapshot_head(store)


def test_the_recovery_transition_is_passed_through():
    store, calls = answered({"revision": 5})
    assert extension_control_recovery_transition(store, 4) == 5
    assert calls == [("extension_control_recovery_transition", {"revision": 4})]
    store, _ = answered({"revision": None})
    assert extension_control_recovery_transition(store, 4) is None


@pytest.mark.parametrize("answer", [None, {}, {"revision": "5"}, {"revision": True}, {"revision": 5, "x": 1}])
def test_a_malformed_recovery_answer_is_refused(answer):
    store, _ = answered(answer)
    with pytest.raises(sqlite3.DatabaseError, match="extension_control_recovery_transition"):
        extension_control_recovery_transition(store, 4)


def test_the_committed_check_is_passed_through():
    store, calls = answered({"committed": True})
    assert extension_control_transition_committed(store, 4) is True
    assert calls == [("extension_control_transition_committed", {"revision": 4})]
    store, _ = answered({"committed": False})
    assert extension_control_transition_committed(store, 4) is False


@pytest.mark.parametrize("answer", [None, {}, {"committed": 1}, {"committed": None}])
def test_a_malformed_committed_answer_is_refused(answer):
    store, _ = answered(answer)
    with pytest.raises(sqlite3.DatabaseError, match="extension_control_transition_committed"):
        extension_control_transition_committed(store, 4)


def test_an_open_connection_scope_reads_on_the_shared_connection(monkeypatch):
    from codex_plugin_scanner.guard import native_extension_control_head

    connection = sqlite3.connect(":memory:")
    connection.executescript(
        "create table extension_control_authority_snapshot ("
        "  singleton integer primary key, revision, catalog_digest, snapshot_digest);"
        "create table extension_control_authority_transition (revision integer primary key, phase text not null);"
    )

    def refuse(method, args):
        raise AssertionError("an owned scope must not call the resident")

    store = SimpleNamespace(_native_store_call=refuse, _connect=lambda: connection)
    monkeypatch.setattr(native_extension_control_head, "owns_scope", lambda _store: True)

    assert extension_control_snapshot_head(store) is None
    assert extension_control_recovery_transition(store, 4) is None
    assert extension_control_transition_committed(store, 4) is False
    connection.execute("insert into extension_control_authority_snapshot values (1, 4, 'c', 's')")
    connection.execute("insert into extension_control_authority_transition values (4, 'committed')")
    connection.execute("insert into extension_control_authority_transition values (5, 'prepared')")
    assert extension_control_snapshot_head(store) == SnapshotHead(4, "s", "c")
    assert extension_control_recovery_transition(store, 4) == 5
    assert extension_control_recovery_transition(store, 5) == 5
    assert extension_control_transition_committed(store, 4) is True
    assert extension_control_transition_committed(store, 5) is False
    connection.execute("update extension_control_authority_snapshot set revision = '4'")
    with pytest.raises(ExtensionControlAuthorityError):
        extension_control_snapshot_head(store)
