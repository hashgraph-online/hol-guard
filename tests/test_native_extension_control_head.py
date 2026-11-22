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
