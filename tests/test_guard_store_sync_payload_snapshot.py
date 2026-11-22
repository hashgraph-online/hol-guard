"""The native store reads several ``sync_state`` rows in one snapshot."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_sync_payload_snapshot import (
    SyncPayloadRowUnreadableError,
    sync_payload_snapshot_rows,
)

_NOW = "2026-11-22T00:00:00+00:00"


def test_rows_come_back_as_get_sync_payload_answers(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    store.set_sync_payload("sync_summary", {"synced_at": _NOW}, _NOW)
    store.set_sync_payload("runtime_session_summary", ["a"], _NOW)

    rows = store.sync_payload_snapshot("sync_summary", "runtime_session_summary", "supply_chain_bundle_summary")

    assert rows == {
        "sync_summary": {"synced_at": _NOW},
        "runtime_session_summary": ["a"],
        "supply_chain_bundle_summary": None,
    }
    assert list(rows) == ["sync_summary", "runtime_session_summary", "supply_chain_bundle_summary"]
    for key, value in rows.items():
        assert store.get_sync_payload(key) == value


def test_a_row_that_is_not_json_refuses_the_snapshot(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    store.set_sync_payload("sync_summary", {"synced_at": _NOW}, _NOW)
    with sqlite3.connect(store.path) as connection:
        connection.execute("update sync_state set payload_json = 'not-json' where state_key = 'sync_summary'")

    with pytest.raises(SyncPayloadRowUnreadableError, match="sync_payload_unreadable:sync_summary"):
        _ = store.sync_payload_snapshot("sync_summary", "runtime_session_summary")


@pytest.mark.parametrize("keys", [(), ("a", "a"), tuple(f"k{index}" for index in range(17))])
def test_a_malformed_key_list_is_refused_before_the_native_call(tmp_path: Path, keys: tuple[str, ...]) -> None:
    with pytest.raises(ValueError, match="distinct keys"):
        _ = GuardStore(tmp_path).sync_payload_snapshot(*keys)


@pytest.mark.parametrize(
    "answer",
    [
        None,
        {},
        {"rows": {"a": None, "b": None}},
        {"rows": {"a": None, "b": None}, "unreadable": False},
        {"rows": {"a": None, "b": None}, "unreadable": ["c"]},
        {"rows": {"a": None, "b": None}, "unreadable": [], "extra": 1},
        {"rows": {"a": None}, "unreadable": []},
        {"rows": {"a": 7, "b": None}, "unreadable": []},
        {"rows": [], "unreadable": []},
    ],
)
def test_a_malformed_answer_is_refused(answer: object) -> None:
    with pytest.raises(RuntimeError, match="no answer"):
        _ = sync_payload_snapshot_rows(answer, ("a", "b"))
