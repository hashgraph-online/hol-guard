"""The native store reads the command queue lanes' state rows in one snapshot."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import command_queue_drain
from codex_plugin_scanner.guard.runtime.command_queue_state import COMMAND_QUEUE_STATE_KEY
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_command_queue_lanes import CommandQueueLaneRow

_NOW = "2026-11-22T00:00:00+00:00"
_DRAIN = f"{COMMAND_QUEUE_STATE_KEY}.review_drain.1"


def test_missing_lanes_hold_nothing(tmp_path: Path) -> None:
    assert GuardStore(tmp_path).command_queue_lane_rows([COMMAND_QUEUE_STATE_KEY, _DRAIN]) == (
        CommandQueueLaneRow(COMMAND_QUEUE_STATE_KEY, True, False, False, 1),
        CommandQueueLaneRow(_DRAIN, True, False, False, 1),
    )


def test_each_lane_reports_its_pending_result_and_limit(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    store.set_sync_payload(COMMAND_QUEUE_STATE_KEY, {"state": "idle", "exact_lease_batch_limit": 5}, _NOW)
    store.set_sync_payload(
        _DRAIN,
        {"state": "result_pending", "pending_result": {"job": {"id": "job-1"}, "payload": {}}},
        _NOW,
    )

    assert store.command_queue_lane_rows([COMMAND_QUEUE_STATE_KEY, _DRAIN]) == (
        CommandQueueLaneRow(COMMAND_QUEUE_STATE_KEY, True, False, True, 5),
        CommandQueueLaneRow(_DRAIN, True, True, False, 1),
    )


def test_a_lane_that_is_not_json_is_unreadable(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    store.set_sync_payload(_DRAIN, {"state": "idle"}, _NOW)
    with sqlite3.connect(store.path) as connection:
        connection.execute("update sync_state set payload_json = 'not-json' where state_key = ?", (_DRAIN,))

    assert store.command_queue_lane_rows([_DRAIN]) == (CommandQueueLaneRow(_DRAIN, False, False, False, 1),)


def test_keys_outside_the_queue_lanes_are_refused(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="invalid_state_key"):
        GuardStore(tmp_path).command_queue_lane_rows([COMMAND_QUEUE_STATE_KEY, "oauth_local_credentials"])


def test_an_unparseable_drain_lane_does_not_hide_another_lanes_result(tmp_path: Path, caplog) -> None:
    store = GuardStore(tmp_path)
    broken = command_queue_drain.review_drain_lane(0).state_key
    store.set_sync_payload(broken, {"state": "idle"}, _NOW)
    store.set_sync_payload(
        command_queue_drain.review_drain_lane(3).state_key,
        {"state": "result_pending", "pending_result": {"job": {"id": "job-3"}, "payload": {}}},
        _NOW,
    )
    with sqlite3.connect(store.path) as connection:
        connection.execute("update sync_state set payload_json = 'not-json' where state_key = ?", (broken,))

    with caplog.at_level("WARNING"):
        assert command_queue_drain.review_drain_has_pending_result(store) is True
        assert command_queue_drain._lane_has_pending_result(store, 0, unreadable=True) is True
        assert command_queue_drain._lane_has_pending_result(store, 0) is False
    assert "drain state unreadable: slot=0 error=unparseable_row" in caplog.text


def test_a_damaged_blob_lane_does_not_hide_another_lanes_result(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    broken = command_queue_drain.review_drain_lane(0).state_key
    store.set_sync_payload(broken, {"state": "idle"}, _NOW)
    store.set_sync_payload(
        command_queue_drain.review_drain_lane(2).state_key,
        {"state": "result_pending", "pending_result": {"job": {"id": "job-2"}, "payload": {}}},
        _NOW,
    )
    with sqlite3.connect(store.path) as connection:
        connection.execute("update sync_state set payload_json = ? where state_key = ?", (b"\xff\xfe{", broken))

    assert store.command_queue_lane_rows([broken]) == (CommandQueueLaneRow(broken, False, False, False, 1),)
    assert command_queue_drain.review_drain_has_pending_result(store) is True


def test_an_answer_without_a_whole_lease_limit_is_refused() -> None:
    answer = {"state_key": _DRAIN, "readable": True, "exact_lease_batch_limit": True}
    with pytest.raises(RuntimeError, match="no lease limit"):
        CommandQueueLaneRow.from_native(answer, _DRAIN)
