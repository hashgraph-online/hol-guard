"""The queue lease batch limit is merged into the lane's row by the native store."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.command_queue_state import (
    COMMAND_QUEUE_STATE_KEY,
    load_command_queue_state,
    record_exact_lease_batch_limit,
)
from codex_plugin_scanner.guard.store import GuardStore

_NOW = "2026-09-27T12:00:00+00:00"


def test_recording_keeps_a_write_made_since_the_state_was_loaded(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    state = load_command_queue_state(store)
    store.set_sync_payload(COMMAND_QUEUE_STATE_KEY, {"state": "result_pending", "last_error": None}, _NOW)

    record_exact_lease_batch_limit(store, state, 4)

    assert state["exact_lease_batch_limit"] == 4
    assert store.get_sync_payload(COMMAND_QUEUE_STATE_KEY) == {
        "state": "result_pending",
        "last_error": None,
        "exact_lease_batch_limit": 4,
    }


def test_the_store_reports_whether_the_row_changed(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")

    assert store.record_command_queue_lease_limit(COMMAND_QUEUE_STATE_KEY, 2, now=_NOW) is True
    assert store.record_command_queue_lease_limit(COMMAND_QUEUE_STATE_KEY, 2, now=_NOW) is False
    assert store.get_sync_payload(COMMAND_QUEUE_STATE_KEY) == {"exact_lease_batch_limit": 2}


@pytest.mark.parametrize("state_key", ["oauth_local_credentials", "sync_summary"])
def test_a_row_outside_the_queue_lanes_is_refused(tmp_path: Path, state_key: str) -> None:
    store = GuardStore(tmp_path / "guard-home")

    with pytest.raises(ValueError, match="invalid_state_key"):
        store.record_command_queue_lease_limit(state_key, 2, now=_NOW)
    assert store.get_sync_payload(state_key) is None
