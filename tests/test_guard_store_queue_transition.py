"""Queue lane job steps are merged into the lane's row by the native store."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.command_queue_state import (
    COMMAND_QUEUE_STATE_KEY,
    transition_command_queue_state,
)
from codex_plugin_scanner.guard.store import GuardStore
from tests.support.command_queue_store import FakeStore

_NOW = "2026-09-27T12:00:00+00:00"
_AT = "2026-09-27T11:59:59+00:00"
_LEASED: dict[str, object] = {
    "state": "leased",
    "active_job": {"id": "job-1"},
    "pending_result": {"job": {"id": "job-0"}, "payload": {}},
    "last_error": "earlier",
    "exact_lease_batch_limit": 4,
}
_STEPS = (
    "disabled",
    "polling",
    "auth_expired",
    "heartbeat_failed",
    "settled",
    "result_refused",
    "stale_result_dropped",
    "malformed_result_dropped",
)


def test_a_step_keeps_a_write_made_since_the_state_was_loaded(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    state: dict[str, object] = {"state": "leased", "active_job": {"id": "job-1"}}
    store.set_sync_payload(COMMAND_QUEUE_STATE_KEY, {**state, "exact_lease_batch_limit": 3}, _NOW)

    transition_command_queue_state(store, state, "heartbeat_failed")

    expected = {"state": "error", "last_error": "Guard command heartbeat failed.", "exact_lease_batch_limit": 3}
    assert state == expected
    assert store.get_sync_payload(COMMAND_QUEUE_STATE_KEY) == expected


def test_a_pending_result_is_kept_with_its_record_time(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    pending: dict[str, object] = {"job": {"id": "job-1"}, "payload": {"status": "succeeded"}}

    merged = store.transition_command_queue_state(
        COMMAND_QUEUE_STATE_KEY, "result_pending", now=_NOW, at=_AT, pending=pending
    )

    assert merged == {"state": "result_pending", "pending_result": {**pending, "recorded_at": _AT}}
    with pytest.raises(ValueError, match="invalid_pending_result"):
        store.transition_command_queue_state(COMMAND_QUEUE_STATE_KEY, "result_pending", now=_NOW)


@pytest.mark.parametrize("step", _STEPS)
def test_the_test_double_takes_each_step_as_the_native_store_does(tmp_path: Path, step: str) -> None:
    store = GuardStore(tmp_path / "guard-home")
    double = FakeStore(tmp_path / "double-home")
    store.set_sync_payload(COMMAND_QUEUE_STATE_KEY, dict(_LEASED), _NOW)
    double.set_sync_payload(COMMAND_QUEUE_STATE_KEY, dict(_LEASED), _NOW)

    native = store.transition_command_queue_state(COMMAND_QUEUE_STATE_KEY, step, now=_NOW, at=_AT)

    assert native == double.transition_command_queue_state(COMMAND_QUEUE_STATE_KEY, step, now=_NOW, at=_AT)
    assert store.get_sync_payload(COMMAND_QUEUE_STATE_KEY) == native


@pytest.mark.parametrize(
    ("state_key", "step", "code"),
    [
        ("oauth_local_credentials", "polling", "invalid_state_key"),
        (COMMAND_QUEUE_STATE_KEY, "leased", "invalid_transition"),
    ],
)
def test_an_unknown_lane_or_step_is_refused(tmp_path: Path, state_key: str, step: str, code: str) -> None:
    store = GuardStore(tmp_path / "guard-home")

    with pytest.raises(ValueError, match=code):
        store.transition_command_queue_state(state_key, step, now=_NOW)
    assert store.get_sync_payload(state_key) is None
