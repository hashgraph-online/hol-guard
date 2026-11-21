"""Cloud Review sync steps are merged into the sync state row by the native store."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import cloud_review_sync
from codex_plugin_scanner.guard.runtime.cloud_review_sync import CLOUD_REVIEW_SYNC_STATE_KEY
from codex_plugin_scanner.guard.store import GuardStore

_NOW = "2026-09-27T12:00:00+00:00"


def test_a_started_run_keeps_a_write_made_since_the_state_was_loaded(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    store.set_sync_payload(
        CLOUD_REVIEW_SYNC_STATE_KEY,
        {"last_error": "old", "last_error_code": "cloud_auth_expired", "batch_events": 25},
        _NOW,
    )
    state: dict[str, object] = {"last_error": "old"}

    cloud_review_sync._transition_sync_state(store, state, "started")

    stored = store.get_sync_payload(CLOUD_REVIEW_SYNC_STATE_KEY)
    assert stored == state
    assert state["state"] == "syncing"
    assert state["last_error"] is None
    assert state["last_error_code"] is None
    assert state["batch_events"] == 25


def test_a_completed_run_records_the_outbox_and_delivery(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    state: dict[str, object] = {}
    binding = {"workspace_id": "w", "machine_id": "m"}

    cloud_review_sync._transition_sync_state(
        store,
        state,
        "completed",
        at=_NOW,
        counts={"accepted": 2, "delivered": 2, "rejected": 0},
        outbox={"depth": 1, "oldest_changed_at": _NOW},
        delivery_binding=binding,
        error="HTTP 503",
    )

    assert state == store.get_sync_payload(CLOUD_REVIEW_SYNC_STATE_KEY)
    assert state["state"] == "error"
    assert state["last_success_at"] == _NOW
    assert state["last_delivery_binding"] == binding
    assert state["outbox_depth"] == 1


def test_a_transient_failure_keeps_a_recorded_auth_code(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    store.set_sync_payload(CLOUD_REVIEW_SYNC_STATE_KEY, {"last_error_code": "cloud_connect_required"}, _NOW)
    state: dict[str, object] = {}

    cloud_review_sync._transition_sync_state(
        store, state, "failed", error="TimeoutError", error_code="cloud_delivery_error", keep_auth_code=True
    )

    assert state["state"] == "error"
    assert state["last_error"] == "TimeoutError"
    assert state["last_error_code"] == "cloud_connect_required"


@pytest.mark.parametrize(
    ("transition", "detail", "code"),
    [
        ("bogus", {}, "invalid_transition"),
        ("failed", {}, "invalid_error"),
        ("batch_limits", {"binding_key": "k", "limits": {"events": 1}}, "invalid_limits"),
    ],
)
def test_a_refused_step_writes_nothing(tmp_path: Path, transition: str, detail: dict[str, object], code: str) -> None:
    store = GuardStore(tmp_path / "guard-home")

    with pytest.raises(ValueError, match=code):
        store.transition_cloud_review_sync_state(CLOUD_REVIEW_SYNC_STATE_KEY, transition, now=_NOW, **detail)

    assert store.get_sync_payload(CLOUD_REVIEW_SYNC_STATE_KEY) is None
