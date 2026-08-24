from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import live_request_sync
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_review_event_outbox_test_support import (
    NOW,
    auth_context,
    connect_store,
    event_row,
    replace_event_payload,
    review_request,
)


def test_unsendable_batch_does_not_advance_authenticated_health(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard")
    binding = connect_store(store)
    store.add_approval_request(review_request("oversized"), NOW)
    replace_event_payload(store, event_row(store), {"payload": "x" * 300_000})
    previous = "2026-08-23T14:00:00+00:00"
    store.set_sync_payload(
        live_request_sync.LIVE_REQUEST_SYNC_STATE_KEY,
        {"last_authenticated_round_trip_at": previous},
        NOW,
    )
    calls = 0

    def post(*_args: object, **_kwargs: object) -> dict[str, object]:
        nonlocal calls
        calls += 1
        return {}

    monkeypatch.setattr(live_request_sync, "_post_sync_events", post)
    live_request_sync.sync_live_requests_once(store, auth_context(binding))
    state = store.get_sync_payload(live_request_sync.LIVE_REQUEST_SYNC_STATE_KEY)

    assert calls == 0
    assert isinstance(state, dict)
    assert state["last_authenticated_round_trip_at"] == previous


def test_empty_health_request_advances_authenticated_health(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard")
    binding = connect_store(store)
    calls = 0

    def post(*_args: object, **_kwargs: object) -> dict[str, object]:
        nonlocal calls
        calls += 1
        return {}

    monkeypatch.setattr(live_request_sync, "_post_sync_events", post)
    live_request_sync.sync_live_requests_once(store, auth_context(binding))
    state = store.get_sync_payload(live_request_sync.LIVE_REQUEST_SYNC_STATE_KEY)

    assert calls == 1
    assert isinstance(state, dict)
    assert state["last_authenticated_round_trip_at"] == state["last_sync_at"]
