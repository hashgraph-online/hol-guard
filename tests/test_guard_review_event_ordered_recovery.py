from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import live_request_sync
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_review_event_outbox_test_support import (
    auth_context,
    connect_store,
    replace_event_payload,
    review_request,
)

_NOW = "2026-08-24T14:00:00+00:00"
_LATER = "2026-08-24T14:00:01+00:00"


def test_corrupt_head_blocks_tail_until_same_sequence_recovers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard")
    binding = connect_store(store)
    store.add_approval_request(review_request("request-1"), _NOW)
    with store._connect() as connection:
        first = connection.execute("select * from guard_review_outbox_events order by stream_sequence").fetchone()
    assert first is not None
    original_payload = json.loads(str(first["payload_json"]))
    store.add_approval_request(review_request("request-2"), _NOW)
    with store._connect() as connection:
        connection.execute(
            "update guard_review_outbox_events set payload_hash = '00' where stream_sequence = ?",
            (first["stream_sequence"],),
        )
    sent: list[dict[str, object]] = []

    def accept(*_args: object, events: list[dict[str, object]], **_kwargs: object) -> dict[str, object]:
        sent.extend(events)
        return {
            "accepted": len(events),
            "rejected": 0,
            "highestContiguousAcknowledgedStreamSequence": max(
                (int(event["localStreamSequence"]) for event in events), default=0
            ),
            "perEventResults": [{"index": index, "accepted": True} for index, _event in enumerate(events)],
        }

    monkeypatch.setattr(live_request_sync, "_post_sync_events", accept)

    first_result = live_request_sync.sync_live_requests_once(store, auth_context(binding))

    assert first_result["synced"] == 0 and sent == []
    with store._connect() as connection:
        blocked = connection.execute("select * from guard_review_outbox_events order by stream_sequence").fetchall()
        cursor_before = connection.execute("select * from guard_review_outbox_cursors").fetchone()
    assert [row["binding_status"] for row in blocked] == ["quarantined", "ready"]
    assert cursor_before is None

    replace_event_payload(store, blocked[0], original_payload)
    assert store.retry_live_request_outbox_dead_letters([int(first["stream_sequence"])], **binding) == 1
    restored = store.list_ready_live_request_outbox(now=_LATER, limit=10, **binding)
    assert [row["stream_sequence"] for row in restored] == [first["stream_sequence"], blocked[1]["stream_sequence"]]

    recovered_result = live_request_sync.sync_live_requests_once(store, auth_context(binding))

    assert recovered_result["synced"] == 2
    assert [event["localStreamSequence"] for event in sent] == [first["stream_sequence"], blocked[1]["stream_sequence"]]
    with store._connect() as connection:
        remaining = connection.execute("select count(*) as count from guard_review_outbox_events").fetchone()
        cursor_after = connection.execute("select * from guard_review_outbox_cursors").fetchone()
    assert remaining is not None and remaining["count"] == 0
    assert cursor_after is not None and cursor_after["acknowledged_stream_sequence"] == blocked[1]["stream_sequence"]
