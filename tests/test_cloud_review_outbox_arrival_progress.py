"""Real outbox progress and materialization bounds under continuing arrivals."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.review_contracts import guard_review_oauth_metadata
from codex_plugin_scanner.guard.runtime import cloud_review_event_delivery, cloud_review_sync
from codex_plugin_scanner.guard.runtime.cloud_review_event_delivery import encoded_review_events_payload
from codex_plugin_scanner.guard.runtime.cloud_review_event_projection import project_cloud_review_event
from tests.guard_exact_cloud_review_support import add_review_request, connected_exact_review_store, review_request


def test_large_backlog_drains_with_oversize_rejections_and_continuing_arrivals(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = connected_exact_review_store(tmp_path)
    binding = store.get_review_event_oauth_binding()
    assert binding is not None
    delivery_binding = {key: value for key, value in binding.items() if key != "oauth_source"}
    now = "2098-01-01T00:00:00+00:00"
    monkeypatch.setattr(cloud_review_sync, "_now", lambda: now)
    backlog = 128
    for index in range(backlog):
        request = review_request(f"arrival-{index:06d}")
        if index == 0:
            request = replace(request, artifact_name="Oversized " * 2_000)
        add_review_request(store, request)

    initial = store.list_ready_review_events(now=now, limit=2, newest_first=False, **delivery_binding)
    oauth = guard_review_oauth_metadata(store)
    projected = [
        project_cloud_review_event(
            store, outbox_row=row, delivery_binding=delivery_binding, redaction_level="standard", oauth=oauth
        )
        for row in initial
    ]
    oversized, ordinary = projected
    assert oversized is not None and ordinary is not None
    byte_limit = len(encoded_review_events_payload([ordinary[1]])) + 128
    assert len(encoded_review_events_payload([oversized[1]])) > byte_limit
    event_limit = 5
    cloud_review_sync._save_sync_state(
        store,
        {
            "batch_binding_key": cloud_review_sync._batch_binding_key(delivery_binding),
            "batch_events": event_limit,
            "batch_max_bytes": byte_limit,
            "batch_event_cap": event_limit,
        },
    )
    read_rows = store.list_ready_review_events
    materialized_counts: list[int] = []
    materialized_bytes: list[int] = []

    def observe_rows(*, now: str, limit: int, newest_first: bool = False, **identity: str) -> list[dict[str, object]]:
        rows = read_rows(now=now, limit=limit, newest_first=newest_first, **identity)
        assert limit <= event_limit
        materialized_counts.append(len(rows))
        materialized_bytes.append(sum(len(str(row["payload_json"]).encode()) for row in rows))
        return rows

    monkeypatch.setattr(store, "list_ready_review_events", observe_rows)
    posted: list[int] = []
    payload_sizes: list[int] = []
    accepted_ids: set[str] = set()
    first_accepted_call: dict[str, int] = {}
    rejected_ids: set[str] = set()
    snapshots: set[str] = set()
    acknowledged_through = 0

    def deliver_with_arrival(_auth: dict[str, object], *, path: str, payload: dict[str, object]) -> dict[str, object]:
        nonlocal acknowledged_through
        assert path == "/api/guard/review/v2/events:batch"
        events = payload["events"]
        assert isinstance(events, list) and len(events) == 1
        event = events[0]
        assert isinstance(event, dict)
        sequence = event["localStreamSequence"]
        assert isinstance(sequence, int)
        posted.append(sequence)
        payload_sizes.append(len(encoded_review_events_payload([event])))
        assert payload_sizes[-1] <= byte_limit
        request_id = event["localRequestId"]
        assert isinstance(request_id, str)
        encoded_event = event["eventPayloadJson"]
        assert isinstance(encoded_event, str)
        stored_event = json.loads(encoded_event)
        is_snapshot = stored_event["eventType"] == "review.request.snapshot_requeued"
        if is_snapshot:
            # This must be a genuine production repair, including its claim.
            assert isinstance(event["reviewClaim"], dict)
            snapshots.add(request_id)
        if request_id.startswith("rejected-"):
            status, code = "rejected", "validation_failed"
            rejected_ids.add(request_id)
        elif sequence == acknowledged_through + 1 or is_snapshot:
            status, code = "accepted", None
            acknowledged_through = sequence
            accepted_ids.add(request_id)
            first_accepted_call.setdefault(request_id, len(posted))
        else:
            # Ordinary events cannot manufacture acceptance over a source gap.
            # The real sync loop must produce a new authenticated snapshot.
            status, code = "quarantined", "review_event_snapshot_required"
        # Commit a genuine new approval during every actual delivery call.
        # Its later sequence must not displace the existing eligible backlog.
        prefix = "rejected" if len(posted) % 7 == 0 else "arrival"
        add_review_request(store, review_request(f"{prefix}-{backlog + len(posted):06d}"))
        return {
            "protocolVersion": 2,
            "acknowledgedThrough": acknowledged_through,
            "accepted": int(status == "accepted"),
            "rejected": int(status != "accepted"),
            "results": [{"eventId": event["eventId"], "status": status, "code": code}],
            "maxBatchEvents": event_limit,
            "maxBatchBytes": byte_limit,
        }

    monkeypatch.setattr(cloud_review_event_delivery, "_post_json", deliver_with_arrival)
    results = [
        cloud_review_sync.sync_cloud_review_events_once(store, {"sync_url": "https://guard.example", **binding})
        for _ in range(3)
    ]

    # The oversized row stays recoverable. Ordinary rows retain oldest-first
    # order, and genuine snapshot repair resolves gaps despite continuing arrivals.
    assert cloud_review_sync.CLOUD_REVIEW_SYNC_MAX_BATCHES == 200
    assert all(result["batches"] == 200 for result in results)
    assert posted[: backlog - 1] == list(range(2, backlog + 1))
    assert next(iter(first_accepted_call)) == "arrival-000001"
    assert first_accepted_call["arrival-000001"] <= cloud_review_sync.CLOUD_REVIEW_SYNC_MAX_BATCHES
    assert {f"arrival-{index:06d}" for index in range(1, backlog)} <= accepted_ids
    assert snapshots and rejected_ids and not rejected_ids.intersection(accepted_ids)
    assert len(materialized_counts) == 600
    assert max(materialized_counts) == event_limit
    assert max(payload_sizes) <= byte_limit
    # Bound the actual SQL payload materialization independently of queue size;
    # this is deliberately not an unmeasured process-RSS assertion.
    largest_initial = max(len(str(row["payload_json"]).encode()) for row in initial)
    assert max(materialized_bytes) <= event_limit * largest_initial
    with store._connect() as connection:
        quarantine = connection.execute(
            "select quarantine_reason, last_error, payload_json, acknowledged_at "
            "from guard_review_outbox_events where stream_sequence = 1"
        ).fetchone()
        remaining = connection.execute("select count(*) from guard_review_outbox_events").fetchone()
    assert quarantine is not None and remaining is not None
    assert quarantine["quarantine_reason"] == "event_exceeds_upload_limit"
    assert "negotiated upload byte limit" in quarantine["last_error"]
    assert quarantine["payload_json"] == initial[0]["payload_json"]
    assert quarantine["acknowledged_at"] is None
    assert 0 < remaining[0] < backlog + len(posted)


def test_repeated_unsettled_rejection_keeps_one_repair_and_real_backoff(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = connected_exact_review_store(tmp_path)
    add_review_request(store, review_request("persistently-rejected"))
    binding = store.get_review_event_oauth_binding()
    assert binding is not None
    clock = datetime(2098, 1, 1, tzinfo=timezone.utc)
    monkeypatch.setattr(cloud_review_sync, "_now", lambda: clock.isoformat())
    observed_ids: dict[str, set[str]] = {}
    calls = 0

    def reject(_auth: dict[str, object], *, path: str, payload: dict[str, object]) -> dict[str, object]:
        nonlocal calls
        calls += 1
        assert path == "/api/guard/review/v2/events:batch"
        events = payload["events"]
        assert isinstance(events, list) and 1 <= len(events) <= 2
        responses: list[dict[str, object]] = []
        for event in events:
            assert isinstance(event, dict)
            encoded = event["eventPayloadJson"]
            event_id = event["eventId"]
            assert isinstance(encoded, str) and isinstance(event_id, str)
            kind = json.loads(encoded)["eventType"]
            observed_ids.setdefault(kind, set()).add(event_id)
            responses.append({"eventId": event_id, "status": "quarantined", "code": "review_event_snapshot_required"})
        return {
            "protocolVersion": 2,
            "acknowledgedThrough": 0,
            "accepted": 0,
            "rejected": len(events),
            "results": responses,
        }

    monkeypatch.setattr(cloud_review_event_delivery, "_post_json", reject)
    frozen_payloads: list[tuple[str, str, str]] | None = None
    for _ in range(3):
        result = cloud_review_sync.sync_cloud_review_events_once(
            store, {"sync_url": "https://guard.example", **binding}
        )
        assert result["synced"] == 0
        outbox = result["outbox"]
        assert isinstance(outbox, dict) and outbox["depth"] == 2 and outbox["ready_depth"] == 0
        retry_at = result["next_attempt_at"]
        assert isinstance(retry_at, str) and datetime.fromisoformat(retry_at) > clock
        with store._connect() as connection:
            rows = connection.execute(
                "select event_id, payload_json, payload_hash, attempt_count, last_error, acknowledged_at "
                "from guard_review_outbox_events order by stream_sequence"
            ).fetchall()
        assert len(rows) == 2
        assert all(row["attempt_count"] > 0 and row["acknowledged_at"] is None for row in rows)
        assert all("review_event_snapshot_required" in row["last_error"] for row in rows)
        payloads = [(row["event_id"], row["payload_json"], row["payload_hash"]) for row in rows]
        if frozen_payloads is None:
            frozen_payloads = payloads
        else:
            assert payloads == frozen_payloads
        # Move past the real bounded retry delay; do not erase retry state.
        clock += timedelta(seconds=301)
    assert calls == 4
    assert len(observed_ids) == 2 and all(len(event_ids) == 1 for event_ids in observed_ids.values())
    assert "review.request.snapshot_requeued" in observed_ids
