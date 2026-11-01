from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import cloud_review_event_delivery as delivery
from codex_plugin_scanner.guard.runtime import cloud_review_sync
from tests.guard_exact_cloud_review_support import add_review_request, connected_exact_review_store, review_request


def test_source_gap_recovery_generic_repair_is_acknowledged(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = connected_exact_review_store(tmp_path)
    add_review_request(store, review_request("gap-request"))
    binding = store.get_review_event_oauth_binding()
    assert binding is not None
    auth: dict[str, object] = {"sync_url": "https://guard.example", **binding}
    snapshot_seen = False
    deliveries: list[tuple[str, str]] = []

    def post(_auth: dict[str, object], *, path: str, payload: dict[str, object]) -> dict[str, object]:
        nonlocal snapshot_seen
        del path
        events = payload["events"]
        assert isinstance(events, list)
        results = []
        for event in events:
            event_type = json.loads(event["eventPayloadJson"])["eventType"]
            deliveries.append((event["eventId"], event_type))
            if event_type == "review.request.snapshot_requeued":
                assert json.loads(event["eventPayloadJson"])["nativeReplay"] is False
                snapshot_seen = True
                status = "accepted"
            elif snapshot_seen:
                status = "stale"
            else:
                status = "quarantined"
            results.append(
                {
                    "eventId": event["eventId"],
                    "status": status,
                    "code": "review_event_snapshot_required" if status == "quarantined" else None,
                }
            )
        accepted = sum(row["status"] != "quarantined" for row in results)
        return {
            "protocolVersion": 2,
            "acknowledgedThrough": 100,
            "accepted": accepted,
            "rejected": len(events) - accepted,
            "results": results,
        }

    monkeypatch.setattr(delivery, "_post_json", post)
    cloud_review_sync.sync_cloud_review_events_once(store, auth)
    assert snapshot_seen
    with store._connect() as connection:
        connection.execute("update guard_review_outbox_events set next_attempt_at = null where acknowledged_at is null")
    result = cloud_review_sync.sync_cloud_review_events_once(store, auth)
    snapshot_ids = [event_id for event_id, kind in deliveries if kind == "review.request.snapshot_requeued"]
    assert len(snapshot_ids) == 1
    status = store.get_sync_payload("guard_cloud_review_sync_state")
    assert isinstance(status, dict)
    outbox = result["outbox"]
    assert isinstance(outbox, dict)
    assert status["state"] == "idle"
    assert outbox["depth"] == 0


def test_snapshot_repair_does_not_upload_other_identity_or_mint_consent(tmp_path: Path) -> None:
    store = connected_exact_review_store(tmp_path)
    add_review_request(store, review_request("current"))
    add_review_request(store, review_request("other"))
    with store._connect() as connection:
        connection.execute(
            "update guard_review_outbox_request_sequences set workspace_id = 'other' where local_request_id = 'other'"
        )
    count = store.requeue_pending_review_events(
        changed_at=datetime.now(timezone.utc).isoformat(),
        require_binding=True,
        snapshot_repair_sequences={"current": 1, "other": 1},
    )
    assert count == 1
    assert store.get_sync_payload("guard_exact_cloud_review_capability") is None


def _outbox_rows(store: object) -> list[dict[str, object]]:
    with store._connect() as connection:  # type: ignore[attr-defined]
        rows = connection.execute(
            "select binding_status, quarantine_reason, acknowledged_at, attempt_count "
            "from guard_review_outbox_events order by stream_sequence"
        ).fetchall()
    return [dict(row) for row in rows]


def _quarantine_poster(code: str, status: str, counter: list[int]):
    def post(_auth: dict[str, object], *, path: str, payload: dict[str, object]) -> dict[str, object]:
        del path
        events = payload["events"]
        assert isinstance(events, list)
        counter.append(len(events))
        return {
            "protocolVersion": 2,
            "acknowledgedThrough": 100,
            "accepted": 0,
            "rejected": len(events),
            "retryAfterMs": 45_000,
            "results": [{"eventId": event["eventId"], "status": status, "code": code} for event in events],
        }

    return post


@pytest.mark.parametrize(
    "code",
    [
        "review_event_payload_hash_mismatch",
        "review_event_snapshot_claim_mismatch",
        "review_event_request_correlation_mismatch",
    ],
)
def test_stored_server_quarantine_is_dead_lettered_locally(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, code: str
) -> None:
    store = connected_exact_review_store(tmp_path)
    add_review_request(store, review_request("stored-quarantine"))
    binding = store.get_review_event_oauth_binding()
    assert binding is not None
    auth: dict[str, object] = {"sync_url": "https://guard.example", **binding}
    posts: list[int] = []
    monkeypatch.setattr(delivery, "_post_json", _quarantine_poster(code, "quarantined", posts))

    _ = cloud_review_sync.sync_cloud_review_events_once(store, auth)
    result = cloud_review_sync.sync_cloud_review_events_once(store, auth)

    rows = _outbox_rows(store)
    assert rows and all(row["binding_status"] == "quarantined" for row in rows)
    assert all(row["quarantine_reason"] == code and row["acknowledged_at"] is None for row in rows)
    assert len(posts) == 1
    outbox = result["outbox"]
    assert isinstance(outbox, dict)
    assert outbox["depth"] == 0
    assert outbox["quarantined_depth"] == len(rows)
    request = store.get_approval_request("stored-quarantine")
    assert request is not None and request["status"] == "pending"


def test_snapshot_required_for_resolved_request_is_dead_lettered(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = connected_exact_review_store(tmp_path)
    add_review_request(store, review_request("resolved-request"))
    with store._connect() as connection:
        connection.execute("update approval_requests set status = 'resolved' where request_id = 'resolved-request'")
    binding = store.get_review_event_oauth_binding()
    assert binding is not None
    auth: dict[str, object] = {"sync_url": "https://guard.example", **binding}
    posts: list[int] = []
    monkeypatch.setattr(
        delivery, "_post_json", _quarantine_poster("review_event_snapshot_required", "quarantined", posts)
    )

    _ = cloud_review_sync.sync_cloud_review_events_once(store, auth)
    _ = cloud_review_sync.sync_cloud_review_events_once(store, auth)

    rows = _outbox_rows(store)
    assert rows and all(row["quarantine_reason"] == "review_event_snapshot_required" for row in rows)
    assert len(posts) == 1


def test_event_rejected_without_a_terminal_code_is_dead_lettered_after_the_attempt_cap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_plugin_scanner.guard.runtime.cloud_review_retry_recovery import MAX_REJECTED_DELIVERY_ATTEMPTS

    store = connected_exact_review_store(tmp_path)
    add_review_request(store, review_request("endless-request"))
    binding = store.get_review_event_oauth_binding()
    assert binding is not None
    auth: dict[str, object] = {"sync_url": "https://guard.example", **binding}
    posts: list[int] = []
    monkeypatch.setattr(
        delivery, "_post_json", _quarantine_poster("review_event_unrecognized_failure", "rejected", posts)
    )

    for _ in range(MAX_REJECTED_DELIVERY_ATTEMPTS + 3):
        with store._connect() as connection:
            connection.execute(
                "update guard_review_outbox_events set next_attempt_at = null where binding_status = 'ready'"
            )
        _ = cloud_review_sync.sync_cloud_review_events_once(store, auth)

    rows = _outbox_rows(store)
    assert rows and all(row["binding_status"] == "quarantined" for row in rows)
    assert all(row["quarantine_reason"] == "review_event_retry_exhausted" for row in rows)
    assert len(posts) == MAX_REJECTED_DELIVERY_ATTEMPTS


def test_batch_without_progress_reports_a_queue_wide_stall_with_the_server_hint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = connected_exact_review_store(tmp_path)
    add_review_request(store, review_request("stalled-request"))
    binding = store.get_review_event_oauth_binding()
    assert binding is not None
    auth: dict[str, object] = {"sync_url": "https://guard.example", **binding}
    monkeypatch.setattr(delivery, "_post_json", _quarantine_poster("review_event_unrecognized_failure", "rejected", []))

    result = cloud_review_sync.sync_cloud_review_events_once(store, auth)

    assert result["stalled"] is True
    assert result["retry_after_ms"] == 45_000


def _rejection_counts(store: object) -> dict[str, int]:
    from codex_plugin_scanner.guard.runtime.cloud_review_retry_recovery import _REJECTION_COUNTS_KEY

    payload = store.get_sync_payload(f"{_REJECTION_COUNTS_KEY}:{store.guard_source}")  # type: ignore[attr-defined]
    return dict(payload) if isinstance(payload, dict) else {}


def _release_backoff(store: object) -> None:
    with store._connect() as connection:  # type: ignore[attr-defined]
        connection.execute(
            "update guard_review_outbox_events set next_attempt_at = null where binding_status = 'ready'"
        )


def test_stall_after_an_accepted_batch_still_reports_a_queue_wide_stall(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = connected_exact_review_store(tmp_path)
    add_review_request(store, review_request("first-request"))
    binding = store.get_review_event_oauth_binding()
    assert binding is not None
    auth: dict[str, object] = {"sync_url": "https://guard.example", **binding}
    calls: list[int] = []

    def post(_auth: dict[str, object], *, path: str, payload: dict[str, object]) -> dict[str, object]:
        del path
        events = payload["events"]
        assert isinstance(events, list)
        calls.append(len(events))
        if len(calls) == 1:
            add_review_request(store, review_request("second-request"))
            results = [{"eventId": event["eventId"], "status": "accepted"} for event in events]
            return {
                "protocolVersion": 2,
                "acknowledgedThrough": 100,
                "accepted": len(events),
                "rejected": 0,
                "results": results,
            }
        results = [
            {"eventId": event["eventId"], "status": "rejected", "code": "review_event_unrecognized_failure"}
            for event in events
        ]
        return {
            "protocolVersion": 2,
            "acknowledgedThrough": 100,
            "accepted": 0,
            "rejected": len(events),
            "retryAfterMs": 30_000,
            "results": results,
        }

    monkeypatch.setattr(delivery, "_post_json", post)

    result = cloud_review_sync.sync_cloud_review_events_once(store, auth)

    assert len(calls) == 2
    assert result["stalled"] is True
    assert result["retry_after_ms"] == 30_000


def test_per_event_retry_hints_never_exhaust_the_attempt_cap(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard.runtime.cloud_review_retry_recovery import MAX_REJECTED_DELIVERY_ATTEMPTS

    store = connected_exact_review_store(tmp_path)
    add_review_request(store, review_request("busy-request"))
    binding = store.get_review_event_oauth_binding()
    assert binding is not None
    auth: dict[str, object] = {"sync_url": "https://guard.example", **binding}

    def post(_auth: dict[str, object], *, path: str, payload: dict[str, object]) -> dict[str, object]:
        del path
        events = payload["events"]
        assert isinstance(events, list)
        results = [
            {"eventId": event["eventId"], "status": "rejected", "code": "review_event_busy", "retryAfterMs": 1_000}
            for event in events
        ]
        return {
            "protocolVersion": 2,
            "acknowledgedThrough": 100,
            "accepted": 0,
            "rejected": len(events),
            "results": results,
        }

    monkeypatch.setattr(delivery, "_post_json", post)
    for _ in range(MAX_REJECTED_DELIVERY_ATTEMPTS + 3):
        _release_backoff(store)
        _ = cloud_review_sync.sync_cloud_review_events_once(store, auth)

    rows = _outbox_rows(store)
    assert rows and all(row["binding_status"] == "ready" and row["quarantine_reason"] is None for row in rows)


def test_snapshot_repair_for_a_pending_request_does_not_count_toward_the_cap(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.runtime.cloud_review_retry_recovery import (
        MAX_REJECTED_DELIVERY_ATTEMPTS,
        dead_letter_exhausted_review_events,
    )

    store = connected_exact_review_store(tmp_path)
    add_review_request(store, review_request("repairing-request"))
    binding = store.get_review_event_oauth_binding()
    assert binding is not None
    with store._connect() as connection:
        rows = connection.execute("select stream_sequence, local_request_id from guard_review_outbox_events").fetchall()
    sequences = [int(row["stream_sequence"]) for row in rows]
    events = {int(row["stream_sequence"]): {"localRequestId": row["local_request_id"]} for row in rows}
    results: list[dict[str, object]] = [{"code": "review_event_snapshot_required", "status": "rejected"}] * len(rows)

    for _ in range(MAX_REJECTED_DELIVERY_ATTEMPTS + 3):
        retained, dead_lettered = dead_letter_exhausted_review_events(
            store, sequences=sequences, results=results, events=events, cleared=[], binding=binding
        )
        assert retained == sequences and dead_lettered == 0
    assert _rejection_counts(store) == {}


def test_rejection_counts_survive_a_backlog_larger_than_the_tracking_window(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.runtime.cloud_review_retry_recovery import dead_letter_exhausted_review_events

    store = connected_exact_review_store(tmp_path)
    binding = store.get_review_event_oauth_binding()
    assert binding is not None
    sequences = list(range(1, 4100))
    results: list[dict[str, object]] = [{"code": "review_event_unrecognized_failure"}] * len(sequences)

    for _ in range(2):
        _ = dead_letter_exhausted_review_events(
            store, sequences=sequences, results=results, events={}, cleared=[], binding=binding
        )

    counts = _rejection_counts(store)
    assert counts["1"] == 2 and len(counts) == len(sequences)


@pytest.mark.parametrize("acknowledgement", ["per-event", "whole-batch"])
def test_rejection_counts_are_cleared_when_events_leave_the_retry_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, acknowledgement: str
) -> None:
    store = connected_exact_review_store(tmp_path)
    add_review_request(store, review_request("recovering-request"))
    binding = store.get_review_event_oauth_binding()
    assert binding is not None
    auth: dict[str, object] = {"sync_url": "https://guard.example", **binding}
    accepting = {"value": False}

    def post(_auth: dict[str, object], *, path: str, payload: dict[str, object]) -> dict[str, object]:
        del path
        events = payload["events"]
        assert isinstance(events, list)
        status = "accepted" if accepting["value"] else "rejected"
        code = None if accepting["value"] else "review_event_unrecognized_failure"
        results = [{"eventId": event["eventId"], "status": status, "code": code} for event in events]
        accepted = len(events) if accepting["value"] else 0
        return {
            "protocolVersion": 2,
            "acknowledgedThrough": 100,
            "accepted": accepted,
            "rejected": len(events) - accepted,
            "results": results,
        }

    monkeypatch.setattr(delivery, "_post_json", post)
    _ = cloud_review_sync.sync_cloud_review_events_once(store, auth)
    assert _rejection_counts(store)

    if acknowledgement == "whole-batch":
        # A reply without per-event results acknowledges the whole batch.
        monkeypatch.setattr(
            cloud_review_sync,
            "_post_events_with_oauth_refresh",
            lambda _store, context, events: ({"accepted": len(events), "rejected": 0}, context),
        )
    accepting["value"] = True
    _release_backoff(store)
    _ = cloud_review_sync.sync_cloud_review_events_once(store, auth)

    assert _rejection_counts(store) == {}
    assert all(row["acknowledged_at"] is not None for row in _outbox_rows(store))


def test_snapshot_required_is_retried_while_an_earlier_snapshot_is_still_queued(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = connected_exact_review_store(tmp_path)
    add_review_request(store, review_request("queued-snapshot"))
    assert store.requeue_pending_review_events(
        changed_at=datetime.now(timezone.utc).isoformat(), request_ids={"queued-snapshot"}
    )
    with store._connect() as connection:
        connection.execute("update approval_requests set status = 'resolved' where request_id = 'queued-snapshot'")
        connection.execute(
            "update guard_review_outbox_events set next_attempt_at = '2099-01-01T00:00:00+00:00' "
            "where stream_sequence = (select min(stream_sequence) from guard_review_outbox_events)"
        )
    binding = store.get_review_event_oauth_binding()
    assert binding is not None
    auth: dict[str, object] = {"sync_url": "https://guard.example", **binding}
    posts: list[int] = []
    monkeypatch.setattr(delivery, "_post_json", _quarantine_poster("review_event_snapshot_required", "rejected", posts))

    _ = cloud_review_sync.sync_cloud_review_events_once(store, auth)

    assert posts
    rows = _outbox_rows(store)
    assert len(rows) >= 2
    assert all(row["binding_status"] == "ready" and row["quarantine_reason"] is None for row in rows)
