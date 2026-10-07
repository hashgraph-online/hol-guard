from __future__ import annotations

import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.review_correlation import cloud_review_correlation_id
from codex_plugin_scanner.guard.runtime import cloud_review_event_delivery as delivery
from codex_plugin_scanner.guard.runtime import cloud_review_sync
from codex_plugin_scanner.guard.store_review_event_outbox_writes import append_request_snapshot_event
from tests.guard_exact_cloud_review_support import add_review_request, connected_exact_review_store, review_request


@pytest.mark.parametrize("code", ["review_continuation_binding_mismatch", "missing_request_snapshot"])
def test_terminal_binding_rejection_is_preserved_without_endless_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, code: str
) -> None:
    store = connected_exact_review_store(tmp_path)
    request_id = "terminal-binding-request"
    add_review_request(store, review_request(request_id))
    completed_at = "2026-08-24T12:01:00+00:00"
    with store._connect() as connection:
        assert (
            append_request_snapshot_event(
                connection,
                request_id=request_id,
                source=store.guard_source,
                event_type="review.continuation.unsupported",
                occurred_at=completed_at,
                continuation_result={
                    "action": "allow_once",
                    "capability": "unsupported",
                    "completedAt": completed_at,
                    "correlationId": cloud_review_correlation_id(request_id),
                    "evidenceId": "evidence-terminal-binding",
                    "reason": "harness_unsupported",
                    "status": "unsupported",
                },
            )
            == 1
        )
    binding = store.get_review_event_oauth_binding()
    assert binding is not None
    deliveries: list[str] = []

    def post(_auth: dict[str, object], *, path: str, payload: dict[str, object]) -> dict[str, object]:
        del path
        events = payload["events"]
        assert isinstance(events, list)
        results = []
        for event in events:
            terminal = event["eventType"] == "continuation_unsupported"
            deliveries.append(event["eventType"])
            results.append(
                {
                    "eventId": event["eventId"],
                    "status": "quarantined" if terminal else "accepted",
                    "code": code if terminal else None,
                }
            )
        rejected = sum(item["status"] == "quarantined" for item in results)
        return {
            "protocolVersion": 2,
            "acknowledgedThrough": 100,
            "accepted": len(events) - rejected,
            "rejected": rejected,
            "results": results,
        }

    monkeypatch.setattr(delivery, "_post_json", post)
    auth: dict[str, object] = {"sync_url": "https://guard.example", **binding}
    _ = cloud_review_sync.sync_cloud_review_events_once(store, auth)
    result = cloud_review_sync.sync_cloud_review_events_once(store, auth)
    outbox = result["outbox"]
    assert isinstance(outbox, dict)
    with store._connect() as connection:
        terminal = connection.execute(
            "select binding_status, quarantine_reason, acknowledged_at, attempt_count "
            "from guard_review_outbox_events where event_type = 'review.continuation.unsupported'"
        ).fetchone()
    assert terminal is not None
    assert terminal["acknowledged_at"] is None
    if code == "review_continuation_binding_mismatch":
        assert outbox["depth"] == 0
        assert outbox["quarantined_depth"] == 1
        assert terminal["binding_status"] == "quarantined"
        assert terminal["quarantine_reason"] == code
        assert terminal["attempt_count"] == 0
        assert deliveries.count("continuation_unsupported") == 1
    else:
        assert outbox["depth"] == 1
        assert outbox["quarantined_depth"] == 0
        assert terminal["binding_status"] == "ready"
        assert terminal["quarantine_reason"] is None
        assert terminal["attempt_count"] >= 1
    request = store.get_approval_request(request_id)
    assert request is not None and request["status"] == "pending"


@pytest.mark.parametrize("canonical_identity_confirmed", [True, False])
def test_rejected_retry_refresh_is_recovered_only_with_canonical_server_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, canonical_identity_confirmed: bool
) -> None:
    store = connected_exact_review_store(tmp_path)
    request_id = "retry-request"
    expected = cloud_review_correlation_id(request_id)
    changed = cloud_review_correlation_id("another-attempt")
    add_review_request(store, review_request(request_id))
    snapshot = {
        "correlationId": changed,
        "capability": "retry-only",
        "hookAttached": False,
        "opaqueTargetId": None,
        "waitDeadline": None,
    }
    with store._connect() as connection:
        _ = connection.execute(
            "update approval_requests set continuation_snapshot_json = ? where request_id = ?",
            (json.dumps(snapshot), request_id),
        )
    binding = store.get_review_event_oauth_binding()
    assert binding is not None
    auth: dict[str, object] = {"sync_url": "https://guard.example", **binding}
    deliveries: list[str] = []

    def post(_auth: dict[str, object], *, path: str, payload: dict[str, object]) -> dict[str, object]:
        del path
        events = payload["events"]
        assert isinstance(events, list)
        results: list[dict[str, object]] = []
        for event in events:
            correlation = event["correlationId"]
            deliveries.append(correlation)
            rejected = correlation != expected
            results.append(
                {
                    "eventId": event["eventId"],
                    "status": "quarantined" if rejected else "accepted",
                    "code": (
                        "review_event_canonical_correlation_required"
                        if canonical_identity_confirmed
                        else "review_event_request_correlation_mismatch"
                    )
                    if rejected
                    else None,
                }
            )
        rejected_count = sum(result["status"] == "quarantined" for result in results)
        return {
            "protocolVersion": 2,
            "acknowledgedThrough": 100,
            "accepted": len(events) - rejected_count,
            "rejected": rejected_count,
            "results": results,
        }

    monkeypatch.setattr(delivery, "_post_json", post)
    result = cloud_review_sync.sync_cloud_review_events_once(store, auth)
    if canonical_identity_confirmed:
        result = cloud_review_sync.sync_cloud_review_events_once(store, auth)
    assert changed in deliveries
    assert len(deliveries) <= 5
    saved = store.get_approval_request(request_id)
    assert saved is not None
    continuation = saved["continuation_snapshot"]
    assert isinstance(continuation, dict)
    assert continuation["correlationId"] == (expected if canonical_identity_confirmed else changed)
    assert saved["status"] == "pending"
    assert store.get_sync_payload("guard_exact_cloud_review_capability") is None
    outbox = result["outbox"]
    assert isinstance(outbox, dict)
    assert outbox["depth"] == (0 if canonical_identity_confirmed else 1)


@pytest.mark.parametrize("status", ["accepted", "duplicate", "stale"])
def test_last_activity_delivery_does_not_advance_for_heartbeat_or_discarded_events(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, status: str
) -> None:
    store = connected_exact_review_store(tmp_path)
    add_review_request(store, review_request("delivery-status"))
    old = "2026-08-24T12:00:00+00:00"
    now = "2026-08-24T12:01:00+00:00"
    store.set_sync_payload("guard_cloud_review_sync_state", {"last_delivery_at": old}, old)
    binding = store.get_review_event_oauth_binding()
    assert binding is not None

    def post(_auth: dict[str, object], *, path: str, payload: dict[str, object]) -> dict[str, object]:
        del path
        events = payload["events"]
        assert isinstance(events, list)
        return {
            "protocolVersion": 2,
            "acknowledgedThrough": 100,
            "accepted": len(events),
            "rejected": 0,
            "results": [{"eventId": event["eventId"], "status": status, "code": None} for event in events],
        }

    monkeypatch.setattr(delivery, "_post_json", post)
    monkeypatch.setattr(cloud_review_sync, "_now", lambda: now)
    auth: dict[str, object] = {"sync_url": "https://guard.example", **binding}
    _ = cloud_review_sync.sync_cloud_review_events_once(store, auth)
    expected = now if status == "accepted" else old
    state = store.get_sync_payload("guard_cloud_review_sync_state")
    assert isinstance(state, dict) and state["last_delivery_at"] == expected
    if status == "accepted":
        assert state["last_delivery_binding"] == {key: value for key, value in binding.items() if key != "oauth_source"}
    monkeypatch.setattr(cloud_review_sync, "_now", lambda: "2026-08-24T12:02:00+00:00")
    _ = cloud_review_sync.sync_cloud_review_events_once(store, auth)
    state = store.get_sync_payload("guard_cloud_review_sync_state")
    assert isinstance(state, dict) and state["last_delivery_at"] == expected
