from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import cloud_review_event_delivery as delivery
from codex_plugin_scanner.guard.runtime import cloud_review_sync
from tests.guard_exact_cloud_review_support import add_review_request, connected_exact_review_store, review_request


@pytest.mark.parametrize("repaired_server", [True, False])
def test_source_gap_recovery_is_automatic_bounded_and_preserves_event_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, repaired_server: bool
) -> None:
    store = connected_exact_review_store(tmp_path)
    add_review_request(store, review_request("gap-request"))
    binding = store.get_review_event_oauth_binding()
    assert binding is not None
    auth = {"sync_url": "https://guard.example", **binding}
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
                snapshot_seen = True
                status = "accepted"
            elif snapshot_seen and repaired_server:
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
    original_id = deliveries[0][0]
    with store._connect() as connection:
        connection.execute("update guard_review_outbox_events set next_attempt_at = null where acknowledged_at is null")
    result = cloud_review_sync.sync_cloud_review_events_once(store, auth)
    assert sum(kind == "review.request.snapshot_requeued" for _, kind in deliveries) == 1
    assert deliveries[-1][0] == original_id
    status = store.get_sync_payload("guard_cloud_review_sync_state")
    assert isinstance(status, dict)
    assert status["state"] == ("idle" if repaired_server else "error")
    assert result["outbox"]["depth"] == (0 if repaired_server else 1)


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
