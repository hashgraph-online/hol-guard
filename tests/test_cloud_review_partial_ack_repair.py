"""HGP-171: partial acknowledgement and snapshot repair keep sequence identity."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import cloud_review_event_delivery as delivery
from codex_plugin_scanner.guard.runtime import cloud_review_sync
from tests.guard_exact_cloud_review_support import add_review_request, connected_exact_review_store, review_request


def test_mixed_accept_reject_keeps_failed_retryable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = connected_exact_review_store(tmp_path)
    add_review_request(store, review_request("keep-accepted"))
    add_review_request(store, review_request("retry-rejected"))
    binding = store.get_review_event_oauth_binding()
    assert binding is not None
    auth = {"sync_url": "https://guard.example", **binding}

    def post(_auth: dict[str, object], *, path: str, payload: dict[str, object]) -> dict[str, object]:
        del path
        events = payload["events"]
        assert isinstance(events, list)
        results = []
        for index, event in enumerate(events):
            accepted = index == 0
            results.append(
                {
                    "eventId": event["eventId"],
                    "status": "accepted" if accepted else "rejected",
                    "code": None if accepted else "temporary_failure",
                }
            )
        return {
            "protocolVersion": 2,
            "acknowledgedThrough": events[0]["localStreamSequence"],
            "accepted": 1,
            "rejected": len(events) - 1,
            "results": results,
        }

    monkeypatch.setattr(delivery, "_post_json", post)
    cloud_review_sync.sync_cloud_review_events_once(store, auth)
    now = "2099-01-01T00:00:00+00:00"
    remaining = store.list_ready_review_events(
        now=now,
        limit=20,
        workspace_id=binding["workspace_id"],
        oauth_subject_hash=binding["oauth_subject_hash"],
        machine_id=binding["machine_id"],
        machine_installation_id=binding["machine_installation_id"],
    )
    assert [row["local_request_id"] for row in remaining] == ["retry-rejected"]


def test_wrong_result_count_does_not_ack_batch(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = connected_exact_review_store(tmp_path)
    add_review_request(store, review_request("count-mismatch"))
    binding = store.get_review_event_oauth_binding()
    assert binding is not None
    auth = {"sync_url": "https://guard.example", **binding}

    def post(_auth: dict[str, object], *, path: str, payload: dict[str, object]) -> dict[str, object]:
        del path, payload
        return {
            "protocolVersion": 2,
            "acknowledgedThrough": 0,
            "accepted": 1,
            "rejected": 0,
            "results": [],
        }

    monkeypatch.setattr(delivery, "_post_json", post)
    with pytest.raises(delivery.CloudReviewEventProtocolError, match="invalid protocol 2 acknowledgement"):
        cloud_review_sync.sync_cloud_review_events_once(store, auth)
    remaining = store.list_ready_review_events(
        now="2099-01-01T00:00:00+00:00",
        limit=20,
        workspace_id=binding["workspace_id"],
        oauth_subject_hash=binding["oauth_subject_hash"],
        machine_id=binding["machine_id"],
        machine_installation_id=binding["machine_installation_id"],
    )
    assert [row["local_request_id"] for row in remaining] == ["count-mismatch"]


@pytest.mark.parametrize("field,value", [("accepted", True), ("accepted", 1.0), ("rejected", False), ("rejected", 0.0)])
def test_non_integer_result_counts_do_not_ack_batch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str, value: object
) -> None:
    store = connected_exact_review_store(tmp_path)
    add_review_request(store, review_request("malformed-count"))
    binding = store.get_review_event_oauth_binding()
    assert binding is not None

    def post(_auth: dict[str, object], *, path: str, payload: dict[str, object]) -> dict[str, object]:
        del path
        event = payload["events"][0]
        response = {
            "protocolVersion": 2,
            "acknowledgedThrough": event["localStreamSequence"],
            "accepted": 1,
            "rejected": 0,
            "results": [{"eventId": event["eventId"], "status": "accepted", "code": None}],
        }
        response[field] = value
        return response

    monkeypatch.setattr(delivery, "_post_json", post)
    with pytest.raises(delivery.CloudReviewEventProtocolError, match="counts are inconsistent"):
        cloud_review_sync.sync_cloud_review_events_once(store, {"sync_url": "https://guard.example", **binding})
    remaining = store.list_ready_review_events(now="2099-01-01T00:00:00Z", limit=10)
    assert [row["local_request_id"] for row in remaining] == ["malformed-count"]
