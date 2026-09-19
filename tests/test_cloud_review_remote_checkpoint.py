"""Durable remote acknowledgements remain useful after a lost response."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import cloud_review_event_delivery as delivery
from codex_plugin_scanner.guard.runtime import cloud_review_sync
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_review_remote_checkpoint import apply_review_remote_checkpoint
from tests.guard_exact_cloud_review_support import add_review_request, connected_exact_review_store, review_request


def test_lost_response_settles_confirmed_event_without_claiming_new_delivery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = connected_exact_review_store(tmp_path)
    add_review_request(store, review_request("lost-response"))
    binding = store.get_review_event_oauth_binding()
    assert binding is not None
    auth = {"sync_url": "https://guard.example", **binding}

    def post(_auth: dict[str, object], *, path: str, payload: dict[str, object]) -> dict[str, object]:
        del path
        events = payload["events"]
        assert isinstance(events, list) and len(events) == 1
        event = events[0]
        return {
            "protocolVersion": 2,
            "acknowledgedThrough": event["localStreamSequence"],
            "accepted": 0,
            "rejected": 1,
            "results": [{"eventId": event["eventId"], "status": "rejected", "code": "review_event_sequence_conflict"}],
        }

    monkeypatch.setattr(delivery, "_post_json", post)
    result = cloud_review_sync.sync_cloud_review_events_once(store, auth)
    assert result["synced"] == 0
    assert result["outbox"]["depth"] == 0
    assert result["errors"] == []
    with store._connect() as connection:
        row = connection.execute("select acknowledged_stream_sequence from guard_review_outbox_cursors").fetchone()
    assert row["acknowledged_stream_sequence"] == 1


@pytest.mark.parametrize("checkpoint", [None, -1, True, 1.5, "1", 100])
def test_invalid_remote_checkpoint_cannot_remove_local_events(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, checkpoint: object
) -> None:
    store = connected_exact_review_store(tmp_path)
    add_review_request(store, review_request("preserve-local"))
    binding = store.get_review_event_oauth_binding()
    assert binding is not None

    def post(_auth: dict[str, object], *, path: str, payload: dict[str, object]) -> dict[str, object]:
        del path
        event = payload["events"][0]
        return {
            "protocolVersion": 2,
            "acknowledgedThrough": checkpoint,
            "accepted": 0,
            "rejected": 1,
            "results": [{"eventId": event["eventId"], "status": "rejected", "code": "temporary_failure"}],
        }

    monkeypatch.setattr(delivery, "_post_json", post)
    with pytest.raises(delivery.CloudReviewEventProtocolError, match=r"acknowledgement|checkpoint"):
        cloud_review_sync.sync_cloud_review_events_once(store, {"sync_url": "https://guard.example", **binding})
    rows = store.list_ready_review_events(now="2099-01-01T00:00:00Z", limit=10)
    assert [row["local_request_id"] for row in rows] == ["preserve-local"]


def test_checkpoint_survives_reopen_and_refuses_regression(tmp_path: Path) -> None:
    store = connected_exact_review_store(tmp_path)
    add_review_request(store, review_request("confirmed"))
    identity = store.get_review_event_oauth_binding()
    assert identity is not None
    binding = {key: value for key, value in identity.items() if key != "oauth_source"}
    assert apply_review_remote_checkpoint(store, acknowledged_through=1, binding=binding) == 1
    reopened = GuardStore(store.guard_home)
    add_review_request(reopened, review_request("still-local"))
    with pytest.raises(delivery.CloudReviewEventProtocolError, match="stream bounds"):
        apply_review_remote_checkpoint(reopened, acknowledged_through=0, binding=binding)
    assert [
        row["local_request_id"] for row in reopened.list_ready_review_events(now="2099-01-01T00:00:00Z", limit=10)
    ] == ["still-local"]
    assert apply_review_remote_checkpoint(reopened, acknowledged_through=1, binding=binding) == 1


@pytest.mark.parametrize("field", ["oauth_subject_hash", "workspace_id", "machine_id", "machine_installation_id"])
def test_checkpoint_cannot_cross_identity(tmp_path: Path, field: str) -> None:
    store = connected_exact_review_store(tmp_path)
    add_review_request(store, review_request("private-binding"))
    identity = store.get_review_event_oauth_binding()
    assert identity is not None
    binding = {key: value for key, value in identity.items() if key != "oauth_source"}
    binding[field] = "different-identity"
    with pytest.raises(delivery.CloudReviewEventProtocolError, match="identity changed"):
        apply_review_remote_checkpoint(store, acknowledged_through=1, binding=binding)
    assert len(store.list_ready_review_events(now="2099-01-01T00:00:00Z", limit=10)) == 1


def test_checkpoint_preserves_quarantined_evidence(tmp_path: Path) -> None:
    store = connected_exact_review_store(tmp_path)
    add_review_request(store, review_request("quarantined"))
    add_review_request(store, review_request("confirmed"))
    identity = store.get_review_event_oauth_binding()
    assert identity is not None
    binding = {key: value for key, value in identity.items() if key != "oauth_source"}
    store.quarantine_review_event(1, reason="fixture-quarantine", error="fixture", **binding)
    assert apply_review_remote_checkpoint(store, acknowledged_through=2, binding=binding) == 2
    with store._connect() as connection:
        rows = connection.execute("select local_request_id, binding_status from guard_review_outbox_events").fetchall()
    assert [(row["local_request_id"], row["binding_status"]) for row in rows] == [("quarantined", "quarantined")]
