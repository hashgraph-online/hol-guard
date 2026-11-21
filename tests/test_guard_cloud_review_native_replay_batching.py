from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest

from codex_plugin_scanner.guard.review_contracts import guard_review_oauth_metadata
from codex_plugin_scanner.guard.runtime import (
    cloud_review_event_delivery,
    cloud_review_event_projection,
    cloud_review_sync,
    native_workspace_review_replay,
    native_workspace_review_replay_delivery,
)
from tests.guard_exact_cloud_review_support import add_review_request, connected_exact_review_store, review_request


def test_replay_detection_uses_durable_discriminator() -> None:
    event = {
        "eventType": "review.request.snapshot_requeued",
        "eventPayloadJson": json.dumps({"eventType": "review.request.snapshot_requeued", "nativeReplay": False}),
    }
    assert not native_workspace_review_replay_delivery._event_is_replay(event)
    event["eventPayloadJson"] = json.dumps({"eventType": "review.request.snapshot_requeued", "nativeReplay": True})
    assert native_workspace_review_replay_delivery._event_is_replay(event)
    event["eventPayloadJson"] = json.dumps({"eventType": "review.request.snapshot_requeued"})
    assert native_workspace_review_replay_delivery._event_is_replay(event)


def test_probe_quota_defers_native_replay_without_retrying_batch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = connected_exact_review_store(tmp_path)
    binding = store.get_review_event_oauth_binding()
    assert binding is not None
    for index in range(3):
        add_review_request(store, review_request(f"batch-request-{index}"))
    marker_key = native_workspace_review_replay._marker_key(
        cast(native_workspace_review_replay._NativeWorkspaceReplayStore, cast(object, store)),
        "batch-request-2",
    )
    assert (
        store.requeue_pending_review_events_with_marker(
            changed_at="2026-08-26T12:00:01+00:00",
            marker_key=marker_key,
            marker_payload={
                "schema": "guard-cloud-review-native-workspace-review-request.v1",
                "request_id": "batch-request-2",
                "binding": dict(binding),
                "authority_generation": 3,
                "authority_record_digest": "a" * 64,
                "native_replay": True,
                "replay_attempts": 1,
            },
            require_binding=True,
            request_ids={"batch-request-2"},
        )
        == 1
    )

    probe_calls = 0

    native_context: dict[str, object] = {
        "authority_generation": 3,
        "authority_record_digest": "a" * 64,
        "action_binding": "c" * 64,
        "intent_binding": "d" * 64,
        "policy_binding": "e" * 64,
    }

    def probe_context(*_args: object) -> dict[str, object] | None:
        nonlocal probe_calls
        probe_calls += 1
        return native_context if probe_calls <= 2 else None

    monkeypatch.setattr(cloud_review_event_projection, "build_native_workspace_review_context", probe_context)
    monkeypatch.setattr(
        cloud_review_event_projection,
        "build_local_review_request_claim",
        lambda **_kwargs: {
            "nativeActionBinding": "c" * 64,
            "nativeIntentBinding": "d" * 64,
            "nativePolicyBinding": "e" * 64,
        },
    )
    posted_sequences: list[int] = []

    def accept_batch(
        _auth: dict[str, object],
        *,
        path: str,
        payload: dict[str, object],
    ) -> dict[str, object]:
        assert path == "/api/guard/review/v2/events:batch"
        events = payload["events"]
        assert isinstance(events, list)
        posted_sequences.extend(
            sequence
            for event in events
            if isinstance(event, dict)
            for sequence in [event.get("localStreamSequence")]
            if isinstance(sequence, int)
        )
        return {
            "protocolVersion": 2,
            "acknowledgedThrough": events[-1]["localStreamSequence"],
            "accepted": len(events),
            "rejected": 0,
            "results": [
                {"eventId": event["eventId"], "status": "accepted", "nativeContextCommitted": True}
                for event in events
                if isinstance(event, dict)
            ],
            "perEventResults": [{"index": index, "accepted": True} for index, _event in enumerate(events)],
        }

    monkeypatch.setattr(cloud_review_event_delivery, "_post_json", accept_batch)

    result = cloud_review_sync.sync_cloud_review_events_once(
        store,
        {"oauth_source": "default", "sync_url": "https://guard.example", **binding},
    )

    assert probe_calls == 2
    assert posted_sequences == [1, 2, 3]
    assert result["synced"] == 3
    assert result["batches"] == 1
    outbox = result["outbox"]
    assert isinstance(outbox, dict)
    assert outbox["ready_depth"] == 0
    assert outbox["depth"] == 1
    assert outbox["quarantined_depth"] == 0
    assert isinstance(outbox["next_attempt_at"], str)

    with store._connect() as connection:
        connection.execute(
            "update guard_review_outbox_events set next_attempt_at = null "
            "where event_type = 'review.request.snapshot_requeued'"
        )
    probe_calls = 0
    recovered = cloud_review_sync.sync_cloud_review_events_once(
        store,
        {"oauth_source": "default", "sync_url": "https://guard.example", **binding},
    )

    assert probe_calls == 1
    assert posted_sequences == [1, 2, 3, 4]
    assert recovered["synced"] == 1
    recovered_outbox = recovered["outbox"]
    assert isinstance(recovered_outbox, dict)
    assert recovered_outbox["depth"] == 0


def test_explicit_native_replay_reconstructs_marker_after_positive_attestation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = connected_exact_review_store(tmp_path)
    binding = store.get_review_event_oauth_binding()
    assert binding is not None
    request_id = "markerless-native-replay"
    add_review_request(store, review_request(request_id))
    marker_key = native_workspace_review_replay._marker_key(
        cast(native_workspace_review_replay._NativeWorkspaceReplayStore, cast(object, store)), request_id
    )
    assert (
        store.requeue_pending_review_events_with_marker(
            changed_at="2026-08-26T12:00:01+00:00",
            marker_key=marker_key,
            marker_payload={
                "schema": "guard-cloud-review-native-workspace-review-request.v1",
                "request_id": request_id,
                "binding": dict(binding),
                "authority_generation": 3,
                "authority_record_digest": "a" * 64,
                "native_replay": True,
                "replay_attempts": 1,
            },
            require_binding=True,
            request_ids={request_id},
        )
        == 1
    )
    with store._connect() as connection:
        row = connection.execute(
            "select * from guard_review_outbox_events where event_type = 'review.request.snapshot_requeued'"
        ).fetchone()
        connection.execute("delete from sync_state where state_key = ?", (marker_key,))
    assert row is not None
    outbox_row = dict(row)
    outbox_row["sequence"] = outbox_row["stream_sequence"]
    context = {
        "authority_generation": 3,
        "authority_record_digest": "a" * 64,
        "action_binding": "c" * 64,
        "intent_binding": "d" * 64,
        "policy_binding": "e" * 64,
    }
    monkeypatch.setattr(cloud_review_event_projection, "build_native_workspace_review_context", lambda *_args: context)
    monkeypatch.setattr(
        cloud_review_event_projection,
        "build_local_review_request_claim",
        lambda **_kwargs: {
            "nativeActionBinding": "c" * 64,
            "nativeIntentBinding": "d" * 64,
            "nativePolicyBinding": "e" * 64,
        },
    )
    projected = cloud_review_event_projection.project_cloud_review_event(
        store,
        outbox_row=outbox_row,
        delivery_binding={key: binding[key] for key in binding if key != "oauth_source"},
        redaction_level="none",
        oauth=guard_review_oauth_metadata(store),
    )
    assert projected is not None
    assert "nativeReplay" not in projected[1]
    assert json.loads(str(projected[1]["eventPayloadJson"]))["nativeReplay"] is True
    assert native_workspace_review_replay_delivery._mark_accepted_replay_contexts(
        store,
        [projected[1]],
        [{"accepted": True, "nativeContextCommitted": True}],
        {key: binding[key] for key in binding if key != "oauth_source"},
    )
    marker = store.get_sync_payload(marker_key)
    assert isinstance(marker, dict) and marker["accepted"] is True


def test_malformed_native_replay_marker_is_quarantined_before_upload(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = connected_exact_review_store(tmp_path)
    binding = store.get_review_event_oauth_binding()
    assert binding is not None
    request_id = "malformed-native-replay-marker"
    add_review_request(store, review_request(request_id))
    marker_key = native_workspace_review_replay._marker_key(
        cast(native_workspace_review_replay._NativeWorkspaceReplayStore, cast(object, store)), request_id
    )
    assert (
        store.requeue_pending_review_events_with_marker(
            changed_at="2026-08-26T12:00:01+00:00",
            marker_key=marker_key,
            marker_payload={
                "schema": "guard-cloud-review-native-workspace-review-request.v1",
                "request_id": request_id,
                "binding": dict(binding),
                "authority_generation": 3,
                "authority_record_digest": "invalid",
                "native_replay": True,
                "replay_attempts": 1,
            },
            require_binding=True,
            request_ids={request_id},
        )
        == 1
    )
    with store._connect() as connection:
        row = connection.execute(
            "select * from guard_review_outbox_events where event_type = 'review.request.snapshot_requeued'"
        ).fetchone()
    assert row is not None
    outbox_row = dict(row)
    outbox_row["sequence"] = outbox_row["stream_sequence"]
    monkeypatch.setattr(cloud_review_event_projection, "build_native_workspace_review_context", lambda *_args: None)
    projected = cloud_review_event_projection.project_cloud_review_event(
        store,
        outbox_row=outbox_row,
        delivery_binding={key: binding[key] for key in binding if key != "oauth_source"},
        redaction_level="none",
        oauth=guard_review_oauth_metadata(store),
    )
    assert projected is None
    with store._connect() as connection:
        state = connection.execute(
            "select binding_status, quarantine_reason from guard_review_outbox_events "
            "where event_type = 'review.request.snapshot_requeued'"
        ).fetchone()
    assert state is not None
    assert state["binding_status"] == "quarantined"
    assert state["quarantine_reason"] == "native_replay_marker_invalid"
