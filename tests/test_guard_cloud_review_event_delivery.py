from __future__ import annotations

from pathlib import Path
from typing import cast
from unittest.mock import Mock

import pytest

from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.runtime import cloud_review_event_delivery as delivery
from codex_plugin_scanner.guard.runtime import cloud_review_sync
from codex_plugin_scanner.guard.runtime.cloud_review_retry_recovery import recover_rejected_review_events
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_exact_cloud_review_support import add_review_request, connected_exact_review_store, review_request

_AUTH: dict[str, object] = {"sync_url": "https://guard.example/api/guard/receipts/sync"}


def _event(sequence: int = 41, event_id: str = "event-41") -> dict[str, object]:
    return {"eventId": event_id, "localStreamSequence": sequence}


def _response(*, status: str = "accepted", version: object = 2) -> dict[str, object]:
    accepted = status in {"accepted", "duplicate", "stale"}
    return {
        "protocolVersion": version,
        "acknowledgedThrough": 41 if accepted else 40,
        "accepted": 1 if accepted else 0,
        "rejected": 0 if accepted else 1,
        "results": [{"eventId": "event-41", "status": status, "code": "review_event_rejected"}],
    }


def _post(events: list[dict[str, object]]) -> dict[str, object]:
    return delivery.post_review_events(
        _AUTH,
        events=events,
    )


def test_canonical_upload_drains_real_immutable_outbox(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    store = connected_exact_review_store(tmp_path)
    binding = store.get_review_event_oauth_binding()
    assert binding is not None
    store.add_approval_request(
        GuardApprovalRequest(
            request_id="request-canonical",
            harness="codex",
            artifact_id="codex:project:canonical",
            artifact_name="Test action",
            artifact_hash="hash-canonical",
            policy_action="require-reapproval",
            recommended_scope="artifact",
            changed_fields=("tool_action_request",),
            source_scope="project",
            config_path="/test/config.toml",
            review_command="hol-guard approvals approve request-canonical",
            approval_url="http://127.0.0.1:5474/requests/request-canonical",
            action_identity="request-canonical",
            queue_group_id="request-canonical",
            trigger_summary="Review action",
            last_seen_at="2026-08-24T14:00:00+00:00",
        ),
        "2026-08-24T14:00:00+00:00",
    )
    paths: list[str] = []

    def accept_batch(
        _auth: dict[str, object],
        *,
        path: str,
        payload: dict[str, object],
    ) -> dict[str, object]:
        paths.append(path)
        events = payload["events"]
        assert isinstance(events, list) and len(events) == 1
        event = events[0]
        assert isinstance(event, dict)
        claim = event["reviewClaim"]
        assert isinstance(claim, dict)
        correlation_id = claim["correlationId"]
        assert isinstance(correlation_id, str) and correlation_id.startswith("gcr_")
        return {
            "protocolVersion": 2,
            "acknowledgedThrough": event["localStreamSequence"],
            "accepted": 1,
            "rejected": 0,
            "results": [{"eventId": event["eventId"], "status": "accepted"}],
        }

    monkeypatch.setattr(delivery, "_post_json", accept_batch)

    result = cloud_review_sync.sync_cloud_review_events_once(
        store,
        {"oauth_source": "default", "sync_url": "https://guard.example", **binding},
    )

    assert paths == ["/api/guard/review/v2/events:batch"]
    assert result["synced"] == 1
    outbox = result["outbox"]
    assert isinstance(outbox, dict) and outbox["depth"] == 0


def test_canonical_upload_uses_frozen_batch_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def post_json(
        auth: dict[str, object],
        *,
        path: str,
        payload: dict[str, object],
    ) -> dict[str, object]:
        captured.update({"auth": auth, "path": path, "payload": payload})
        return _response()

    monkeypatch.setattr(delivery, "_post_json", post_json)

    result = _post([_event()])

    assert captured == {
        "auth": _AUTH,
        "path": "/api/guard/review/v2/events:batch",
        "payload": {
            "protocolVersion": 2,
            "firstSequence": 41,
            "lastSequence": 41,
            "events": [_event()],
        },
    }
    assert result["perEventResults"] == [{"index": 0, "accepted": True, "code": "review_event_rejected", "error": None}]


def test_snapshot_collision_recovers_then_uploads_without_changing_event_or_decision(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    store = connected_exact_review_store(tmp_path)
    binding = store.get_review_event_oauth_binding()
    assert binding is not None
    add_review_request(store, review_request("collision-recovery"))
    delivery_binding = {
        key: binding[key] for key in ("oauth_subject_hash", "workspace_id", "machine_id", "machine_installation_id")
    }
    store.acknowledge_review_events([1], **delivery_binding)
    assert store.requeue_pending_review_events(changed_at="2026-10-01T12:00:00+00:00", require_binding=True) == 1
    captured: list[dict[str, object]] = []

    def respond(_auth: dict[str, object], *, path: str, payload: dict[str, object]) -> dict[str, object]:
        assert path.endswith("events:batch")
        events = payload["events"]
        assert isinstance(events, list) and len(events) == 1
        event = events[0]
        assert isinstance(event, dict)
        captured.append(dict(event))
        collision = len(captured) == 1
        assert store.review_event_outbox_status(now="2026-10-01T12:00:01+00:00")["depth"] == 1
        return {
            "protocolVersion": 2,
            "acknowledgedThrough": 529 if collision else event["localStreamSequence"],
            "accepted": 0 if collision else 1,
            "rejected": 1 if collision else 0,
            "results": [
                {
                    "eventId": event["eventId"],
                    "status": "rejected" if collision else "accepted",
                    **({"code": "review_event_snapshot_sequence_collision"} if collision else {}),
                }
            ],
        }

    monkeypatch.setattr(delivery, "_post_json", respond)
    auth: dict[str, object] = {"oauth_source": "default", "sync_url": "https://guard.example", **binding}
    first = cloud_review_sync.sync_cloud_review_events_once(store, auth)
    assert first["synced"] == 1
    second = cloud_review_sync.sync_cloud_review_events_once(store, auth)
    assert second["synced"] == 0
    assert len(captured) == 2
    assert [event["localStreamSequence"] for event in captured] == [2, 530]
    for key in ("eventId", "eventPayloadJson", "payloadHash", "localRequestId", "localEventSequence"):
        assert captured[0][key] == captured[1][key]
    assert store.review_event_outbox_status(now="2026-10-01T12:00:01+00:00")["depth"] == 0
    request = store.get_approval_request("collision-recovery")
    assert isinstance(request, dict) and request["status"] == "pending"


def test_canonical_transport_rejects_invalid_advertised_batch_limits(monkeypatch: pytest.MonkeyPatch) -> None:
    for invalid_limit in (0, -1, True, "250"):
        response = {**_response(), "maxBatchEvents": invalid_limit}
        monkeypatch.setattr(delivery, "_post_json", lambda *_args, response=response, **_kwargs: response)
        with pytest.raises(delivery.CloudReviewEventProtocolError, match="invalid batch limit"):
            _post([_event()])


@pytest.mark.parametrize("high_water", [-1, True, 2**53, "529"])
def test_canonical_transport_rejects_invalid_high_water(monkeypatch: pytest.MonkeyPatch, high_water: object) -> None:
    response = {**_response(status="rejected"), "acknowledgedThrough": high_water}
    monkeypatch.setattr(delivery, "_post_json", lambda *_args, **_kwargs: response)
    with pytest.raises(delivery.CloudReviewEventProtocolError, match="invalid protocol 2 acknowledgement"):
        _post([_event()])


def test_canonical_transport_accepts_zero_for_an_all_rejected_batch(monkeypatch: pytest.MonkeyPatch) -> None:
    response = {**_response(status="rejected"), "acknowledgedThrough": 0}
    monkeypatch.setattr(delivery, "_post_json", lambda *_args, **_kwargs: response)

    normalized = _post([_event()])

    assert normalized["acknowledgedThrough"] == 0
    assert normalized["accepted"] == 0
    assert normalized["rejected"] == 1


@pytest.mark.parametrize("code", ["review_event_snapshot_sequence_collision", "review_event_sequence_conflict"])
def test_collision_result_retains_verified_event_identity_only_for_recoverable_code(
    monkeypatch: pytest.MonkeyPatch, code: str
) -> None:
    response = {
        **_response(status="rejected"),
        "acknowledgedThrough": 529,
        "results": [{"eventId": "event-41", "status": "rejected", "code": code}],
    }
    monkeypatch.setattr(delivery, "_post_json", lambda *_args, **_kwargs: response)
    normalized = _post([_event()])["perEventResults"]
    assert isinstance(normalized, list)
    assert normalized[0].get("eventId") == ("event-41" if code.endswith("snapshot_sequence_collision") else None)


@pytest.mark.parametrize(
    ("code", "event_id", "high_water", "repaired"),
    [
        ("review_event_snapshot_sequence_collision", "event-41", 529, True),
        ("review_event_sequence_conflict", "event-41", 529, False),
        ("review_event_snapshot_sequence_collision", "different-event", 529, False),
        ("review_event_snapshot_sequence_collision", "event-41", True, False),
    ],
)
def test_recovery_requires_typed_collision_and_exact_sent_identity(
    code: str, event_id: str, high_water: object, repaired: bool
) -> None:
    recovery = Mock(return_value={41: 530})

    class Store:
        recover_review_snapshot_sequences = recovery

    result: dict[str, object] = {"code": code, "eventId": event_id}
    binding = {"workspace_id": "workspace-1"}
    sequences, results = recover_rejected_review_events(
        cast(GuardStore, cast(object, Store())),
        sequences=[41],
        results=[result],
        events={41: _event()},
        binding=binding,
        acknowledged_through=high_water,
    )
    if repaired:
        recovery.assert_called_once_with(collisions={41: "event-41"}, acknowledged_through=529, binding=binding)
        assert (sequences, results) == ([], [])
    else:
        recovery.assert_not_called()
        assert (sequences, results) == ([41], [result])


@pytest.mark.parametrize("status", ["duplicate", "stale"])
def test_duplicate_or_stale_result_is_idempotently_acknowledged(
    monkeypatch: pytest.MonkeyPatch,
    status: str,
) -> None:
    monkeypatch.setattr(delivery, "_post_json", lambda *_args, **_kwargs: _response(status=status))

    assert _post([_event()])["accepted"] == 1


@pytest.mark.parametrize("version", [None, 1, "2", 3])
def test_canonical_transport_rejects_unsupported_protocol_with_upgrade_guidance(
    monkeypatch: pytest.MonkeyPatch,
    version: object,
) -> None:
    monkeypatch.setattr(delivery, "_post_json", lambda *_args, **_kwargs: _response(version=version))

    with pytest.raises(delivery.CloudReviewEventProtocolError, match="Update HOL Guard"):
        _post([_event()])
