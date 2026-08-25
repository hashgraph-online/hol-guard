from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.runtime import cloud_review_event_delivery as delivery
from codex_plugin_scanner.guard.runtime import cloud_review_sync
from tests.guard_exact_cloud_review_support import connected_exact_review_store

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
