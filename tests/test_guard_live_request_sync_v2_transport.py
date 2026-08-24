from __future__ import annotations

import urllib.error
from email.message import Message
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.runtime import live_request_sync
from codex_plugin_scanner.guard.runtime import live_request_sync_transport as transport
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
    return transport._post_sync_events(
        _AUTH,
        workspace_id="workspace-1",
        machine_id="machine-1",
        machine_installation_id="installation-1",
        cursor=None,
        events=events,
    )


def test_v2_upload_drains_real_immutable_outbox(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    store = connected_exact_review_store(tmp_path)
    binding = store.get_live_request_oauth_binding()
    assert binding is not None
    store.add_approval_request(
        GuardApprovalRequest(
            request_id="request-v2",
            harness="codex",
            artifact_id="codex:project:v2",
            artifact_name="Test action",
            artifact_hash="hash-v2",
            policy_action="require-reapproval",
            recommended_scope="artifact",
            changed_fields=("tool_action_request",),
            source_scope="project",
            config_path="/test/config.toml",
            review_command="hol-guard approvals approve request-v2",
            approval_url="http://127.0.0.1:5474/requests/request-v2",
            action_identity="request-v2",
            queue_group_id="request-v2",
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
        assert isinstance(correlation_id, str) and correlation_id.startswith("gcrv2_")
        return {
            "protocolVersion": 2,
            "acknowledgedThrough": event["localStreamSequence"],
            "accepted": 1,
            "rejected": 0,
            "results": [{"eventId": event["eventId"], "status": "accepted"}],
        }

    monkeypatch.setenv(transport.V2_EVENTS_FLAG, "1")
    monkeypatch.setenv(transport.LEGACY_EVENTS_FLAG, "0")
    monkeypatch.setattr(transport, "_post_json", accept_batch)

    result = live_request_sync.sync_live_requests_once(
        store,
        {"oauth_source": "default", "sync_url": "https://guard.example", **binding},
    )

    assert paths == ["/api/guard/review/v2/events:batch"]
    assert result["synced"] == 1
    outbox = result["outbox"]
    assert isinstance(outbox, dict) and outbox["depth"] == 0


def test_v2_upload_uses_frozen_batch_contract(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, object] = {}

    def post_json(
        auth: dict[str, object],
        *,
        path: str,
        payload: dict[str, object],
    ) -> dict[str, object]:
        captured.update({"auth": auth, "path": path, "payload": payload})
        return _response()

    monkeypatch.setenv(transport.V2_EVENTS_FLAG, "1")
    monkeypatch.setenv(transport.LEGACY_EVENTS_FLAG, "0")
    monkeypatch.setattr(transport, "_post_json", post_json)

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
def test_v2_duplicate_or_stale_result_is_idempotently_acknowledged(
    monkeypatch: pytest.MonkeyPatch,
    status: str,
) -> None:
    monkeypatch.setenv(transport.V2_EVENTS_FLAG, "1")
    monkeypatch.setenv(transport.LEGACY_EVENTS_FLAG, "0")
    monkeypatch.setattr(transport, "_post_json", lambda *_args, **_kwargs: _response(status=status))

    assert _post([_event()])["accepted"] == 1


def test_v2_rejection_remains_retryable_during_dual_write(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []

    def v2(*_args: object, **_kwargs: object) -> dict[str, object]:
        calls.append("v2")
        return {
            "accepted": 0,
            "rejected": 1,
            "perEventResults": [{"index": 0, "accepted": False, "code": "review_event_rejected", "error": "rejected"}],
        }

    def legacy(*_args: object, **_kwargs: object) -> dict[str, object]:
        calls.append("legacy")
        return {"accepted": 1, "rejected": 0, "perEventResults": [{"index": 0, "accepted": True}]}

    monkeypatch.setenv(transport.V2_EVENTS_FLAG, "1")
    monkeypatch.setenv(transport.LEGACY_EVENTS_FLAG, "1")
    monkeypatch.setattr(transport, "_post_v2_events", v2)
    monkeypatch.setattr(transport, "_post_legacy_events", legacy)

    result = _post([_event()])

    assert calls == ["v2", "legacy"]
    assert result["rejected"] == 1


def test_v2_transport_error_does_not_ack_through_legacy(monkeypatch: pytest.MonkeyPatch) -> None:
    legacy_called = False

    def failed_v2(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise OSError("offline")

    def legacy(*_args: object, **_kwargs: object) -> dict[str, object]:
        nonlocal legacy_called
        legacy_called = True
        return {"accepted": 1}

    monkeypatch.setenv(transport.V2_EVENTS_FLAG, "1")
    monkeypatch.setenv(transport.LEGACY_EVENTS_FLAG, "1")
    monkeypatch.setattr(transport, "_post_v2_events", failed_v2)
    monkeypatch.setattr(transport, "_post_legacy_events", legacy)

    with pytest.raises(OSError, match="offline"):
        _post([_event()])
    assert legacy_called is False


def test_missing_v2_route_rolls_back_to_legacy_when_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    def missing(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise urllib.error.HTTPError("https://guard.example", 404, "missing", Message(), None)

    def legacy(*_args: object, **_kwargs: object) -> dict[str, object]:
        return {"accepted": 1, "rejected": 0}

    monkeypatch.setenv(transport.V2_EVENTS_FLAG, "1")
    monkeypatch.setenv(transport.LEGACY_EVENTS_FLAG, "1")
    monkeypatch.setattr(transport, "_post_v2_events", missing)
    monkeypatch.setattr(transport, "_post_legacy_events", legacy)

    assert _post([_event()])["accepted"] == 1


def test_protocol_upgrade_response_never_silently_falls_back(monkeypatch: pytest.MonkeyPatch) -> None:
    def upgrade_required(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise urllib.error.HTTPError("https://guard.example", 426, "upgrade", Message(), None)

    monkeypatch.setenv(transport.V2_EVENTS_FLAG, "1")
    monkeypatch.setenv(transport.LEGACY_EVENTS_FLAG, "1")
    monkeypatch.setattr(transport, "_post_v2_events", upgrade_required)
    monkeypatch.setattr(
        transport,
        "_post_legacy_events",
        lambda *_args, **_kwargs: pytest.fail("unsupported protocol must not fall back"),
    )

    with pytest.raises(transport.LiveRequestSyncProtocolError, match="Update HOL Guard"):
        _post([_event()])


def test_default_flags_keep_legacy_authoritative(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(transport.V2_EVENTS_FLAG, raising=False)
    monkeypatch.delenv(transport.LEGACY_EVENTS_FLAG, raising=False)
    monkeypatch.setattr(
        transport,
        "_post_v2_events",
        lambda *_args, **_kwargs: pytest.fail("v2 must be explicitly enabled"),
    )
    monkeypatch.setattr(
        transport,
        "_post_legacy_events",
        lambda *_args, **_kwargs: {"accepted": 1, "rejected": 0},
    )

    assert _post([_event()])["accepted"] == 1


@pytest.mark.parametrize("version", [None, 1, "2", 3])
def test_v2_rejects_unsupported_protocol_with_upgrade_guidance(
    monkeypatch: pytest.MonkeyPatch,
    version: object,
) -> None:
    monkeypatch.setenv(transport.V2_EVENTS_FLAG, "1")
    monkeypatch.setenv(transport.LEGACY_EVENTS_FLAG, "0")
    monkeypatch.setattr(transport, "_post_json", lambda *_args, **_kwargs: _response(version=version))

    with pytest.raises(transport.LiveRequestSyncProtocolError, match="Update HOL Guard"):
        _post([_event()])
