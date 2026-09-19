"""Regressions for telemetry decoding, permanent rejection and durable progress."""

from __future__ import annotations

import json
import sqlite3
import urllib.error
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import server
from codex_plugin_scanner.guard.edge_events import build_runtime_session_event
from codex_plugin_scanner.guard.runtime import runner
from tests.support.network import stub_authenticated_urlopen
from tests.test_policy_bundle_v2_runtime_admission import _SyncResponse
from tests.test_policy_telemetry_isolation import _AUTH, _connected_policy
from tests.test_policy_telemetry_transport import _add_signal


class _RawResponse:
    def __init__(self, body: bytes) -> None:
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return self.body


def _add_guard_event(store):
    event = build_runtime_session_event(
        session_id="session-telemetry-review",
        occurred_at="2026-07-15T12:00:00Z",
        payload={"sessionId": "session-telemetry-review", "harness": "codex", "status": "active"},
        device_id="device-alpha",
        workspace_id="workspace-alpha",
    )
    store.add_guard_event_v1(event)
    return event


@pytest.mark.parametrize("body", [b'{"secret-canary":', b'"\xff"', b"[]", b"null", b'"secret-canary"'])
def test_invalid_guard_event_response_is_recorded_without_aborting_applied_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, body: bytes
) -> None:
    upload = runner.sync_guard_events
    store, bundle, _requests = _connected_policy(tmp_path, monkeypatch)
    monkeypatch.setattr(runner, "sync_guard_events", upload)
    event = _add_guard_event(store)

    def transport(request, timeout):
        if request.full_url.endswith("/guard/events"):
            return _RawResponse(body)
        return _SyncResponse({"syncedAt": "2026-07-15T12:01:00Z", "receiptsStored": 0, "policyBundle": bundle})

    stub_authenticated_urlopen(monkeypatch, transport)

    summary = runner.sync_receipts(store, auth_context=_AUTH)

    assert summary["policy_application_status"] == "applied"
    assert summary["guard_events_upload_status"] == "degraded"
    assert summary["guard_events_upload_reason"] == "telemetry_invalid_response"
    assert summary["guard_events_v1"]["progress_known"] is True
    assert summary["guard_events_v1"]["pending_count"] == 1
    recorded = store.get_sync_payload("guard_events_v1_summary")
    assert recorded["status"] == "failed"
    assert "secret-canary" not in json.dumps(recorded)
    assert store.list_guard_events_v1(uploaded=False)[0]["event_id"] == event.event_id
    assert store.get_sync_payload("policy_bundle_ack")["status"] == "applied"


@pytest.mark.parametrize("lane", ["pain_signals", "guard_events"])
@pytest.mark.parametrize("status", [400, 413])
def test_permanent_telemetry_request_rejection_propagates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, lane: str, status: int
) -> None:
    upload = getattr(runner, f"sync_{lane}")
    original_response = runner._urlopen_json_with_timeout_retry
    store, _bundle, _requests = _connected_policy(tmp_path, monkeypatch)
    monkeypatch.setattr(runner, f"sync_{lane}", upload)
    _add_signal(store, 1)
    _add_guard_event(store)
    requests = []

    def transport(*, request, **kwargs):
        if request.full_url.endswith("/guard/receipts/sync"):
            return original_response(request=request, **kwargs)
        requests.append(request)
        raise urllib.error.HTTPError(request.full_url, status, "permanent rejection", {}, None)

    monkeypatch.setattr(runner, "_urlopen_with_timeout_retry", transport)
    monkeypatch.setattr(runner, "_urlopen_json_with_timeout_retry", transport)

    with pytest.raises(RuntimeError) as caught:
        runner.sync_receipts(store, auth_context=_AUTH)

    assert isinstance(caught.value.__cause__, urllib.error.HTTPError)
    assert caught.value.__cause__.code == status
    assert len(requests) == 1
    assert store.get_sync_payload("policy_bundle_ack")["status"] == "applied"


@pytest.mark.parametrize("error_class", [OSError, sqlite3.OperationalError])
def test_accepted_pain_page_cursor_failure_propagates_completed_count(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error_class: type[Exception]
) -> None:
    upload = runner.sync_pain_signals
    store, _bundle, _requests = _connected_policy(tmp_path, monkeypatch)
    monkeypatch.setattr(runner, "sync_pain_signals", upload)
    _add_signal(store, 1)
    accepted = []
    monkeypatch.setattr(runner, "_urlopen_with_timeout_retry", lambda **kwargs: accepted.append(kwargs["request"]))
    persist = store.set_sync_payload

    def failing_cursor(key, payload, synced_at):
        if key == "pain_signal_cursor":
            raise error_class("secret-canary disk is full")
        return persist(key, payload, synced_at)

    monkeypatch.setattr(store, "set_sync_payload", failing_cursor)

    with pytest.raises(RuntimeError, match="save telemetry upload progress") as caught:
        runner.sync_receipts(store, auth_context=_AUTH)

    assert caught.value.uploaded_count == 1
    assert "secret-canary" not in str(caught.value)
    assert len(accepted) == 1
    assert store.get_sync_payload("pain_signal_cursor") is None
    assert store.get_sync_payload("policy_bundle_ack")["status"] == "applied"


def test_headless_sync_persists_independent_telemetry_degradation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _bundle, _requests = _connected_policy(tmp_path, monkeypatch)

    def unavailable(_store, auth_context=None):
        raise OSError("telemetry transport unavailable")

    monkeypatch.setattr(runner, "sync_pain_signals", unavailable)
    monkeypatch.setattr(server, "_resolve_guard_sync_auth_context", lambda _store: _AUTH)
    monkeypatch.setattr(
        server,
        "_sync_local_guard_cloud_proof_with_optional_auth_context",
        lambda store, auth_context: runner.sync_receipts(store, auth_context=auth_context),
    )
    monkeypatch.setattr(
        server, "_sync_supply_chain_cloud_state_with_optional_auth_context", lambda *_args: {"status": "synced"}
    )

    summary = server._run_headless_cloud_sync(store=store)

    assert summary["status"] == "synced"
    core = store.get_sync_payload("sync_summary")
    persisted = store.get_sync_payload("headless_app_sync_summary")
    for key in (
        "telemetry_status",
        "pain_signals_uploaded",
        "pain_signals_upload_status",
        "pain_signals_upload_reason",
        "guard_events_v1",
        "guard_events_upload_status",
        "guard_events_upload_reason",
    ):
        assert summary[key] == core[key]
        assert persisted[key] == core[key]
    assert summary["telemetry_status"] == "degraded"
