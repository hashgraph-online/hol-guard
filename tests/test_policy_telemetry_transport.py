"""Real telemetry pagination retains cursors and successful-page counts."""

from __future__ import annotations

import urllib.error
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.edge_events import build_runtime_session_event
from codex_plugin_scanner.guard.runtime import runner
from tests.support.native_policy_application import native_policy_consumer as native_policy_consumer
from tests.test_policy_telemetry_isolation import _AUTH, _connected_policy

pytestmark = pytest.mark.usefixtures("native_policy_consumer")


def _add_signal(store, index: int) -> None:
    store.add_event(
        "changed_artifact_caught",
        {
            "harness": "codex",
            "artifact_id": f"codex:project:changed-{index}",
            "artifact_name": "changed",
            "policy_action": "block",
            "changed_fields": ["command"],
        },
        "2026-07-15T12:00:00Z",
    )


@pytest.mark.parametrize(
    "status,reason",
    [(404, "telemetry_endpoint_unavailable"), (429, "telemetry_rate_limited"), (500, "telemetry_service_error")],
)
def test_real_pain_transport_failure_keeps_cursor_until_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, status: int, reason: str
) -> None:
    upload = runner.sync_pain_signals
    store, _bundle, _requests = _connected_policy(tmp_path, monkeypatch, optional_uploads=True)
    monkeypatch.setattr(runner, "sync_pain_signals", upload)
    _add_signal(store, 1)
    failed = True
    uploads: list[bytes] = []

    def transport(*, request, **_kwargs):
        uploads.append(request.data)
        if failed:
            raise urllib.error.HTTPError(request.full_url, status, "telemetry unavailable", {}, None)

    monkeypatch.setattr(runner, "_urlopen_with_timeout_retry", transport)

    first = runner.sync_receipts(store, auth_context=_AUTH)

    assert first["policy_application_status"] == "applied"
    assert first["pain_signals_upload_status"] == "degraded"
    assert first["pain_signals_upload_reason"] == reason
    assert first["pain_signals_uploaded"] == 0
    assert store.get_sync_payload("pain_signal_cursor") is None
    failed = False

    retried = runner.sync_receipts(store, auth_context=_AUTH)

    assert retried["pain_signals_uploaded"] == 1
    assert retried["pain_signals_upload_status"] == "success"
    assert store.get_sync_payload("pain_signal_cursor")["event_id"] > 0
    assert uploads[0] == uploads[1]


def test_later_page_failure_reports_completed_page_and_retries_only_pending_page(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    upload = runner.sync_pain_signals
    store, _bundle, _requests = _connected_policy(tmp_path, monkeypatch, optional_uploads=True)
    monkeypatch.setattr(runner, "sync_pain_signals", upload)
    for index in range(501):
        _add_signal(store, index)
    completed: list[bytes] = []
    failed = True

    def transport(*, request, **_kwargs):
        if len(completed) == 1 and failed:
            raise OSError("connection reset after first page")
        completed.append(request.data)

    monkeypatch.setattr(runner, "_urlopen_with_timeout_retry", transport)

    first = runner.sync_receipts(store, auth_context=_AUTH)

    assert first["pain_signals_uploaded"] == 500
    assert first["pain_signals_upload_status"] == "degraded"
    cursor = store.get_sync_payload("pain_signal_cursor")["event_id"]
    failed = False

    retried = runner.sync_receipts(store, auth_context=_AUTH)

    assert retried["pain_signals_uploaded"] == 1
    assert retried["pain_signals_upload_status"] == "success"
    assert store.get_sync_payload("pain_signal_cursor")["event_id"] > cursor
    assert len(completed) == 2


def test_real_guard_event_failure_records_current_progress_and_retries_pending_event(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    upload = runner.sync_guard_events
    transport = runner._urlopen_json_with_timeout_retry
    store, _bundle, _requests = _connected_policy(tmp_path, monkeypatch, optional_uploads=True)
    monkeypatch.setattr(runner, "sync_guard_events", upload)
    event = build_runtime_session_event(
        session_id="session-telemetry-test",
        occurred_at="2026-07-15T12:00:00Z",
        payload={"sessionId": "session-telemetry-test", "harness": "codex", "status": "active"},
        device_id="device-alpha",
        workspace_id="workspace-alpha",
    )
    store.add_guard_event_v1(event)
    failed = True

    def response(*, request, **kwargs):
        if request.full_url.endswith("/guard/events"):
            if failed:
                raise urllib.error.HTTPError(request.full_url, 500, "service unavailable", {}, None)
            return {
                "syncedAt": "2026-07-15T12:01:00Z",
                "statuses": [{"eventId": event.event_id, "status": "accepted"}],
            }
        return transport(request=request, **kwargs)

    monkeypatch.setattr(runner, "_urlopen_json_with_timeout_retry", response)

    first = runner.sync_receipts(store, auth_context=_AUTH)

    assert first["policy_application_status"] == "applied"
    assert first["guard_events_upload_status"] == "degraded"
    assert first["guard_events_upload_reason"] == "telemetry_service_error"
    assert first["guard_events_v1"]["progress_known"] is True
    assert first["guard_events_v1"]["accepted"] == 0
    assert first["guard_events_v1"]["pending_count"] == 1
    assert len(store.list_guard_events_v1(uploaded=False)) == 1
    failed = False

    retried = runner.sync_receipts(store, auth_context=_AUTH)

    assert retried["guard_events_upload_status"] == "success"
    assert retried["guard_events_v1"]["accepted"] == 1
    assert store.list_guard_events_v1(uploaded=False) == []
