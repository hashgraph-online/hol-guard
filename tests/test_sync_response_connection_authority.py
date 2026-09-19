"""Actual response commits cannot outlive the connection that sent the request."""

from __future__ import annotations

import socket
import urllib.error
from email.message import Message
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.edge_events import build_runtime_session_event
from codex_plugin_scanner.guard.runtime import runner
from codex_plugin_scanner.guard.runtime.sync_auth_handoff import hold_sync_auth_handoff
from codex_plugin_scanner.guard.runtime.sync_response import InvalidSyncResponseError
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_native_policy_bundle_ack import accepted as accepted
from tests.test_receipt_runner_preference_integration import _ordinary_auth, _ready, _settings

NOW = "2026-06-01T00:00:00+00:00"
MARKER = {"source": "newer-connection"}


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def denied(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Response authority regressions must not open network sockets")

    monkeypatch.setattr(socket.socket, "connect", denied)
    monkeypatch.setattr(socket.socket, "connect_ex", denied)
    monkeypatch.setattr(runner, "_guard_runtime_was_upgraded", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(runner, "_safe_private_ip", lambda: None)


@pytest.mark.parametrize("change", ["replacement", "disconnect", "same-values", "unchanged"])
@pytest.mark.parametrize("persist", [False, True])
def test_receipt_response_refuses_stale_control_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str, persist: bool
) -> None:
    store, inputs = _ready(tmp_path)
    peer = GuardStore(store.guard_home, allow_system_keyring=False)
    connection = store.capture_oauth_connection()
    assert connection is not None
    context = _ordinary_auth(store)
    keys = ("alert_preferences", "policy_bundle_last_error", "sync_summary", "aibom_inventory_context")
    events_before = peer.list_events(limit=100)

    def response(*, request, prepare_request, **_kwargs):
        prepare_request(request)
        if change == "replacement":
            replacement = inputs.copy()
            replacement["workspace_id"] = "newer-team"
            peer.set_oauth_local_credentials(**replacement)
        elif change == "disconnect":
            peer.clear_oauth_local_credentials()
        elif change == "same-values":
            peer.set_oauth_local_credentials(**inputs)
        if change != "unchanged":
            for key in keys:
                peer.set_sync_payload(key, MARKER, NOW)
        return {"syncedAt": NOW, "alertPreferences": {"source": "old-response"}, "policyBundle": []}

    monkeypatch.setattr(runner, "_urlopen_json_with_timeout_retry", response)
    with hold_sync_auth_handoff(store, context, connection):
        if change == "unchanged":
            result = runner.sync_receipts(
                store,
                auth_context=context,
                persist_sync_summary=persist,
                persist_connect_state=persist,
                home_dir=store.guard_home,
            )
            assert result["synced_at"] == NOW
            assert peer.get_sync_payload("alert_preferences") == {"source": "old-response"}
        else:
            with pytest.raises(RuntimeError, match="connection changed"):
                runner.sync_receipts(
                    store,
                    auth_context=context,
                    persist_sync_summary=persist,
                    persist_connect_state=persist,
                    home_dir=store.guard_home,
                )
            assert all(peer.get_sync_payload(key) == MARKER for key in keys)
            assert peer.list_events(limit=100) == events_before


@pytest.mark.parametrize("status", [404, 429, 403, 500, "transport", "invalid"])
@pytest.mark.parametrize("change", ["replacement", "disconnect", "unchanged"])
def test_event_error_response_cannot_replace_newer_summary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, status: int | str, change: str
) -> None:
    store, inputs = _ready(tmp_path, telemetry=True)
    _settings(store, telemetry=True)
    peer = GuardStore(store.guard_home, allow_system_keyring=False)
    connection = store.capture_oauth_connection()
    assert connection is not None
    context = _ordinary_auth(store)
    event = build_runtime_session_event(
        session_id="synthetic-session",
        occurred_at=NOW,
        payload={"sessionId": "synthetic-session", "harness": "codex", "status": "active"},
        device_id="synthetic-device",
        workspace_id=str(inputs["workspace_id"]),
    )
    store.add_guard_event_v1(event)

    def response(*, request, prepare_request, **_kwargs):
        prepare_request(request)
        if change == "replacement":
            replacement = inputs.copy()
            replacement["workspace_id"] = "newer-team"
            peer.set_oauth_local_credentials(**replacement)
        elif change == "disconnect":
            peer.clear_oauth_local_credentials()
        peer.set_sync_payload("guard_events_v1_summary", MARKER, NOW)
        if status == "transport":
            raise OSError("synthetic transport failure")
        if status == "invalid":
            raise InvalidSyncResponseError("synthetic invalid response")
        assert isinstance(status, int)
        raise urllib.error.HTTPError(request.full_url, status, "synthetic failure", Message(), None)

    monkeypatch.setattr(runner, "_urlopen_json_with_timeout_retry", response)
    with hold_sync_auth_handoff(store, context, connection):
        if change != "unchanged":
            with pytest.raises(RuntimeError, match="connection changed"):
                runner.sync_guard_events(store, auth_context=context)
            assert peer.get_sync_payload("guard_events_v1_summary") == MARKER
        else:
            if status in (404, 429):
                result = runner.sync_guard_events(store, auth_context=context)
                assert result["sync_skipped"] is True
            else:
                with pytest.raises(RuntimeError):
                    runner.sync_guard_events(store, auth_context=context)
            assert peer.get_sync_payload("guard_events_v1_summary") != MARKER
        assert len(peer.list_guard_events_v1(uploaded=False)) == 1


@pytest.mark.parametrize("surface", ["receipt-controls", "guard-events", "pain-signals"])
def test_response_writes_hold_the_credential_lease(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, surface: str
) -> None:
    from concurrent.futures import ThreadPoolExecutor

    store, inputs = _ready(tmp_path, telemetry=True)
    _settings(store, telemetry=True)
    peer = GuardStore(store.guard_home, allow_system_keyring=False)
    connection = store.capture_oauth_connection()
    assert connection is not None
    context = _ordinary_auth(store)
    probes: list[bool] = []
    event = build_runtime_session_event(
        session_id="lease-session",
        occurred_at=NOW,
        payload={"sessionId": "lease-session", "harness": "codex", "status": "active"},
        device_id="synthetic-device",
        workspace_id=str(inputs["workspace_id"]),
    )

    def competing_commit() -> None:
        # A real competing writer must fail to acquire authority before it can write.
        with peer.hold_oauth_credential_lock(timeout_seconds=0):
            peer._set_sync_payload_unlocked("sync_summary", MARKER, NOW)

    def check_lease() -> None:
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(competing_commit)
            with pytest.raises(TimeoutError, match="credential lock"):
                future.result(timeout=3)
        probes.append(True)
        assert peer.get_sync_payload("sync_summary") is None

    def response(*, request, prepare_request, validate_request=None, **_kwargs):
        if validate_request is not None:
            validate_request()
        prepare_request(request)
        return {"syncedAt": NOW, "statuses": [{"eventId": event.event_id, "status": "accepted"}]}

    monkeypatch.setattr(runner, "_urlopen_json_with_timeout_retry", response)
    monkeypatch.setattr(runner, "_urlopen_with_timeout_retry", response)
    if surface == "guard-events":
        store.add_guard_event_v1(event)
        original_mark = store.mark_guard_events_v1_uploaded

        def mark(*args, **kwargs):
            check_lease()
            return original_mark(*args, **kwargs)

        monkeypatch.setattr(store, "mark_guard_events_v1_uploaded", mark)
    else:
        original_write = store.set_sync_payload
        expected_key = "alert_preferences" if surface == "receipt-controls" else "pain_signal_cursor"

        def write(key, payload, now):
            if key == expected_key:
                check_lease()
            return original_write(key, payload, now)

        monkeypatch.setattr(store, "set_sync_payload", write)
        if surface == "pain-signals":
            store.add_event(
                "changed_artifact_caught",
                {
                    "harness": "codex",
                    "artifact_id": "synthetic",
                    "artifact_name": "synthetic",
                    "policy_action": "block",
                    "changed_fields": ["command"],
                },
                NOW,
            )
    with hold_sync_auth_handoff(store, context, connection):
        if surface == "receipt-controls":
            runner.sync_receipts(store, auth_context=context, persist_sync_summary=False, persist_connect_state=False)
        elif surface == "guard-events":
            assert runner.sync_guard_events(store, auth_context=context)["accepted"] == 1
        else:
            assert runner.sync_pain_signals(store, auth_context=context) == 1
    assert probes == [True]
    competing_commit()
    assert peer.get_sync_payload("sync_summary") == MARKER


@pytest.mark.parametrize("change", ["replacement", "disconnect", "unchanged"])
def test_receipt_final_summary_rechecks_after_optional_uploads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    store, inputs = _ready(tmp_path)
    peer = GuardStore(store.guard_home, allow_system_keyring=False)
    connection = store.capture_oauth_connection()
    assert connection is not None
    context = _ordinary_auth(store)
    original_metrics = runner._build_value_metrics

    def response(*, request, prepare_request, validate_request, **_kwargs):
        validate_request()
        prepare_request(request)
        return {"syncedAt": NOW}

    def metrics(value):
        result = original_metrics(value)
        if change == "replacement":
            replacement = inputs.copy()
            replacement["workspace_id"] = "newer-team"
            peer.set_oauth_local_credentials(**replacement)
        elif change == "disconnect":
            peer.clear_oauth_local_credentials()
        if change != "unchanged":
            peer.set_sync_payload("sync_summary", MARKER, NOW)
        return result

    monkeypatch.setattr(runner, "_urlopen_json_with_timeout_retry", response)
    monkeypatch.setattr(runner, "_build_value_metrics", metrics)
    with hold_sync_auth_handoff(store, context, connection):
        if change == "unchanged":
            result = runner.sync_receipts(store, auth_context=context)
            assert peer.get_sync_payload("sync_summary") == result
        else:
            with pytest.raises(RuntimeError, match="connection changed"):
                runner.sync_receipts(store, auth_context=context)
            assert peer.get_sync_payload("sync_summary") == MARKER


@pytest.mark.parametrize("change", ["unchanged", "same-values", "replacement"])
def test_native_ack_commit_retains_the_request_connection(accepted, change: str) -> None:
    from codex_plugin_scanner.guard.native_policy_bundle_acceptance import capture_accepted_policy_bundle
    from codex_plugin_scanner.guard.native_policy_bundle_ack import commit_native_policy_bundle_acknowledgement
    from tests.test_oauth_connection_authority import _inputs

    store, publisher, _old_token, bundle, previous = accepted
    inputs = _inputs()
    inputs["workspace_id"] = bundle["workspaceId"]
    store.set_oauth_local_credentials(**inputs)
    expected = store.capture_oauth_connection()
    assert expected is not None
    if change != "unchanged":
        replacement = inputs.copy()
        if change == "replacement":
            replacement["refresh_token"] = "replacement-refresh"
        store.set_oauth_local_credentials(**replacement)
    # Actual publication succeeds for the live source. It is not sufficient to
    # let an older HTTP response adopt that newer connection's acceptance.
    publisher._publish_once()
    assert publisher.is_ready(), publisher.last_error
    token = capture_accepted_policy_bundle(
        publisher, bundle=bundle, installation_id=store.get_or_create_installation_id()
    )
    assert token is not None
    acknowledged = commit_native_policy_bundle_acknowledgement(publisher, token, expected_connection=expected)
    if change == "unchanged":
        assert acknowledged is not None and acknowledged["status"] == "applied"
    else:
        assert acknowledged is None
        assert store.get_sync_payload("policy_bundle_ack") == previous
