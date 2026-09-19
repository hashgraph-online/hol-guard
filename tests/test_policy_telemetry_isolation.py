"""Telemetry failures preserve policy progress without hiding authorization failure."""

from __future__ import annotations

import json
import urllib.error
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from codex_plugin_scanner.guard import native_policy_bundle_sync
from codex_plugin_scanner.guard.cli.render import emit_guard_payload
from codex_plugin_scanner.guard.runtime import runner
from codex_plugin_scanner.guard.store import GuardStore
from tests.support.native_policy_application import controlled_policy_publisher
from tests.support.native_policy_application import native_policy_consumer as native_policy_consumer
from tests.support.network import stub_authenticated_urlopen
from tests.support.optional_uploads import OPTIONAL_UPLOAD_WORKSPACE, prepare_optional_uploads
from tests.test_policy_bundle_v2 import _signed_bundle, _verification_key
from tests.test_policy_bundle_v2_runtime_admission import (
    _generic_v2_payload,
    _seed_v2_admission_store,
    _SyncResponse,
)

_AUTH: dict[str, object] = {
    "sync_url": "https://hol.org/api/guard/receipts/sync",
    "access_token": "test-token",
    "dpop_key_material": None,
}

pytestmark = pytest.mark.usefixtures("native_policy_consumer")


def _connected_policy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, optional_uploads: bool = False
) -> tuple[GuardStore, dict[str, object], list[dict[str, object]]]:
    monkeypatch.setenv("HOL_GUARD_POLICY_CANONICAL_ENFORCEMENT", "1")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    workspace_id = OPTIONAL_UPLOAD_WORKSPACE if optional_uploads else "workspace-alpha"
    key = _verification_key(private_key, workspace_id=workspace_id)
    bundle = _signed_bundle(
        private_key,
        key,
        payload_base=_generic_v2_payload(rule_id="block.outage", artifact_id="command:outage"),
        workspace_id=workspace_id,
    )
    store = _seed_v2_admission_store(tmp_path, key)
    if optional_uploads:
        prepare_optional_uploads(store, monkeypatch)
    requests: list[dict[str, object]] = []

    def response(request, timeout):
        requests.append(json.loads(request.data))
        return _SyncResponse({"syncedAt": "2026-07-15T12:01:00Z", "receiptsStored": 0, "policyBundle": bundle})

    stub_authenticated_urlopen(monkeypatch, response)
    monkeypatch.setattr(runner, "sync_pain_signals", lambda _store, auth_context=None: 0)
    monkeypatch.setattr(runner, "sync_guard_events", lambda _store, auth_context=None: {"events": 0, "accepted": 0})
    return store, bundle, requests


def _fail(error: BaseException):
    def upload(_store, auth_context=None):
        raise error

    return upload


@pytest.mark.parametrize("lane", ["pain_signals", "guard_events"])
@pytest.mark.parametrize("error", [RuntimeError("telemetry unavailable secret-canary"), OSError("connection reset")])
def test_optional_failure_keeps_applied_policy_and_uploads_its_ack_on_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, lane: str, error: BaseException
) -> None:
    store, bundle, requests = _connected_policy(tmp_path, monkeypatch)
    monkeypatch.setattr(runner, f"sync_{lane}", _fail(error))

    first = runner.sync_receipts(store, auth_context=_AUTH)

    assert first["receipt_upload_status"] == "success"
    assert first["policy_application_status"] == "applied"
    assert first["telemetry_status"] == "degraded"
    assert first[f"{lane}_upload_status"] == "degraded"
    assert "secret-canary" not in json.dumps(first)
    saved_ack = store.get_sync_payload("policy_bundle_ack")
    assert saved_ack["status"] == "applied"
    publisher = native_policy_bundle_sync.get_native_policy_snapshot_publisher(store)
    assert publisher.is_ready()
    acceptance = store.get_sync_payload("native_policy_bundle_ack_acceptance")
    assert isinstance(acceptance, dict)
    assert acceptance["ack"] == saved_ack
    assert acceptance["binding"] == publisher.current_snapshot_binding()
    assert store.get_sync_payload("policy_bundle")["bundleHash"] == bundle["bundleHash"]
    assert store.get_sync_payload("sync_summary") == first
    decisions = store.list_policy_decisions()
    monkeypatch.setattr(runner, "sync_pain_signals", lambda _store, auth_context=None: 3)
    monkeypatch.setattr(runner, "sync_guard_events", lambda _store, auth_context=None: {"events": 2, "accepted": 2})

    retried = runner.sync_receipts(store, auth_context=_AUTH)

    assert requests[-1]["syncContext"]["policyBundleAcknowledgementV2"] == saved_ack
    assert retried["policy_application_status"] == "applied"
    assert retried["telemetry_status"] == "success"
    assert retried["pain_signals_uploaded"] == 3
    assert [
        {key: value for key, value in row.items() if key != "decision_id"} for row in store.list_policy_decisions()
    ] == [{key: value for key, value in row.items() if key != "decision_id"} for row in decisions]
    assert store.get_sync_payload("policy_bundle")["bundleHash"] == bundle["bundleHash"]


@pytest.mark.parametrize("lane", ["pain_signals", "guard_events"])
@pytest.mark.parametrize("status", [401, 403])
def test_authorization_http_errors_are_not_hidden_by_optional_lane(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, lane: str, status: int
) -> None:
    store, _bundle, _requests = _connected_policy(tmp_path, monkeypatch)
    cause = urllib.error.HTTPError("https://hol.org/api/guard/signals/pain", status, "denied", {}, None)
    failure = RuntimeError("request 429 did not authorize this device")
    failure.__cause__ = cause
    monkeypatch.setattr(runner, f"sync_{lane}", _fail(failure))

    with pytest.raises(RuntimeError, match="did not authorize") as caught:
        runner.sync_receipts(store, auth_context=_AUTH)

    assert caught.value is failure


def test_sync_display_keeps_policy_outcome_separate_from_delayed_telemetry(capsys: pytest.CaptureFixture[str]) -> None:
    emit_guard_payload(
        "sync",
        {"policy_application_status": "applied", "telemetry_status": "degraded", "pain_signals_uploaded": 0},
        False,
    )
    output = " ".join(capsys.readouterr().out.split())
    assert "Policy application" in output and "applied" in output
    assert "Telemetry uploads delayed" in output


def test_unrecorded_event_failure_cannot_reuse_counts_from_previous_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _bundle, _requests = _connected_policy(tmp_path, monkeypatch)
    store.set_sync_payload("guard_events_v1_summary", {"events": 100, "accepted": 100}, "2026-07-15T12:00:00Z")
    monkeypatch.setattr(runner, "sync_guard_events", _fail(RuntimeError("telemetry unavailable")))

    summary = runner.sync_receipts(store, auth_context=_AUTH)

    assert summary["guard_events_v1"]["accepted"] is None
    assert summary["guard_events_v1"]["progress_known"] is False


@pytest.mark.parametrize("lane", ["pain_signals", "guard_events"])
@pytest.mark.parametrize(
    "error_class",
    [
        runner.GuardSyncAuthorizationExpiredError,
        runner.GuardSyncEndpointUntrustedError,
        runner.GuardSyncNotAvailableError,
    ],
)
def test_typed_authorization_and_endpoint_failures_propagate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, lane: str, error_class: type[RuntimeError]
) -> None:
    store, _bundle, _requests = _connected_policy(tmp_path, monkeypatch)
    failure = error_class("authorization 429 must not be mistaken for rate limiting")
    monkeypatch.setattr(runner, f"sync_{lane}", _fail(failure))

    with pytest.raises(error_class) as caught:
        runner.sync_receipts(store, auth_context=_AUTH)

    assert caught.value is failure


@pytest.mark.parametrize("lane", ["pain_signals", "guard_events"])
@pytest.mark.parametrize("native_reply", ["timeout", "different-source"])
def test_optional_telemetry_cannot_promote_unaccepted_policy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    lane: str,
    native_reply: str,
) -> None:
    store, bundle, _requests = _connected_policy(tmp_path, monkeypatch)
    publisher = controlled_policy_publisher(store, reply=native_reply)
    monkeypatch.setattr(native_policy_bundle_sync, "get_native_policy_snapshot_publisher", lambda _store: publisher)
    monkeypatch.setattr(runner, f"sync_{lane}", _fail(OSError("telemetry unavailable")))

    try:
        summary = runner.sync_receipts(store, auth_context=_AUTH)

        assert summary["receipt_upload_status"] == "success"
        assert summary["policy_application_status"] == "unverified"
        assert summary["policy_rejection_reason"] == "native_policy_publication_pending"
        assert summary["telemetry_status"] == "degraded"
        ack = store.get_sync_payload("policy_bundle_ack")
        assert isinstance(ack, dict) and ack["status"] == "received"
        assert ack["bundleHash"] == bundle["bundleHash"]
        assert store.get_sync_payload("native_policy_bundle_ack_acceptance") is None
        assert not native_policy_bundle_sync.get_native_policy_snapshot_publisher(store).is_ready()

    finally:
        publisher.close()
