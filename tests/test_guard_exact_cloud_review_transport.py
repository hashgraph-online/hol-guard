# pyright: reportPrivateUsage=false

from __future__ import annotations

import hashlib
import io
import json
import urllib.error
from datetime import datetime, timezone
from email.message import Message
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.review_contracts import (
    validate_local_review_request_claim,
    validated_remote_approval_envelope,
)
from codex_plugin_scanner.guard.runtime import command_queue
from codex_plugin_scanner.guard.runtime.command_capability import CommandCapabilityError, issue_command_capability
from codex_plugin_scanner.guard.runtime.command_executors import SUPPORTED_COMMAND_OPERATIONS
from codex_plugin_scanner.guard.runtime.exact_cloud_review import (
    EXACT_CLOUD_REVIEW_OPERATION,
    disable_exact_cloud_review,
    enable_exact_cloud_review,
)
from codex_plugin_scanner.guard.runtime.exact_cloud_review_transport import (
    EXACT_CLOUD_REVIEW_COMMAND_API_BASE,
    exact_result,
    exact_transport_job,
)
from tests.guard_exact_cloud_review_support import connected_exact_review_store
from tests.test_guard_exact_cloud_review import _add_request, _job, _remote_approval, _request

_TRANSPORT_FIXTURE_PATH = Path(__file__).parent / "fixtures" / "guard-cloud-review-v2" / "exact-transport-fixture.json"
_TRANSPORT_FIXTURE_SHA256 = "5e265b19ecaaa43b581d3a0b75d9d287ffa3762fad02ed7fdf130b710c1bfbd7"


def _context(tmp_path: Path) -> HarnessContext:
    return HarnessContext(home_dir=tmp_path, workspace_dir=tmp_path, guard_home=tmp_path / "guard-home")


def _transport_fixture() -> dict[str, object]:
    fixture_bytes = _TRANSPORT_FIXTURE_PATH.read_bytes()
    assert hashlib.sha256(fixture_bytes).hexdigest() == _TRANSPORT_FIXTURE_SHA256
    fixture = json.loads(fixture_bytes)
    assert fixture["contractVersion"] == "guard-cloud-review-exact-transport-v1"
    return fixture


def _exact_job(tmp_path: Path):
    store = connected_exact_review_store(tmp_path)
    request = _request("exact-v2-transport")
    _add_request(store, request)
    enable_exact_cloud_review(store)
    job = _job(
        store,
        _remote_approval(store, request.request_id, receipt_id="exact-v2-transport-receipt"),
    )
    job.update(
        {
            "resultContractVersion": "guard-cloud-review-command-result-v2",
            "serverResolvedBinding": {"localRequestId": request.request_id},
        }
    )
    return store, job


def test_exact_command_api_url_uses_versioned_review_route() -> None:
    assert (
        command_queue._command_api_url(
            "https://guard.example/api/guard/receipts/sync",
            "/lease",
            base_path=EXACT_CLOUD_REVIEW_COMMAND_API_BASE,
        )
        == "https://guard.example/api/guard/review/v2/commands/lease"
    )


def test_shared_exact_transport_fixture_binds_queue_eligibility_and_verifies_signature(tmp_path: Path) -> None:
    fixture = _transport_fixture()
    lease_request = fixture["leaseRequest"]
    lease_response = fixture["leaseResponse"]
    eligibility = fixture["queueEligibility"]
    assert isinstance(lease_request, dict) and isinstance(lease_response, dict)
    assert isinstance(eligibility, dict)
    snapshot = lease_request["localRequestsSnapshot"]
    assert isinstance(snapshot, dict)
    requests = snapshot["requests"]
    assert isinstance(requests, list) and len(requests) == 1
    request_item = requests[0]
    assert isinstance(request_item, dict)
    claim = request_item["claim"]
    assert isinstance(claim, dict)
    validate_local_review_request_claim(claim)
    advertisement = claim["exactReviewCapability"]
    assert isinstance(advertisement, dict)
    assert lease_request["deviceId"] == advertisement["deviceId"] == eligibility["deviceId"]
    assert lease_request["workspaceId"] == advertisement["workspaceId"] == eligibility["workspaceId"]
    assert advertisement["capabilityId"] == eligibility["capabilityId"]
    assert advertisement["machineInstallationId"] == advertisement["machineId"]
    assert advertisement["sourceClaimHash"] == eligibility["requestClaimHash"] == claim["claimHash"]
    assert advertisement["actionDigest"] == eligibility["actionEnvelopeHash"] == claim["actionEnvelopeHash"]
    assert advertisement["requestVersion"] == eligibility["requestVersion"] == claim["policyVersion"]

    item = lease_response["item"]
    assert isinstance(item, dict)
    payload = item["payload"]
    assert isinstance(payload, dict)
    remote_approval = payload["remoteApproval"]
    assert isinstance(remote_approval, dict)
    assert remote_approval["capabilityId"] == advertisement["capabilityId"]
    assert remote_approval["grantId"] == claim["grantId"] == advertisement["grantId"]
    keys = remote_approval["verificationKeys"]
    store = connected_exact_review_store(tmp_path)
    store.set_sync_payload("guard_review_verification_keyring", keys, "2026-08-24T00:00:00+00:00")
    assert (
        validated_remote_approval_envelope(
            remote_approval,
            store=store,
            admitted_at="2026-08-24T00:02:30+00:00",
        )
        == remote_approval
    )
    expected_result = fixture["resultRequest"]
    assert isinstance(expected_result, dict)
    assert (
        exact_result(
            {
                "generatedAt": "2026-08-24T00:03:00+00:00",
                "data": {"daemonAckStatus": "resolved", "resumeStatus": "resumed"},
            }
        )
        == expected_result["result"]
    )


def test_live_request_claim_advertises_only_current_local_exact_authority(tmp_path: Path) -> None:
    store, _job_payload = _exact_job(tmp_path)
    request = store.get_approval_request("exact-v2-transport")
    assert isinstance(request, dict)
    lease = command_queue._lease_payload(store, operations=(EXACT_CLOUD_REVIEW_OPERATION,))
    snapshot = lease["localRequestsSnapshot"]
    assert isinstance(snapshot, dict)
    items = snapshot["requests"]
    assert isinstance(items, list) and items
    claim = items[0]["claim"]
    assert isinstance(claim, dict)
    advertisement = claim["exactReviewCapability"]
    assert isinstance(advertisement, dict)
    capability = store.get_sync_payload("guard_exact_cloud_review_capability_v1")
    assert isinstance(capability, dict)
    assert advertisement["operation"] == EXACT_CLOUD_REVIEW_OPERATION
    assert advertisement["deviceId"] == lease["deviceId"] == capability["deviceId"]
    assert advertisement["workspaceId"] == lease["workspaceId"] == capability["workspaceId"]
    assert advertisement["machineInstallationId"] == advertisement["machineId"]
    assert advertisement["localRequestId"] == request["request_id"]
    assert advertisement["sourceClaimHash"] == claim["claimHash"]

    disable_exact_cloud_review(store)
    refreshed = command_queue._local_requests_snapshot(store)
    refreshed_items = refreshed["requests"]
    assert isinstance(refreshed_items, list) and refreshed_items
    refreshed_claim = refreshed_items[0]["claim"]
    assert isinstance(refreshed_claim, dict)
    assert "exactReviewCapability" not in refreshed_claim


def test_poll_exact_v2_leases_acks_applies_and_posts_versioned_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, job = _exact_job(tmp_path)
    calls: list[tuple[str, str, dict[str, object]]] = []
    lifecycle: list[dict[str, object]] = []

    def exact_request(
        auth_context: dict[str, object],
        *,
        method: str,
        path: str,
        payload: dict[str, object],
    ) -> dict[str, object]:
        assert auth_context["access_token"] == "token"
        calls.append((method, path, payload))
        if path == "/lease":
            return {"generatedAt": datetime.now(timezone.utc).isoformat(), "item": job}
        return {"ok": True}

    monkeypatch.setattr(command_queue, "_exact_json_request", exact_request)
    monkeypatch.setattr(
        command_queue,
        "_json_request",
        lambda *args, **kwargs: pytest.fail("exact-only capability must not poll the legacy queue"),
    )
    monkeypatch.setattr(
        command_queue,
        "_resolve_command_queue_auth_context",
        lambda _store, force_refresh=False: {
            "sync_url": "https://guard.example/api/guard/receipts/sync",
            "access_token": "token",
        },
    )

    status = command_queue.poll_command_queue_once(
        store,
        _context(tmp_path),
        observer=lifecycle.append,
    )

    assert status["state"] == "idle"
    lease_payload = calls[0][2]
    assert lease_payload["deviceId"] == job["deviceId"]
    capabilities = lease_payload["capabilities"]
    assert isinstance(capabilities, dict)
    assert capabilities["operations"] == [EXACT_CLOUD_REVIEW_OPERATION]
    assert capabilities["schemaVersions"] == {EXACT_CLOUD_REVIEW_OPERATION: 1}
    assert calls[1] == ("POST", f"/{job['id']}/ack", {"leaseId": job["leaseId"]})
    assert calls[2] == ("POST", f"/{job['id']}/ack", {"leaseId": job["leaseId"]})
    result_call = calls[3]
    assert result_call[0:2] == ("POST", f"/{job['id']}/result")
    result = result_call[2]["result"]
    assert isinstance(result, dict)
    assert result["contractVersion"] == "guard-cloud-review-command-result-v2"
    assert result["applicationStatus"] == "applied"
    assert result["continuationStatus"] in {"resumed", "already_resumed", "manual_retry_required"}
    row = store.get_approval_request("exact-v2-transport")
    assert row is not None and row["status"] == "resolved"
    assert [item["event"] for item in lifecycle] == [
        "command_leased",
        "local_resolved",
        "continuation_completed",
        "command_result",
    ]
    assert {item["correlationId"] for item in lifecycle} == {job["id"]}
    assert all(item["operation"] == EXACT_CLOUD_REVIEW_OPERATION for item in lifecycle)


def test_mixed_capability_polls_exact_nonblocking_then_legacy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, _job_payload = _exact_job(tmp_path)
    issue_command_capability(
        store,
        operations=("guard.packageShims.status",),
        supported_operations=SUPPORTED_COMMAND_OPERATIONS,
    )
    exact_calls: list[dict[str, object]] = []
    legacy_calls: list[dict[str, object]] = []
    monkeypatch.setattr(
        command_queue,
        "_exact_json_request",
        lambda _auth, *, method, path, payload: exact_calls.append(payload) or {"item": None},
    )
    monkeypatch.setattr(
        command_queue,
        "_json_request",
        lambda _auth, *, method, path, payload: legacy_calls.append(payload) or {"item": None},
    )
    monkeypatch.setattr(command_queue, "_command_queue_lease_wait_ms", lambda: 17_000)

    item = command_queue._lease_next_job(store, {"sync_url": "https://guard.example", "access_token": "token"})

    assert item is None
    assert exact_calls[0]["waitMs"] == 0
    exact_capabilities = exact_calls[0]["capabilities"]
    assert isinstance(exact_capabilities, dict)
    assert exact_capabilities["operations"] == [EXACT_CLOUD_REVIEW_OPERATION]
    assert legacy_calls[0]["waitMs"] == 17_000
    legacy_capabilities = legacy_calls[0]["capabilities"]
    assert isinstance(legacy_capabilities, dict)
    assert legacy_capabilities["operations"] == ["guard.packageShims.status"]


def test_exact_transport_rejects_cross_queue_operations_and_preserves_legacy_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, exact_job = _exact_job(tmp_path)
    issue_command_capability(
        store,
        operations=("guard.packageShims.status",),
        supported_operations=SUPPORTED_COMMAND_OPERATIONS,
    )
    generic_job = {
        **exact_job,
        "operation": "guard.packageShims.status",
        "schemaVersion": 1,
        "payload": {},
    }
    with pytest.raises(CommandCapabilityError, match="remote_exact_job_operation_invalid"):
        command_queue.authorize_command_queue_job(
            store,
            exact_transport_job(generic_job),
            schema_versions=command_queue.COMMAND_OPERATION_SCHEMA_VERSIONS,
        )
    with pytest.raises(CommandCapabilityError, match="remote_exact_transport_required"):
        command_queue.authorize_command_queue_job(
            store,
            exact_job,
            schema_versions=command_queue.COMMAND_OPERATION_SCHEMA_VERSIONS,
        )

    def unavailable(*args: object, **kwargs: object) -> dict[str, object]:
        del args, kwargs
        raise urllib.error.HTTPError(
            "https://guard.example/api/guard/review/v2/commands/lease",
            404,
            "Not Found",
            Message(),
            io.BytesIO(),
        )

    monkeypatch.setattr(command_queue, "_exact_json_request", unavailable)
    monkeypatch.setattr(
        command_queue,
        "_json_request",
        lambda _auth, *, method, path, payload: {"item": generic_job},
    )
    leased = command_queue._lease_next_job(store, {"sync_url": "https://guard.example", "access_token": "token"})
    assert leased == generic_job


def test_pending_exact_result_retries_on_v2_result_route(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, job = _exact_job(tmp_path)
    tagged = exact_transport_job(job)
    payload = {
        "leaseId": tagged["leaseId"],
        "idempotencyKey": "retry-result",
        "status": "succeeded",
        "result": {"contractVersion": "guard-cloud-review-command-result-v2"},
    }
    state: dict[str, object] = {
        "state": "result_pending",
        "pending_result": {"job": tagged, "payload": payload},
        "active_job": tagged,
    }
    store.set_sync_payload(command_queue.COMMAND_QUEUE_STATE_KEY, state, datetime.now(timezone.utc).isoformat())
    calls: list[str] = []
    monkeypatch.setattr(
        command_queue,
        "_exact_json_request",
        lambda _auth, *, method, path, payload: calls.append(path) or {"ok": True},
    )
    monkeypatch.setattr(
        command_queue,
        "_json_request",
        lambda *args, **kwargs: pytest.fail("pending exact result must not use legacy transport"),
    )

    assert command_queue._retry_pending_result(
        store,
        {"sync_url": "https://guard.example", "access_token": "token"},
        state,
    )
    assert calls == [f"/{job['id']}/result"]
