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
from codex_plugin_scanner.guard.contracts.guard_cloud_review import validate_exact_command_result
from codex_plugin_scanner.guard.review_contracts import (
    build_local_review_request_claim,
    validated_remote_approval_envelope,
)
from codex_plugin_scanner.guard.runtime import command_queue
from codex_plugin_scanner.guard.runtime.command_capability import CommandCapabilityError, issue_command_capability
from codex_plugin_scanner.guard.runtime.command_executors import SUPPORTED_COMMAND_OPERATIONS
from codex_plugin_scanner.guard.runtime.exact_cloud_review import (
    EXACT_CLOUD_REVIEW_OPERATION,
    EXACT_CLOUD_REVIEW_PROTOCOL_VERSION,
    _oauth_metadata,
    disable_exact_cloud_review,
    enable_exact_cloud_review,
)
from codex_plugin_scanner.guard.runtime.exact_cloud_review_transport import (
    EXACT_CLOUD_REVIEW_COMMAND_API_BASE,
    exact_result,
    exact_transport_job,
    lease_next_job,
)
from tests.guard_exact_cloud_review_support import (
    add_review_request as _add_request,
)
from tests.guard_exact_cloud_review_support import (
    connected_exact_review_store,
)
from tests.guard_exact_cloud_review_support import (
    exact_review_job as _job,
)
from tests.guard_exact_cloud_review_support import (
    remote_approval as _remote_approval,
)
from tests.guard_exact_cloud_review_support import (
    review_request as _request,
)

_TRANSPORT_FIXTURE_PATH = Path(__file__).parent / "fixtures" / "guard-cloud-review" / "exact-transport-fixture.json"
_TRANSPORT_FIXTURE_SHA256 = "3b14a6c1ea73b53492d32bcd3031666fdd429220c1021525cb7df7510f12a0f3"


def _context(tmp_path: Path) -> HarnessContext:
    return HarnessContext(home_dir=tmp_path, workspace_dir=tmp_path, guard_home=tmp_path / "guard-home")


def _transport_fixture() -> dict[str, object]:
    fixture_bytes = _TRANSPORT_FIXTURE_PATH.read_bytes()
    assert hashlib.sha256(fixture_bytes).hexdigest() == _TRANSPORT_FIXTURE_SHA256
    fixture = json.loads(fixture_bytes)
    assert fixture["contractVersion"] == "guard-cloud-review-exact-transport-v2"
    return fixture


def _exact_job(tmp_path: Path):
    store = connected_exact_review_store(tmp_path)
    request = _request("exact-transport")
    _add_request(store, request)
    enable_exact_cloud_review(store)
    job = _job(
        store,
        _remote_approval(store, request.request_id, receipt_id="exact-transport-receipt"),
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


@pytest.mark.parametrize(
    "response",
    [
        {"item": None},
        {"item": None, "protocolVersion": 1},
        {"item": {"protocolVersion": 1}, "protocolVersion": 2},
    ],
)
def test_exact_lease_rejects_missing_or_downgraded_protocol(
    response: dict[str, object],
) -> None:
    with pytest.raises(ValueError, match="cloud_review_protocol_upgrade_required"):
        lease_next_job(
            operations=(EXACT_CLOUD_REVIEW_OPERATION,),
            wait_ms=0,
            exact_request=lambda _options: response,
            queue_request=lambda _options: pytest.fail("exact-only lease cannot use the generic queue"),
        )


def test_shared_exact_transport_fixture_binds_queue_eligibility_and_verifies_signature(tmp_path: Path) -> None:
    fixture = _transport_fixture()
    lease_request = fixture["leaseRequest"]
    lease_response = fixture["leaseResponse"]
    eligibility = fixture["queueEligibility"]
    assert isinstance(lease_request, dict) and isinstance(lease_response, dict)
    assert isinstance(eligibility, dict)
    assert "localRequestsSnapshot" not in lease_request
    assert lease_request["deviceId"] == eligibility["deviceId"]
    assert lease_request["workspaceId"] == eligibility["workspaceId"]
    assert eligibility["machineId"] == "machine-device-fixture"
    assert eligibility["machineInstallationId"] == "machine-installation-fixture"
    assert eligibility["machineId"] != eligibility["machineInstallationId"]

    item = lease_response["item"]
    assert isinstance(item, dict)
    payload = item["payload"]
    assert isinstance(payload, dict)
    remote_approval = payload["remoteApproval"]
    assert isinstance(remote_approval, dict)
    assert remote_approval["capabilityId"] == eligibility["capabilityId"]
    assert remote_approval["machineId"] == eligibility["machineId"]
    assert remote_approval["machineInstallationId"] == eligibility["machineInstallationId"]
    assert remote_approval["sourceClaimHash"] == eligibility["requestClaimHash"]
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
            item,
            {
                "generatedAt": "2026-08-24T00:03:00+00:00",
                "data": {
                    "daemonAckStatus": "resolved",
                    "localRequestId": "fixture-request",
                    "receiptId": "fixture-receipt",
                    "continuationStatus": "resumed",
                },
            },
        )
        == expected_result["result"]
    )
    validate_exact_command_result(expected_result["result"])


def test_exact_claim_binds_current_local_authority_without_queue_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, _job_payload = _exact_job(tmp_path)
    request = store.get_approval_request("exact-transport")
    assert isinstance(request, dict)
    oauth = _oauth_metadata(store)
    claim = build_local_review_request_claim(request_row=request, oauth=oauth, store=store)
    continuation = request["continuation_snapshot"]
    assert isinstance(continuation, dict)
    assert claim["correlationId"] == continuation["correlationId"]
    advertisement = claim["exactReviewCapability"]
    assert isinstance(advertisement, dict)
    capability = store.get_sync_payload("guard_exact_cloud_review_capability")
    assert isinstance(capability, dict)
    assert advertisement["operation"] == EXACT_CLOUD_REVIEW_OPERATION
    assert advertisement["deviceId"] == oauth.device_id == capability["deviceId"]
    assert advertisement["workspaceId"] == oauth.workspace_id == capability["workspaceId"]
    assert advertisement["machineId"] == oauth.machine_id
    assert advertisement["machineInstallationId"] == oauth.installation_id
    assert advertisement["runtimeId"] == oauth.runtime_id == "hol-guard"
    assert advertisement["machineId"] != advertisement["machineInstallationId"]
    assert advertisement["localRequestId"] == request["request_id"]
    assert advertisement["sourceClaimHash"] == claim["claimHash"]

    monkeypatch.setattr(
        command_queue,
        "_live_request_sync_repair_status",
        lambda _store: {"status": "repair_required"},
    )
    lease = command_queue._lease_payload(store, operations=(EXACT_CLOUD_REVIEW_OPERATION,))
    assert "localRequestsSnapshot" not in lease
    assert lease["protocolVersion"] == EXACT_CLOUD_REVIEW_PROTOCOL_VERSION
    assert lease["capabilities"] == {"operations": [EXACT_CLOUD_REVIEW_OPERATION]}
    disable_exact_cloud_review(store)
    refreshed_claim = build_local_review_request_claim(request_row=request, oauth=oauth, store=store)
    assert "exactReviewCapability" not in refreshed_claim


def test_poll_exact_leases_acks_applies_and_posts_versioned_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, job = _exact_job(tmp_path)
    calls: list[tuple[str, str, dict[str, object]]] = []

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
            return {
                "generatedAt": datetime.now(timezone.utc).isoformat(),
                "item": job,
                "protocolVersion": 2,
            }
        return {"ok": True}

    monkeypatch.setattr(command_queue, "_exact_json_request", exact_request)
    monkeypatch.setattr(
        command_queue,
        "_json_request",
        lambda *args, **kwargs: pytest.fail("exact-only capability must not poll the generic queue"),
    )
    monkeypatch.setattr(
        command_queue,
        "_resolve_command_queue_auth_context",
        lambda _store, force_refresh=False: {
            "sync_url": "https://guard.example/api/guard/receipts/sync",
            "access_token": "token",
        },
    )

    status = command_queue.poll_command_queue_once(store, _context(tmp_path))

    assert status["state"] == "idle"
    lease_payload = calls[0][2]
    assert lease_payload["deviceId"] == job["deviceId"]
    assert lease_payload["protocolVersion"] == 2
    capabilities = lease_payload["capabilities"]
    assert isinstance(capabilities, dict)
    assert capabilities["operations"] == [EXACT_CLOUD_REVIEW_OPERATION]
    assert "schemaVersions" not in capabilities
    ack_payload = {"leaseId": job["leaseId"], "protocolVersion": 2}
    assert calls[1] == ("POST", f"/{job['id']}/ack", ack_payload)
    assert calls[2] == ("POST", f"/{job['id']}/ack", ack_payload)
    result_call = calls[3]
    assert result_call[0:2] == ("POST", f"/{job['id']}/result")
    assert result_call[2]["protocolVersion"] == 2
    result = result_call[2]["result"]
    assert isinstance(result, dict)
    assert result["contractVersion"] == "guard-cloud-review-command-result-v2"
    assert result["applicationStatus"] == "applied"
    assert result["continuationStatus"] in {"resumed", "already_resumed", "manual_retry_required"}
    assert result["correlationId"] == job["id"]
    assert result["localRequestId"] == "exact-transport"
    assert result["protocolVersion"] == 2
    assert result["receiptId"] == "exact-transport-receipt"
    validate_exact_command_result(result)
    row = store.get_approval_request("exact-transport")
    assert row is not None and row["status"] == "resolved"


def test_mixed_capability_polls_exact_nonblocking_then_generic_queue(
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
    generic_calls: list[dict[str, object]] = []
    monkeypatch.setattr(
        command_queue,
        "_exact_json_request",
        lambda _auth, *, method, path, payload: exact_calls.append(payload) or {"item": None, "protocolVersion": 2},
    )
    monkeypatch.setattr(
        command_queue,
        "_json_request",
        lambda _auth, *, method, path, payload: generic_calls.append(payload) or {"item": None},
    )
    monkeypatch.setattr(command_queue, "_command_queue_lease_wait_ms", lambda: 17_000)

    item = command_queue._lease_next_job(store, {"sync_url": "https://guard.example", "access_token": "token"})

    assert item is None
    assert exact_calls[0]["waitMs"] == 0
    exact_capabilities = exact_calls[0]["capabilities"]
    assert isinstance(exact_capabilities, dict)
    assert exact_capabilities["operations"] == [EXACT_CLOUD_REVIEW_OPERATION]
    assert generic_calls[0]["waitMs"] == 17_000
    generic_capabilities = generic_calls[0]["capabilities"]
    assert isinstance(generic_capabilities, dict)
    assert generic_capabilities["operations"] == ["guard.packageShims.status"]


def test_missing_exact_route_preserves_generic_queue_progress_and_exact_health(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, _exact_job_payload = _exact_job(tmp_path)
    issue_command_capability(
        store,
        operations=("guard.packageShims.status",),
        supported_operations=SUPPORTED_COMMAND_OPERATIONS,
    )
    generic_job = {
        "id": "generic-status-job",
        "leaseId": "generic-status-lease",
        "operation": "guard.packageShims.status",
    }
    generic_paths: list[str] = []

    def unavailable(*args: object, **kwargs: object) -> dict[str, object]:
        del args, kwargs
        raise urllib.error.HTTPError(
            "https://guard.example/api/guard/review/v2/commands/lease",
            404,
            "Not Found",
            Message(),
            io.BytesIO(),
        )

    def generic_request(
        _auth: dict[str, object],
        *,
        method: str,
        path: str,
        payload: dict[str, object],
    ) -> dict[str, object]:
        del method, payload
        generic_paths.append(path)
        return {"item": generic_job} if path == "/lease" else {"ok": True}

    monkeypatch.setattr(command_queue, "_exact_json_request", unavailable)
    monkeypatch.setattr(command_queue, "_json_request", generic_request)
    monkeypatch.setattr(
        command_queue,
        "_resolve_command_queue_auth_context",
        lambda _store, force_refresh=False: {
            "sync_url": "https://guard.example/api/guard/receipts/sync",
            "access_token": "token",
        },
    )
    monkeypatch.setattr(
        command_queue,
        "_execute_job",
        lambda _job, _context, _store: {"generatedAt": "2026-08-24T12:00:01+00:00", "data": {"active_managers": []}},
    )

    status = command_queue.poll_command_queue_once(store, _context(tmp_path))

    assert status["state"] == "idle"
    assert "404" in str(status["exact_review_route_error"])
    assert generic_paths == [
        "/lease",
        "/generic-status-job/heartbeat",
        "/generic-status-job/heartbeat",
        "/generic-status-job/result",
    ]
    approval = store.get_approval_request("exact-transport")
    assert approval is not None and approval["status"] == "pending"


def test_exact_transport_rejects_cross_queue_operations_and_fails_closed_when_route_is_missing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, exact_job = _exact_job(tmp_path)
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
    with pytest.raises(CommandCapabilityError, match="remote_exact_job_invalid"):
        command_queue.authorize_command_queue_job(
            store,
            exact_transport_job({**exact_job, "schemaVersion": 1}),
            schema_versions=command_queue.COMMAND_OPERATION_SCHEMA_VERSIONS,
        )
    with pytest.raises(
        CommandCapabilityError,
        match="cloud_review_protocol_upgrade_required",
    ):
        command_queue.authorize_command_queue_job(
            store,
            exact_transport_job({**exact_job, "protocolVersion": 1}),
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
        lambda *_args, **_kwargs: pytest.fail("missing exact route must not reach the generic queue"),
    )
    with pytest.raises(urllib.error.HTTPError, match="Not Found"):
        command_queue._lease_next_job(store, {"sync_url": "https://guard.example", "access_token": "token"})


def test_pending_exact_result_retries_on_versioned_result_route(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, job = _exact_job(tmp_path)
    tagged = exact_transport_job(job)
    payload = {
        "leaseId": tagged["leaseId"],
        "idempotencyKey": "retry-result",
        "protocolVersion": 2,
        "status": "succeeded",
        "result": exact_result(
            tagged,
            {
                "generatedAt": "2026-08-24T00:03:00+00:00",
                "data": {
                    "daemonAckStatus": "resolved",
                    "localRequestId": "exact-transport",
                    "receiptId": "exact-transport-receipt",
                    "continuationStatus": "resumed",
                },
            },
        ),
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
        lambda *args, **kwargs: pytest.fail("pending exact result must not use the generic queue"),
    )

    assert command_queue._retry_pending_result(
        store,
        {"sync_url": "https://guard.example", "access_token": "token"},
        state,
    )
    assert calls == [f"/{job['id']}/result"]


def test_exact_result_validates_unsupported_continuation_status(tmp_path: Path) -> None:
    _store, job = _exact_job(tmp_path)

    result = exact_result(
        job,
        {
            "generatedAt": "2026-08-24T00:03:00+00:00",
            "data": {
                "daemonAckStatus": "resolved_unconfirmed",
                "localRequestId": "exact-transport",
                "receiptId": "exact-transport-receipt",
                "continuationReason": "no_resume_transport",
                "continuationStatus": "unsupported",
            },
        },
    )

    assert result["continuationStatus"] == "unsupported"
    validate_exact_command_result(result)
