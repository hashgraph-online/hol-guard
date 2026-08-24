# pyright: reportMissingImports=false

from __future__ import annotations

import json
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.cli import _build_parser, _resolve_legacy_args, main
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.daemon import command_queue_worker as queue_worker_module
from codex_plugin_scanner.guard.daemon import server as daemon_server_module
from codex_plugin_scanner.guard.daemon.headless_exact_cloud_review import build_headless_exact_cloud_review_response
from codex_plugin_scanner.guard.daemon.manager import load_guard_daemon_auth_token
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.review_contracts import (
    build_local_review_request_claim,
    payload_hash_for_remote_approval_envelope,
)
from codex_plugin_scanner.guard.runtime import runner as guard_runner_module
from codex_plugin_scanner.guard.runtime.command_capability import (
    CommandCapabilityError,
    issue_command_capability,
    mark_command_job_consumed,
)
from codex_plugin_scanner.guard.runtime.command_executors import (
    COMMAND_OPERATION_SCHEMA_VERSIONS,
    SUPPORTED_COMMAND_OPERATIONS,
    _local_request_snapshot_payload,
    execute_guard_command_job,
)
from codex_plugin_scanner.guard.runtime.command_queue_authority import (
    authorize_command_queue_job,
    command_queue_oauth_target,
)
from codex_plugin_scanner.guard.runtime.exact_cloud_review import (
    EXACT_CLOUD_REVIEW_OPERATION,
    ExactCloudReviewError,
    _oauth_metadata,
    apply_exact_cloud_review,
    disable_exact_cloud_review,
    enable_exact_cloud_review,
    exact_cloud_review_operations,
)
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_exact_cloud_review_support import (
    connected_exact_review_store as _connected_store,
)
from tests.guard_exact_cloud_review_support import (
    post_json,
)
from tests.guard_review_signing_helpers import (
    REVIEW_SIGNING_KEY_ID,
    review_verification_keys,
    sign_review_payload,
)


def _request(request_id: str, *, harness: str = "codex") -> GuardApprovalRequest:
    return GuardApprovalRequest(
        request_id=request_id,
        harness=harness,
        artifact_id=f"{harness}:project:{request_id}",
        artifact_name="Exact Cloud Review request",
        artifact_type="tool_action_request",
        artifact_hash=f"hash-{request_id}",
        publisher=None,
        policy_action="require-reapproval",
        recommended_scope="artifact",
        changed_fields=("shell_command",),
        source_scope="project",
        config_path="/workspace/repo/.guard/config.toml",
        workspace="/workspace/repo",
        launch_target="cat /workspace/repo/.npmrc",
        review_command=f"hol-guard approvals approve {request_id}",
        approval_url=f"http://127.0.0.1:5474/approvals/{request_id}",
        action_envelope_json={
            "action_type": "shell_command",
            "command": "cat /workspace/repo/.npmrc",
            "tool_name": "Bash",
        },
    )


def _add_request(store: GuardStore, request: GuardApprovalRequest) -> None:
    store.add_approval_request(request, datetime.now(timezone.utc).isoformat())


def _remote_approval(
    store: GuardStore,
    request_id: str,
    *,
    receipt_id: str,
    decision: str = "allow_once",
    issued_at: datetime | None = None,
    expires_at: datetime | None = None,
    source_claim: dict[str, object] | None = None,
) -> dict[str, object]:
    request = store.get_approval_request(request_id)
    assert isinstance(request, dict)
    claim = source_claim or build_local_review_request_claim(
        request_row=request, oauth=_oauth_metadata(store), store=store
    )
    advertisement = claim["exactReviewCapability"]
    assert isinstance(advertisement, dict)
    issued_at = issued_at or datetime.now(timezone.utc).replace(microsecond=0)
    expires_at = expires_at or issued_at + timedelta(minutes=5)
    envelope: dict[str, object] = {
        "actionEnvelopeHash": claim["actionEnvelopeHash"],
        "approvalId": claim["approvalId"],
        "capabilityId": advertisement["capabilityId"],
        "capabilityCategory": claim["capabilityCategory"],
        "contractVersion": "guard.remote-approval.v1",
        "decision": decision,
        "decisionId": receipt_id,
        "deviceId": claim["deviceId"],
        "expiresAt": expires_at.isoformat(),
        "grantId": claim["grantId"],
        "harnessId": claim["harnessId"],
        "issuedAt": issued_at.isoformat(),
        "keyId": REVIEW_SIGNING_KEY_ID,
        "localRequestId": claim["localRequestId"],
        "machineId": claim["machineId"],
        "machineInstallationId": claim["machineInstallationId"],
        "nonce": f"{claim['nonce']}:{receipt_id}",
        "policyVersion": claim["policyVersion"],
        "projectIdentity": claim["projectIdentity"],
        "receiptId": receipt_id,
        "reviewerRole": "owner",
        "reviewerUserId": "user-1",
        "riskCategory": claim["riskCategory"],
        "runtimeGrantId": claim["runtimeGrantId"],
        "scope": "artifact",
        "sourceClaimHash": claim["claimHash"],
        "stepUpChallengeId": None,
        "verificationKeys": review_verification_keys(),
        "signatureAlgorithm": "rsa-pss-sha256",
        "workspaceId": claim["workspaceId"],
    }
    envelope["payloadHash"] = payload_hash_for_remote_approval_envelope(envelope)
    envelope["signature"] = sign_review_payload(envelope)
    return envelope


def _job(
    store: GuardStore,
    remote_approval: dict[str, object],
    *,
    created_at: datetime | None = None,
    expires_at: datetime | None = None,
) -> dict[str, object]:
    credentials = store.get_oauth_local_credentials(allow_primary=False)
    assert isinstance(credentials, dict)
    capability = store.get_sync_payload("guard_exact_cloud_review_capability_v1")
    assert isinstance(capability, dict)
    device_id = capability.get("deviceId")
    assert isinstance(device_id, str) and device_id
    return {
        "id": "exact-job-1",
        "leaseId": "exact-lease-1",
        "operation": EXACT_CLOUD_REVIEW_OPERATION,
        "schemaVersion": COMMAND_OPERATION_SCHEMA_VERSIONS[EXACT_CLOUD_REVIEW_OPERATION],
        "deviceId": device_id,
        "workspaceId": credentials["workspace_id"],
        "nonce": "exact-job-nonce",
        "createdAt": (created_at or datetime.now(timezone.utc)).isoformat(),
        "expiresAt": (expires_at or datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        "idempotencyKey": "exact-idempotency-key",
        "payload": {"harness": "codex", "remoteApproval": remote_approval},
    }


def test_exact_cloud_review_resolves_one_request_without_policy_or_memory(tmp_path: Path) -> None:
    store = _connected_store(tmp_path)
    target = _request("exact-target")
    other = _request("exact-other")
    _add_request(store, target)
    _add_request(store, other)
    policies_before = store.list_policy_decisions()
    enable_exact_cloud_review(store)

    resolution = apply_exact_cloud_review(
        store,
        remote_approval=_remote_approval(store, target.request_id, receipt_id="exact-receipt-1"),
        expected_harness="codex",
    )

    assert resolution.request_id == target.request_id
    assert resolution.resolved_request["resolution_scope"] == "artifact"
    target_row = store.get_approval_request(target.request_id)
    other_row = store.get_approval_request(other.request_id)
    assert target_row is not None and target_row["status"] == "resolved"
    assert other_row is not None and other_row["status"] == "pending"
    assert store.list_policy_decisions() == policies_before
    assert store.get_sync_payload("guard_review_memory_registry") is None
    audit = store.list_events(limit=1, event_name="cloud_review.exact_applied")
    assert audit
    audit_payload = audit[0].get("payload")
    assert isinstance(audit_payload, dict)
    assert audit_payload["receipt_id"] == "exact-receipt-1"


def test_exact_cloud_review_replay_is_durable_and_rejected_before_resolution(tmp_path: Path) -> None:
    store = _connected_store(tmp_path)
    request = _request("exact-replay")
    _add_request(store, request)
    enable_exact_cloud_review(store)
    approval = _remote_approval(store, request.request_id, receipt_id="exact-receipt-replay")
    apply_exact_cloud_review(store, remote_approval=approval)

    reopened = GuardStore(store.guard_home)
    with pytest.raises(ExactCloudReviewError, match="remote_exact_replayed"):
        apply_exact_cloud_review(reopened, remote_approval=approval)
    reopened_request = reopened.get_approval_request(request.request_id)
    assert reopened_request is not None and reopened_request["status"] == "resolved"


def test_exact_cloud_review_capability_is_separate_from_generic_commands(tmp_path: Path) -> None:
    missing_store = _connected_store(tmp_path / "missing-device", missing_device_id=True)
    missing_credentials = missing_store.get_oauth_local_credentials(allow_primary=False)
    assert isinstance(missing_credentials, dict) and missing_credentials["machine_id"]
    with pytest.raises(ExactCloudReviewError, match="cloud_review_device_binding_missing"):
        enable_exact_cloud_review(missing_store)
    store = _connected_store(tmp_path)
    oauth_state = store.get_sync_payload("oauth_local_credentials")
    assert isinstance(oauth_state, dict)
    without_device = {key: value for key, value in oauth_state.items() if key != "device_id"}
    store.set_sync_payload("oauth_local_credentials", without_device, datetime.now(timezone.utc).isoformat())
    with pytest.raises(ExactCloudReviewError, match="cloud_review_device_binding_missing"):
        enable_exact_cloud_review(store)
    store.set_sync_payload("oauth_local_credentials", oauth_state, datetime.now(timezone.utc).isoformat())
    status = enable_exact_cloud_review(store)

    assert status["enabled"] is True
    request = _request("exact-missing-device-atomic")
    _add_request(store, request)
    approval = _remote_approval(store, request.request_id, receipt_id="exact-missing-device-atomic")
    store.set_sync_payload("oauth_local_credentials", without_device, datetime.now(timezone.utc).isoformat())
    with pytest.raises(ExactCloudReviewError, match="cloud_review_device_binding_missing"):
        apply_exact_cloud_review(store, remote_approval=approval)
    pending = store.get_approval_request(request.request_id)
    assert pending is not None and pending["status"] == "pending"
    store.set_sync_payload("oauth_local_credentials", oauth_state, datetime.now(timezone.utc).isoformat())
    diagnostics = status.get("diagnostics")
    assert isinstance(diagnostics, dict)
    assert {"capability", "oauth", "outbox", "worker"} <= diagnostics.keys()
    assert exact_cloud_review_operations(store) == (EXACT_CLOUD_REVIEW_OPERATION,)
    with pytest.raises(CommandCapabilityError, match="unsupported_capability_operation"):
        issue_command_capability(
            store,
            operations=(EXACT_CLOUD_REVIEW_OPERATION,),
            supported_operations=SUPPORTED_COMMAND_OPERATIONS,
        )
    disabled = disable_exact_cloud_review(store)
    assert disabled["enabled"] is False
    assert exact_cloud_review_operations(store) == ()
    assert store.get_sync_payload("guard_exact_cloud_review_revocation_v1") is not None


def test_exact_cloud_review_rejects_tampered_or_revoked_capabilities(tmp_path: Path) -> None:
    store = _connected_store(tmp_path)
    request = _request("exact-revoked")
    _add_request(store, request)
    enable_exact_cloud_review(store)
    remote_approval = _remote_approval(store, request.request_id, receipt_id="exact-tampered")
    capability = store.get_sync_payload("guard_exact_cloud_review_capability_v1")
    assert isinstance(capability, dict)
    tampered = {**capability, "workspaceId": "other-workspace"}
    store.set_sync_payload("guard_exact_cloud_review_capability_v1", tampered, "2026-08-24T12:00:00+00:00")
    with pytest.raises(ExactCloudReviewError, match="cloud_review_capability_signature_invalid"):
        apply_exact_cloud_review(
            store,
            remote_approval=remote_approval,
        )

    disable_exact_cloud_review(store)
    store.set_sync_payload("guard_exact_cloud_review_capability_v1", capability, "2026-08-24T12:00:00+00:00")
    with pytest.raises(ExactCloudReviewError, match="cloud_review_capability_revoked"):
        apply_exact_cloud_review(
            store,
            remote_approval=remote_approval,
        )


def test_exact_cloud_review_cli_status_is_routable(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    guard_home = tmp_path / "guard-home"

    assert main(["guard", "cloud-review", "status", "--guard-home", str(guard_home), "--json"]) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["operation"] == EXACT_CLOUD_REVIEW_OPERATION
    assert payload["enabled"] is False


def test_hol_guard_routes_cloud_review_as_a_top_level_command() -> None:
    assert _resolve_legacy_args(
        ["cloud-review", "status"],
        program_mode="combined",
        program_name="hol-guard",
    ) == ["guard", "cloud-review", "status"]
    parser = _build_parser("hol-guard", program_mode="combined")
    assert parser.parse_args(["guard", "connect", "--enable-exact-cloud-review"]).enable_exact_cloud_review is True
    assert parser.parse_args(["guard", "connect", "--headless", "--enable-exact-cloud-review"]).headless is True


def test_exact_cloud_review_queue_job_requires_no_generic_capability_or_local_approval(tmp_path: Path) -> None:
    store = _connected_store(tmp_path)
    credentials = store.get_oauth_local_credentials(allow_primary=False)
    assert isinstance(credentials, dict)
    guard_runner_module._persist_rotated_oauth_refresh_token(
        store=store,
        credentials=credentials,
        refresh_token="rotated-refresh-token",
    )
    oauth_state = store.get_sync_payload("oauth_local_credentials")
    assert isinstance(oauth_state, dict)
    assert oauth_state["device_id"] == credentials["dpop_public_jwk_thumbprint"]
    request = _request("exact-queue")
    _add_request(store, request)
    enable_exact_cloud_review(store)
    snapshot = _local_request_snapshot_payload(store)
    snapshot_requests = snapshot.get("requests")
    assert isinstance(snapshot_requests, list) and snapshot_requests
    snapshot_claim = snapshot_requests[0].get("claim")
    assert isinstance(snapshot_claim, dict)
    assert snapshot_claim["deviceId"] == oauth_state["device_id"]
    assert snapshot_claim["machineId"] == oauth_state["machine_id"]
    assert command_queue_oauth_target(store) == (oauth_state["device_id"], oauth_state["workspace_id"])
    job = _job(
        store,
        _remote_approval(
            store,
            request.request_id,
            receipt_id="exact-receipt-queue",
            source_claim=snapshot_claim,
        ),
    )

    authorized = authorize_command_queue_job(store, job, schema_versions=COMMAND_OPERATION_SCHEMA_VERSIONS)
    assert authorized.identity["deviceId"] == oauth_state["device_id"]
    with pytest.raises(CommandCapabilityError, match="remote_exact_job_wrong_target"):
        authorize_command_queue_job(
            store,
            {**job, "deviceId": oauth_state["machine_id"]},
            schema_versions=COMMAND_OPERATION_SCHEMA_VERSIONS,
        )
    result = execute_guard_command_job(
        job,
        context=HarnessContext(home_dir=tmp_path, workspace_dir=tmp_path, guard_home=store.guard_home),
        store=store,
    )

    assert authorized.operation == EXACT_CLOUD_REVIEW_OPERATION
    assert authorized.requires_local_approval is False
    result_data = result.get("data")
    assert isinstance(result_data, dict)
    assert result_data["status"] == "completed"
    assert result_data["daemonAckStatus"] == "resolved"
    assert store.get_sync_payload("guard_review_memory_registry") is None
    second = _request("exact-queue-replay-second")
    _add_request(store, second)
    mark_command_job_consumed(store, authorized)
    replay = _job(store, _remote_approval(store, second.request_id, receipt_id="exact-job-second"))

    with pytest.raises(CommandCapabilityError, match="remote_exact_job_replayed"):
        authorize_command_queue_job(store, replay, schema_versions=COMMAND_OPERATION_SCHEMA_VERSIONS)

    second_row = store.get_approval_request(second.request_id)
    assert second_row is not None and second_row["status"] == "pending"
    recovery_now = datetime.now(timezone.utc).isoformat()
    store.record_guard_connect_pairing_completed(
        sync_url="https://hol.org/api/guard/receipts/sync",
        allowed_origin="https://hol.org",
        now=recovery_now,
    )
    store.delete_sync_payload("oauth_local_credentials")
    recovered = store._recover_missing_oauth_local_credentials_payload(now=recovery_now)
    assert isinstance(recovered, dict)
    assert recovered["device_id"] == oauth_state["device_id"]
    assert recovered["dpop_public_jwk_thumbprint"] == oauth_state["dpop_public_jwk_thumbprint"]
    assert "dpop_private_key_pem" not in recovered
    assert "dpop_public_jwk" not in recovered
    assert "refresh_token" not in recovered

    assert store.repair_oauth_local_credential_storage_from_primary() is True
    restarted = GuardStore(store.guard_home)
    persisted = restarted.get_sync_payload("oauth_local_credentials")
    assert isinstance(persisted, dict)
    assert persisted["dpop_public_jwk_thumbprint"] == oauth_state["dpop_public_jwk_thumbprint"]


def test_headless_exact_endpoint_uses_the_same_service(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _connected_store(tmp_path)
    request = _request("exact-headless")
    _add_request(store, request)
    enable_exact_cloud_review(store)
    monkeypatch.setattr(daemon_server_module, "start_command_queue_worker", lambda *_args: None)
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = load_guard_daemon_auth_token(store.guard_home)
        assert token is not None
        status, payload = post_json(
            daemon.port,
            "/v1/requests/remote-exact",
            token,
            {
                "harness": "codex",
                "remoteApproval": _remote_approval(store, request.request_id, receipt_id="exact-receipt-headless"),
            },
        )
    finally:
        daemon.stop()

    assert status == 200
    assert payload["operation"] == "remote_exact"
    resolved_request = payload.get("resolved_request")
    assert isinstance(resolved_request, dict)
    assert resolved_request["request_id"] == request.request_id

    side_effect_request = _request("exact-headless-side-effects")
    _add_request(store, side_effect_request)
    side_effect_calls: list[str] = []

    def _record_failure(**_kwargs: object) -> dict[str, object]:
        side_effect_calls.append("receipt")
        raise RuntimeError("receipt unavailable")

    def _resume_failure(**_kwargs: object) -> dict[str, object]:
        side_effect_calls.append("resume")
        raise RuntimeError("resume unavailable")

    failure_status, failure_payload = build_headless_exact_cloud_review_response(
        store=store,
        payload={
            "harness": "codex",
            "remoteApproval": _remote_approval(
                store,
                side_effect_request.request_id,
                receipt_id="exact-receipt-side-effects",
            ),
        },
        decode_mapping=lambda value: value if isinstance(value, dict) else {},
        optional_string=lambda value: value if isinstance(value, str) and value else None,
        record_receipt=_record_failure,
        resume_codex=_resume_failure,
        now=lambda: datetime.now(timezone.utc).isoformat(),
    )

    assert failure_status == 200
    assert failure_payload["status"] == "completed"
    assert failure_payload["delivery_status"] == "incomplete"
    assert failure_payload["post_commit_errors"] == ["receipt_record_failed", "harness_resume_failed"]
    assert side_effect_calls == ["receipt", "resume"]
    delivery_codes: set[object] = set()
    for event in store.list_events(limit=10, event_name="cloud_review.exact_delivery_failed"):
        event_payload = event.get("payload")
        assert isinstance(event_payload, dict)
        delivery_codes.add(event_payload.get("code"))
    assert delivery_codes == {
        "harness_resume_failed",
        "receipt_record_failed",
    }
    side_effect_row = store.get_approval_request(side_effect_request.request_id)
    assert side_effect_row is not None and side_effect_row["status"] == "resolved"

    starts: list[str] = []
    monkeypatch.setattr(
        daemon_server_module,
        "start_command_queue_worker",
        lambda *_args: starts.append("start") or None,
    )
    lifecycle_daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    lifecycle_daemon.start()
    lifecycle_daemon._finish_service_lock.acquire()
    entered = threading.Event()
    refresh_result: dict[str, object] = {}

    def _refresh_during_shutdown() -> None:
        entered.set()
        refresh_result.update(lifecycle_daemon.refresh_command_queue_worker())

    refresh_thread = threading.Thread(target=_refresh_during_shutdown)
    refresh_thread.start()
    assert entered.wait(timeout=1)
    lifecycle_daemon._shutdown_started.set()
    lifecycle_daemon._finish_service_lock.release()
    refresh_thread.join(timeout=2)
    try:
        assert refresh_thread.is_alive() is False
        assert refresh_result["running"] is False
        assert starts == ["start"]
    finally:
        lifecycle_daemon.stop()

    old_release = threading.Event()
    old_thread = threading.Thread(target=old_release.wait)
    old_thread.start()
    old_stop = threading.Event()
    old_stop.set()
    old_worker = queue_worker_module.CommandQueueWorker(thread=old_thread, stop_event=old_stop)
    monkeypatch.setattr(queue_worker_module, "command_queue_enabled", lambda _store: True)
    monkeypatch.setattr(queue_worker_module, "_COMMAND_QUEUE_THREAD_JOIN_TIMEOUT_SECONDS", 0.01)
    try:
        assert queue_worker_module.start_command_queue_worker(store, old_worker) is old_worker
    finally:
        old_release.set()
        old_thread.join(timeout=1)
