# pyright: reportMissingImports=false

from __future__ import annotations

import json
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.cli import _build_parser, _resolve_legacy_args, main
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli.oauth_client import generate_dpop_key_pair
from codex_plugin_scanner.guard.daemon import server as daemon_server_module
from codex_plugin_scanner.guard.daemon.manager import load_guard_daemon_auth_token
from codex_plugin_scanner.guard.daemon.server import GuardDaemonServer
from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.review_contracts import (
    build_local_review_request_claim,
    guard_review_oauth_metadata,
    payload_hash_for_remote_approval_envelope,
)
from codex_plugin_scanner.guard.runtime.command_capability import (
    CommandCapabilityError,
    authorize_command_job,
    issue_command_capability,
)
from codex_plugin_scanner.guard.runtime.command_executors import (
    COMMAND_OPERATION_SCHEMA_VERSIONS,
    SUPPORTED_COMMAND_OPERATIONS,
    execute_guard_command_job,
)
from codex_plugin_scanner.guard.runtime.exact_cloud_review import (
    EXACT_CLOUD_REVIEW_OPERATION,
    ExactCloudReviewError,
    apply_exact_cloud_review,
    disable_exact_cloud_review,
    enable_exact_cloud_review,
    exact_cloud_review_operations,
)
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_review_signing_helpers import (
    REVIEW_SIGNING_KEY_ID,
    review_trusted_keyring_payload,
    review_verification_keys,
    sign_review_payload,
)


def _connected_store(tmp_path: Path) -> GuardStore:
    store = GuardStore(tmp_path / "guard-home")
    dpop = generate_dpop_key_pair()
    machine_id = str(store.get_device_metadata()["installation_id"])
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="refresh-token",
        dpop_private_key_pem=dpop.private_key_pem,
        dpop_public_jwk=dpop.public_jwk,
        dpop_public_jwk_thumbprint=dpop.public_jwk_thumbprint,
        grant_id="grant-1",
        machine_id=machine_id,
        workspace_id="workspace-1",
        now=datetime.now(timezone.utc).isoformat(),
    )
    store.set_sync_payload(
        "guard_review_verification_keyring",
        review_trusted_keyring_payload(workspace_id="workspace-1"),
        datetime.now(timezone.utc).isoformat(),
    )
    return store


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
) -> dict[str, object]:
    request = store.get_approval_request(request_id)
    assert isinstance(request, dict)
    claim = build_local_review_request_claim(
        request_row=request,
        oauth=guard_review_oauth_metadata(store),
        store=store,
    )
    issued_at = issued_at or datetime.now(timezone.utc).replace(microsecond=0)
    expires_at = expires_at or issued_at + timedelta(minutes=5)
    envelope: dict[str, object] = {
        "actionEnvelopeHash": claim["actionEnvelopeHash"],
        "approvalId": claim["approvalId"],
        "capabilityCategory": claim["capabilityCategory"],
        "contractVersion": "guard.remote-approval.v1",
        "decision": decision,
        "decisionId": receipt_id,
        "deviceId": claim["deviceId"],
        "expiresAt": expires_at.isoformat(),
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
    return {
        "id": "exact-job-1",
        "leaseId": "exact-lease-1",
        "operation": EXACT_CLOUD_REVIEW_OPERATION,
        "schemaVersion": COMMAND_OPERATION_SCHEMA_VERSIONS[EXACT_CLOUD_REVIEW_OPERATION],
        "deviceId": credentials["machine_id"],
        "workspaceId": credentials["workspace_id"],
        "nonce": "exact-job-nonce",
        "createdAt": (created_at or datetime.now(timezone.utc)).isoformat(),
        "expiresAt": (expires_at or datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        "idempotencyKey": "exact-idempotency-key",
        "payload": {"harness": "codex", "remoteApproval": remote_approval},
    }


def _request_json(port: int, path: str, token: str, payload: dict[str, object]) -> tuple[int, dict[str, object]]:
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "Origin": "http://127.0.0.1:6174",
            "X-Guard-Token": token,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read().decode("utf-8"))


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
    store = _connected_store(tmp_path)
    status = enable_exact_cloud_review(store)

    assert status["enabled"] is True
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
    capability = store.get_sync_payload("guard_exact_cloud_review_capability_v1")
    assert isinstance(capability, dict)
    tampered = {**capability, "workspaceId": "other-workspace"}
    store.set_sync_payload("guard_exact_cloud_review_capability_v1", tampered, "2026-08-24T12:00:00+00:00")
    with pytest.raises(ExactCloudReviewError, match="cloud_review_capability_signature_invalid"):
        apply_exact_cloud_review(
            store,
            remote_approval=_remote_approval(store, request.request_id, receipt_id="exact-tampered"),
        )

    disable_exact_cloud_review(store)
    store.set_sync_payload("guard_exact_cloud_review_capability_v1", capability, "2026-08-24T12:00:00+00:00")
    with pytest.raises(ExactCloudReviewError, match="cloud_review_capability_revoked"):
        apply_exact_cloud_review(
            store,
            remote_approval=_remote_approval(store, request.request_id, receipt_id="exact-revoked"),
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
    request = _request("exact-queue")
    _add_request(store, request)
    enable_exact_cloud_review(store)
    job = _job(store, _remote_approval(store, request.request_id, receipt_id="exact-receipt-queue"))

    authorized = authorize_command_job(store, job, schema_versions=COMMAND_OPERATION_SCHEMA_VERSIONS)
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
    assert store.get_sync_payload("guard_review_memory_registry") is None


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
        status, payload = _request_json(
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
