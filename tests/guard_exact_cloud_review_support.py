from __future__ import annotations

import json
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

from codex_plugin_scanner.guard.cli.oauth_client import generate_dpop_key_pair
from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.review_contracts import (
    build_local_review_request_claim,
    payload_hash_for_remote_approval_envelope,
)
from codex_plugin_scanner.guard.runtime.command_executors import (
    COMMAND_OPERATION_SCHEMA_VERSIONS,
)
from codex_plugin_scanner.guard.runtime.exact_cloud_review import (
    EXACT_CLOUD_REVIEW_OPERATION,
    _oauth_metadata,
)
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_oauth_token_support import oauth_binding_access_token
from tests.guard_review_signing_helpers import (
    REVIEW_SIGNING_KEY_ID,
    review_trusted_keyring_payload,
    review_verification_keys,
    sign_review_payload,
)


def connected_exact_review_store(
    tmp_path: Path,
    *,
    missing_device_id: bool = False,
) -> GuardStore:
    store = GuardStore(tmp_path / "guard-home")
    dpop = generate_dpop_key_pair()
    machine_id = "machine-device-fixture"
    now = datetime.now(timezone.utc).isoformat()
    bound_device_id = dpop.public_jwk_thumbprint
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="refresh-token",
        dpop_private_key_pem=dpop.private_key_pem,
        dpop_public_jwk=dpop.public_jwk,
        dpop_public_jwk_thumbprint=bound_device_id,
        grant_id="grant-1",
        machine_id=machine_id,
        device_id=None if missing_device_id else bound_device_id,
        workspace_id="workspace-1",
        access_token=oauth_binding_access_token(
            device_id=bound_device_id,
            grant_id="grant-1",
            machine_id=machine_id,
            workspace_id="workspace-1",
        ),
        access_token_expires_at="2099-01-01T00:00:00+00:00",
        now=now,
    )
    store.set_sync_payload(
        "guard_review_verification_keyring",
        review_trusted_keyring_payload(workspace_id="workspace-1"),
        now,
    )
    return store


def review_request(request_id: str, *, harness: str = "codex") -> GuardApprovalRequest:
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


def add_review_request(store: GuardStore, request: GuardApprovalRequest) -> None:
    store.add_approval_request(request, datetime.now(timezone.utc).isoformat())


def remote_approval(
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


def exact_review_job(
    store: GuardStore,
    approval: dict[str, object],
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
        "payload": {"harness": "codex", "remoteApproval": approval},
    }


def post_json(port: int, path: str, token: str, payload: dict[str, object]) -> tuple[int, dict[str, object]]:
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


__all__ = [
    "add_review_request",
    "connected_exact_review_store",
    "exact_review_job",
    "post_json",
    "remote_approval",
    "review_request",
]
