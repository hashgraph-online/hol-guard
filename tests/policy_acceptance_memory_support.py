"""Signed policy-memory inputs used by runtime acceptance scenarios."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from codex_plugin_scanner.guard.cli.oauth_client import generate_dpop_key_pair
from codex_plugin_scanner.guard.review_contracts import payload_hash_for_decision_memory_bundle
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_review_signing_helpers import REVIEW_SIGNING_KEY_ID, review_verification_keys, sign_review_payload
from tests.policy_bundle_signing_helpers import policy_bundle_test_keyring

_WORKSPACE = "workspace-acceptance"
_NOW = "2026-09-17T12:00:00+00:00"


def _memory_bundle(
    store: GuardStore, *, version: str, artifact_id: str, revocations: list[str] | None = None
) -> dict[str, object]:
    issued_at = datetime.now(timezone.utc).replace(microsecond=0)
    bundle: dict[str, object] = {
        "blastRadius": {"artifactCount": 1, "machineCount": 1, "workspaceCount": 1},
        "bundleVersion": version,
        "contractVersion": "guard.decision-memory-bundle.v1",
        "expiresAt": (issued_at + timedelta(days=30)).isoformat(),
        "issuedAt": issued_at.isoformat(),
        "issuerKeyId": REVIEW_SIGNING_KEY_ID,
        "memoryRules": []
        if revocations
        else [
            {
                "action": "allow",
                "approvalId": "memory-approval-1",
                "artifactHash": "b" * 64,
                "artifactId": artifact_id,
                "capabilityCategory": "tool-call",
                "expiresAt": (issued_at + timedelta(days=30)).isoformat(),
                "harnessId": "codex",
                "projectIdentity": "project:/workspace/repo",
                "reason": "Remembered in cloud.",
                "recommendedScope": "artifact",
                "riskCategory": "medium",
                "ruleId": "review-memory:acceptance-1",
                "scope": "artifact",
                "sourceReceiptIds": ["receipt-memory-1"],
                "target": {
                    "machineIds": [str(store.get_device_metadata()["installation_id"])],
                    "workspaceIds": [_WORKSPACE],
                },
            }
        ],
        "policyVersion": version,
        "revocations": revocations or [],
        "scope": "workspace",
        "scopeEvidence": {
            "approvalIds": ["memory-approval-1"],
            "sourceReceiptHashes": ["c" * 64],
            "sourceReceiptIds": ["receipt-memory-1"],
        },
        "verificationKeys": review_verification_keys(workspace_id=None, purpose="unscoped"),
        "signatureAlgorithm": "rsa-pss-sha256",
        "workspaceId": _WORKSPACE,
    }
    payload_hash = payload_hash_for_decision_memory_bundle(bundle)
    bundle["bundleHash"] = payload_hash
    bundle["payloadHash"] = payload_hash
    bundle["signature"] = sign_review_payload(bundle)
    return bundle


def _enable_memory_keys(store: GuardStore) -> None:
    dpop = generate_dpop_key_pair()
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="synthetic-refresh-token",
        dpop_private_key_pem=dpop.private_key_pem,
        dpop_public_jwk=dpop.public_jwk,
        dpop_public_jwk_thumbprint=dpop.public_jwk_thumbprint,
        device_id=dpop.public_jwk_thumbprint,
        grant_id="synthetic-memory-grant",
        machine_id="machine-" + str(store.get_device_metadata()["installation_id"]),
        workspace_id=_WORKSPACE,
        now=_NOW,
    )
    store.set_sync_payload(
        "policy_bundle_keyring",
        policy_bundle_test_keyring(workspace_id=_WORKSPACE),
        _NOW,
    )
    store.set_sync_payload(
        "guard_review_verification_keyring",
        review_verification_keys(workspace_id=None, purpose="unscoped"),
        _NOW,
    )
