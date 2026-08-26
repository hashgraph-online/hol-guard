from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli.oauth_client import generate_dpop_key_pair
from codex_plugin_scanner.guard.review_contracts import payload_hash_for_decision_memory_bundle
from codex_plugin_scanner.guard.runtime.command_executors import execute_guard_command_job
from codex_plugin_scanner.guard.runtime.review_policy_memory_executor import REVIEW_POLICY_MEMORY_OPERATION
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_review_signing_helpers import REVIEW_SIGNING_KEY_ID, review_verification_keys, sign_review_payload


def _store(tmp_path: Path) -> GuardStore:
    store = GuardStore(tmp_path / "guard-home")
    dpop = generate_dpop_key_pair()
    machine_id = "machine-device-policy-memory"
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="refresh-token",
        dpop_private_key_pem=dpop.private_key_pem,
        dpop_public_jwk=dpop.public_jwk,
        dpop_public_jwk_thumbprint=dpop.public_jwk_thumbprint,
        device_id=dpop.public_jwk_thumbprint,
        grant_id="grant-1",
        machine_id=machine_id,
        workspace_id="workspace-1",
        now=datetime.now(timezone.utc).isoformat(),
    )
    assert machine_id != store.get_device_metadata()["installation_id"]
    store.set_sync_payload(
        "policy_bundle_keyring",
        review_verification_keys(workspace_id=None, purpose="unscoped"),
        datetime.now(timezone.utc).isoformat(),
    )
    return store


def _bundle(store: GuardStore, *, rule_scope: str = "workspace") -> dict[str, object]:
    workspace_id = (store.get_cloud_sync_profile() or {})["workspace_id"]
    issued_at = datetime.now(timezone.utc).replace(microsecond=0)
    expires_at = issued_at + timedelta(days=30)
    bundle: dict[str, object] = {
        "blastRadius": {"artifactCount": 1, "machineCount": 1, "workspaceCount": 1},
        "bundleVersion": "review-memory-receipt-1",
        "contractVersion": "guard.decision-memory-bundle.v1",
        "expiresAt": expires_at.isoformat(),
        "issuedAt": issued_at.isoformat(),
        "issuerKeyId": REVIEW_SIGNING_KEY_ID,
        "memoryRules": [
            {
                "action": "allow",
                "approvalId": "approval-1",
                "artifactHash": "b" * 64,
                "artifactId": "plugin:hol/deploy",
                "capabilityCategory": "tool-call",
                "expiresAt": expires_at.isoformat(),
                "harnessId": "cursor",
                "projectIdentity": "project:/workspace/repo",
                "reason": "Approved in cloud.",
                "recommendedScope": "artifact",
                "riskCategory": "medium",
                "ruleId": "review-memory:receipt-1",
                "scope": rule_scope,
                "sourceReceiptIds": ["receipt-1"],
                "target": {
                    "machineIds": [str(store.get_device_metadata()["installation_id"])],
                    "workspaceIds": [workspace_id],
                },
            }
        ],
        "policyVersion": "policy-version-current",
        "revocations": [],
        "scope": "workspace",
        "scopeEvidence": {
            "approvalIds": ["approval-1"],
            "sourceReceiptHashes": ["c" * 64],
            "sourceReceiptIds": ["receipt-1"],
        },
        "verificationKeys": review_verification_keys(workspace_id=None, purpose="unscoped"),
        "signatureAlgorithm": "rsa-pss-sha256",
        "workspaceId": workspace_id,
    }
    return _resign_bundle(bundle)


def _resign_bundle(bundle: dict[str, object]) -> dict[str, object]:
    payload_hash = payload_hash_for_decision_memory_bundle(bundle)
    bundle["bundleHash"] = payload_hash
    bundle["payloadHash"] = payload_hash
    bundle["signature"] = sign_review_payload(bundle)
    return bundle


def _execute(store: GuardStore, payload: dict[str, object]) -> dict[str, object]:
    return execute_guard_command_job(
        {"operation": REVIEW_POLICY_MEMORY_OPERATION, "payload": payload},
        context=HarnessContext(home_dir=store.guard_home.parent, workspace_dir=None, guard_home=store.guard_home),
        store=store,
        now=lambda: "2026-08-24T14:00:00+00:00",
    )


def test_policy_memory_command_applies_a_signed_bundle_without_resolving_a_request(tmp_path: Path) -> None:
    store = _store(tmp_path)

    result = _execute(store, {"decisionMemoryBundle": _bundle(store)})

    data = result["data"]
    assert data["status"] == "accepted"
    assert "action" not in data
    assert store.get_sync_payload("guard_review_memory_registry") is not None
    policies = store.list_policy_decisions()
    assert len(policies) == 1
    assert policies[0]["source"] == "cloud-signed-memory"


def test_policy_memory_command_rejects_request_attachment_and_bundle_alias(tmp_path: Path) -> None:
    store = _store(tmp_path)
    bundle = _bundle(store)

    alias_result = _execute(store, {"decision_memory_bundle": bundle})
    request_result = _execute(store, {"decisionMemoryBundle": bundle, "localRequestId": "request-1"})

    assert alias_result["failureCode"] == "missing_decision_memory_bundle"
    assert request_result["failureCode"] == "review_policy_memory_local_request_forbidden"
    assert store.get_sync_payload("guard_review_memory_registry") is None


def test_policy_memory_command_reports_rejected_rules_without_updating_policy_version(tmp_path: Path) -> None:
    store = _store(tmp_path)
    bundle = _bundle(store, rule_scope="team")

    result = _execute(store, {"decisionMemoryBundle": bundle})

    data = result["data"]
    assert data["status"] == "rejected"
    ack = data["decisionMemoryAck"]
    assert isinstance(ack, dict)
    assert ack["rejectedRuleIds"] == ["review-memory:receipt-1"]
    assert store.get_sync_payload("guard_review_memory_policy_version") is None


def test_rejected_memory_bundle_keeps_existing_policies_registry_version_and_revocations_unchanged(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    assert _execute(store, {"decisionMemoryBundle": _bundle(store)})["data"]["status"] == "accepted"
    before_registry = store.get_sync_payload("guard_review_memory_registry")
    before_version = store.get_sync_payload("guard_review_memory_policy_version")
    before_policies = store.list_policy_decisions()

    rejected_bundle = _bundle(store)
    rejected_bundle["policyVersion"] = "policy-version-next"
    rejected_bundle["revocations"] = ["review-memory:receipt-1"]
    rules = rejected_bundle["memoryRules"]
    assert isinstance(rules, list) and isinstance(rules[0], dict)
    rules[0]["scope"] = "team"
    result = _execute(store, {"decisionMemoryBundle": _resign_bundle(rejected_bundle)})

    assert result["data"]["status"] == "rejected"
    assert store.get_sync_payload("guard_review_memory_registry") == before_registry
    assert store.get_sync_payload("guard_review_memory_policy_version") == before_version
    assert store.list_policy_decisions() == before_policies
