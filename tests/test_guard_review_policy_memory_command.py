from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli.oauth_client import generate_dpop_key_pair
from codex_plugin_scanner.guard.review_contracts import payload_hash_for_decision_memory_bundle
from codex_plugin_scanner.guard.runtime.command_executors import execute_guard_command_job
from codex_plugin_scanner.guard.runtime.review_policy_memory_executor import (
    REVIEW_POLICY_MEMORY_OPERATION,
    execute_review_policy_memory,
    native_review_policy_memory_actions,
)
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_policy import StorePolicyMixin
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
    local_installation_id = store.get_device_metadata()["installation_id"]
    # The enrolled machineId, the local installation UUID, and the server
    # transport-owner UUID are three distinct identities; none may alias another.
    assert machine_id != local_installation_id
    assert machine_id != _TRANSPORT_OWNER
    assert str(local_installation_id) != _TRANSPORT_OWNER
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
                "capabilityCategory": "command",
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
                    "machineIds": [str(store.get_oauth_local_credentials(allow_primary=False)["machine_id"])],
                    "workspaceIds": [workspace_id],
                },
                "exactCommand": {
                    "contractVersion": "guard.exact-command.v1",
                    "sha256": hashlib.sha256(b"git status --short").hexdigest(),
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


_TRANSPORT_OWNER = "67c1a86b-8d31-407a-b560-ef8c68a6e931"


def _execute(store: GuardStore, payload: dict[str, object]) -> dict[str, object]:
    bundle = payload.get("decisionMemoryBundle")
    if isinstance(bundle, dict) and "expectedApplication" not in payload:
        oauth = store.get_oauth_local_credentials(allow_primary=False)
        payload = {
            **payload,
            "expectedApplication": {
                "bundleHash": bundle["bundleHash"],
                "bundleVersion": bundle["bundleVersion"],
                "deviceId": oauth["device_id"],
                "machineId": oauth["machine_id"],
                "machineInstallationId": _TRANSPORT_OWNER,
                "policyVersion": bundle["policyVersion"],
                "workspaceId": oauth["workspace_id"],
            },
        }
    return execute_guard_command_job(
        {
            "operation": REVIEW_POLICY_MEMORY_OPERATION,
            "payload": payload,
            "targetMachineInstallationId": _TRANSPORT_OWNER,
        },
        context=HarnessContext(home_dir=store.guard_home.parent, workspace_dir=None, guard_home=store.guard_home),
        store=store,
        now=lambda: "2026-08-24T14:00:00+00:00",
    )


@pytest.mark.parametrize(
    "selector",
    [
        None,
        {"contractVersion": "guard.exact-command.v1", "sha256": "not-a-digest"},
        {"contractVersion": "guard.exact-command.v1", "sha256": "a" * 64, "extra": True},
    ],
)
def test_command_memory_cannot_fall_back_to_broad_artifact_matching(tmp_path: Path, selector: object) -> None:
    store = _store(tmp_path)
    bundle = _bundle(store)
    bundle["memoryRules"][0]["exactCommand"] = selector

    result = _execute(store, {"decisionMemoryBundle": _resign_bundle(bundle)})
    assert result["data"]["status"] == "rejected"
    assert result["data"]["decisionMemoryAck"]["appliedRuleCount"] == 0
    assert store.get_sync_payload("guard_review_memory_registry") is None

    assert store.get_sync_payload("guard_review_memory_policy_version") is None


def test_registry_row_copy_cannot_widen_the_retained_signed_rule(tmp_path: Path) -> None:
    store = _store(tmp_path)
    _execute(store, {"decisionMemoryBundle": _bundle(store)})
    registry = store.get_sync_payload("guard_review_memory_registry")
    registry[0]["decision"]["artifact_id"] = "plugin:codex:dep"
    store.set_sync_payload("guard_review_memory_registry", registry, "2026-08-24T14:00:00+00:00")

    with pytest.raises(ValueError, match="decision_memory_registry_projection_mismatch"):
        native_review_policy_memory_actions(store)


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


def test_accepted_memory_bundle_rolls_back_rows_and_state_on_transaction_failure(
    tmp_path: Path,
    monkeypatch,
) -> None:
    store = _store(tmp_path)
    assert _execute(store, {"decisionMemoryBundle": _bundle(store)})["data"]["status"] == "accepted"
    before_registry = store.get_sync_payload("guard_review_memory_registry")
    before_version = store.get_sync_payload("guard_review_memory_policy_version")
    before_ack = store.get_sync_payload("guard_review_memory_last_ack")
    before_policies = store.list_policy_decisions()
    original = StorePolicyMixin._replace_remote_policy_rows_locked

    def replace_then_fail(connection, rows, *, sources) -> None:
        original(connection, rows, sources=sources)
        raise RuntimeError("injected policy-memory transaction failure")

    monkeypatch.setattr(StorePolicyMixin, "_replace_remote_policy_rows_locked", staticmethod(replace_then_fail))
    next_bundle = _bundle(store)
    next_bundle["policyVersion"] = "policy-version-next"

    with pytest.raises(RuntimeError, match="injected policy-memory transaction failure"):
        _execute(store, {"decisionMemoryBundle": _resign_bundle(next_bundle)})

    assert store.get_sync_payload("guard_review_memory_registry") == before_registry
    assert store.get_sync_payload("guard_review_memory_policy_version") == before_version
    assert store.get_sync_payload("guard_review_memory_last_ack") == before_ack
    assert store.list_policy_decisions() == before_policies


@pytest.mark.parametrize("owner", [None, "f" * 32, "dc668358-2a3e-42cf-b77f-e8b8d0f5e2b7"])
def test_memory_transport_ack_requires_exact_leased_owner(tmp_path: Path, owner: object) -> None:
    store = _store(tmp_path)
    bundle = _bundle(store)
    oauth = store.get_oauth_local_credentials(allow_primary=False)
    payload = {
        "decisionMemoryBundle": bundle,
        "expectedApplication": {
            "bundleHash": bundle["bundleHash"],
            "bundleVersion": bundle["bundleVersion"],
            "deviceId": oauth["device_id"],
            "machineId": oauth["machine_id"],
            "machineInstallationId": _TRANSPORT_OWNER,
            "policyVersion": bundle["policyVersion"],
            "workspaceId": oauth["workspace_id"],
        },
    }
    with pytest.raises(ValueError, match=r"decision_memory_(transport_owner|application_identity)"):
        execute_review_policy_memory(
            payload, store=store, generated_at="2026-08-24T14:00:00+00:00", machine_installation_id=owner
        )
    assert store.get_sync_payload("guard_review_memory_registry") is None
    assert store.get_sync_payload("guard_review_memory_last_ack") is None


def test_server_installation_uuid_is_not_an_sdk_machine_target_alias(tmp_path: Path) -> None:
    store = _store(tmp_path)
    bundle = _bundle(store)
    bundle["memoryRules"][0]["target"]["machineIds"] = [_TRANSPORT_OWNER]
    oauth = store.get_oauth_local_credentials(allow_primary=False)
    payload = {
        "decisionMemoryBundle": _resign_bundle(bundle),
        "expectedApplication": {
            "bundleHash": bundle["bundleHash"],
            "bundleVersion": bundle["bundleVersion"],
            "deviceId": oauth["device_id"],
            "machineId": oauth["machine_id"],
            "machineInstallationId": _TRANSPORT_OWNER,
            "policyVersion": bundle["policyVersion"],
            "workspaceId": oauth["workspace_id"],
        },
    }
    with pytest.raises(ValueError, match="machine"):
        execute_review_policy_memory(
            payload,
            store=store,
            generated_at="2026-08-24T14:00:00+00:00",
            machine_installation_id=_TRANSPORT_OWNER,
        )
    assert store.get_sync_payload("guard_review_memory_registry") is None


def test_signed_actual_enrolled_machine_target_is_admitted_and_retained(tmp_path: Path) -> None:
    """A bundle signed for the enrolled OAuth machineId is admitted and retained.

    The enrolled machineId, the local installation UUID, and the server
    transport-owner UUID all differ; only the machineId may satisfy the signed
    target while the transport owner and device bindings stay independently
    verified.
    """

    store = _store(tmp_path)
    bundle = _bundle(store)
    oauth = store.get_oauth_local_credentials(allow_primary=False)
    local_installation_id = store.get_device_metadata()["installation_id"]
    signed_machine = str(oauth["machine_id"])
    assert signed_machine != str(local_installation_id)
    assert signed_machine != _TRANSPORT_OWNER
    assert bundle["memoryRules"][0]["target"]["machineIds"] == [signed_machine]

    result = _execute(store, {"decisionMemoryBundle": bundle})

    data = result["data"]
    assert data["status"] == "accepted"
    ack = data["decisionMemoryAck"]
    assert ack["status"] == "accepted"
    assert ack["machineId"] == signed_machine
    assert ack["machineInstallationId"] == _TRANSPORT_OWNER
    registry = store.get_sync_payload("guard_review_memory_registry")
    assert isinstance(registry, list) and len(registry) == 1

    actions = native_review_policy_memory_actions(store)
    sha = bundle["memoryRules"][0]["exactCommand"]["sha256"]
    assert [action["command_sha256"] for action in actions] == [sha]
    assert [action["cloud_workspace_id"] for action in actions] == [bundle["workspaceId"]]


@pytest.mark.parametrize(
    "selector",
    [
        "local_installation_uuid",
        "server_installation_uuid",
    ],
)
def test_non_enrolled_machine_selector_is_rejected_with_unchanged_store(tmp_path: Path, selector: str) -> None:
    """Signing the local installation UUID or the server transport-owner UUID
    instead of the enrolled machineId is rejected without mutating the store."""

    store = _store(tmp_path)
    wrong = (
        str(store.get_device_metadata()["installation_id"])
        if selector == "local_installation_uuid"
        else _TRANSPORT_OWNER
    )
    enrolled = str(store.get_oauth_local_credentials(allow_primary=False)["machine_id"])
    assert wrong != enrolled
    bundle = _bundle(store)
    bundle["memoryRules"][0]["target"]["machineIds"] = [wrong]

    result = _execute(store, {"decisionMemoryBundle": _resign_bundle(bundle)})

    assert result["failureCode"] == "decision_memory_machine_mismatch"
    assert store.get_sync_payload("guard_review_memory_registry") is None
    assert store.get_sync_payload("guard_review_memory_policy_version") is None
    assert store.get_sync_payload("guard_review_memory_last_ack") is None


def test_retained_signed_rule_machine_target_is_revalidated_at_native_publish(tmp_path: Path) -> None:
    """The retained registry re-runs the signed machine-target check at native
    publish. A retained sourceBundle whose signed machineIds no longer names the
    enrolled machine fails closed and publishes no native action."""

    store = _store(tmp_path)
    bundle = _bundle(store)
    assert _execute(store, {"decisionMemoryBundle": bundle})["data"]["status"] == "accepted"
    assert native_review_policy_memory_actions(store)

    # Rewrite the retained signed rule's machine target to a non-enrolled id and
    # re-sign it: the retained path must re-derive oauth.machine_id, not trust
    # the stored row, and must reject before publishing native authority.
    registry = store.get_sync_payload("guard_review_memory_registry")
    source_bundle = dict(registry[0]["sourceBundle"])
    rule = dict(source_bundle["memoryRules"][0])
    foreign_machine = "machine-foreign-not-enrolled"
    enrolled = str(store.get_oauth_local_credentials(allow_primary=False)["machine_id"])
    assert foreign_machine != enrolled
    rule["target"] = {"machineIds": [foreign_machine], "workspaceIds": rule["target"]["workspaceIds"]}
    source_bundle["memoryRules"] = [rule]
    source_bundle = _resign_bundle(source_bundle)
    registry[0]["sourceBundle"] = source_bundle
    store.set_sync_payload("guard_review_memory_registry", registry, "2026-08-24T14:00:00+00:00")

    with pytest.raises(ValueError, match="decision_memory_machine_mismatch"):
        native_review_policy_memory_actions(store)
