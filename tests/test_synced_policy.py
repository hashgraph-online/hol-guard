"""Cached cloud-policy authority tests shared by runtime config consumers."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from codex_plugin_scanner.guard.config import GuardConfig, overlay_synced_guard_policy
from codex_plugin_scanner.guard.policy_bundle_parser import (
    computed_policy_bundle_hash,
    payload_hash_for_policy_bundle,
)
from codex_plugin_scanner.guard.synced_policy import (
    synced_policy_bundle_validation,
    synced_policy_payload,
    validated_synced_policy_bundle,
)
from tests.policy_bundle_signing_helpers import policy_bundle_test_keyring, sign_policy_bundle

_WORKSPACE_ID = "workspace-1"
_SYNCED_AT = "2026-07-01T00:00:00Z"


@dataclass
class _MemorySyncStore:
    payloads: dict[str, dict[str, object] | list[object]]
    workspace_id: str | None = _WORKSPACE_ID

    def get_sync_payload(self, state_key: str) -> dict[str, object] | list[object] | None:
        return self.payloads.get(state_key)

    def get_cloud_workspace_id(self) -> str | None:
        return self.workspace_id


def _signed_policy_bundle() -> dict[str, object]:
    return sign_policy_bundle(
        {
            "contractVersion": "guard-policy-bundle.v1",
            "bundleVersion": "policy-2026-07-01.1",
            "bundleHash": "",
            "issuedAt": _SYNCED_AT,
            "expiresAt": None,
            "verifier": {
                "algorithm": "rsa-pss-sha256",
                "keyId": "test-only-placeholder",
                "signature": None,
            },
            "rolloutState": "enforcing",
            "receiptRedactionLevel": "none",
            "policyDefaults": {
                "mode": "observe",
                "defaultAction": "allow",
                "unknownPublisherAction": "review",
                "changedHashAction": "require-reapproval",
                "newNetworkDomainAction": "allow",
                "subprocessAction": "allow",
                "telemetryEnabled": False,
                "syncEnabled": True,
            },
            "rules": [],
            "acknowledgements": [],
        },
        workspace_id=_WORKSPACE_ID,
    )


def _local_block_config(tmp_path: Path) -> GuardConfig:
    return GuardConfig(
        guard_home=tmp_path / "guard-home",
        workspace=tmp_path / "workspace",
        mode="enforce",
        default_action="block",
        new_network_domain_action="block",
        subprocess_action="block",
    )


def test_present_digest_only_bundle_cannot_fall_back_to_unsigned_policy(tmp_path: Path) -> None:
    digest_only_bundle = _signed_policy_bundle()
    digest_only_bundle["verifier"] = {
        "algorithm": "sha256",
        "keyId": "attacker-recomputed-digest",
        "signature": None,
    }
    digest_only_bundle["bundleHash"] = computed_policy_bundle_hash(digest_only_bundle)
    digest_only_bundle["payloadHash"] = payload_hash_for_policy_bundle(digest_only_bundle)
    unsigned_legacy_policy: dict[str, object] = {
        "mode": "observe",
        "defaultAction": "allow",
        "receiptRedactionLevel": "none",
    }
    store = _MemorySyncStore(
        {
            "policy_bundle": digest_only_bundle,
            "policy_bundle_keyring": policy_bundle_test_keyring(workspace_id=_WORKSPACE_ID),
            "policy": unsigned_legacy_policy,
        }
    )

    payload = synced_policy_payload(store)
    effective_config = overlay_synced_guard_policy(_local_block_config(tmp_path), payload)

    assert synced_policy_bundle_validation(store) == (None, "unsupported_signature_algorithm")
    assert validated_synced_policy_bundle(store) is None
    assert payload is None
    assert effective_config.mode == "enforce"
    assert effective_config.default_action == "block"
    assert effective_config.new_network_domain_action == "block"
    assert effective_config.subprocess_action == "block"
    assert effective_config.receipt_redaction_level == "full"


def test_absent_bundle_cannot_promote_unsigned_legacy_policy(tmp_path: Path) -> None:
    legacy_policy: dict[str, object] = {"mode": "observe", "defaultAction": "allow"}
    store = _MemorySyncStore({"policy": legacy_policy})
    cleared_store = _MemorySyncStore({"policy_bundle": {}, "policy": legacy_policy})

    payload = synced_policy_payload(store)
    effective_config = overlay_synced_guard_policy(_local_block_config(tmp_path), payload)

    assert synced_policy_bundle_validation(store) == (None, None)
    assert synced_policy_bundle_validation(cleared_store) == (None, None)
    assert validated_synced_policy_bundle(store) is None
    assert payload is None
    assert synced_policy_payload(cleared_store) is None
    assert effective_config.mode == "enforce"
    assert effective_config.default_action == "block"


def test_cached_pinned_signature_can_supply_runtime_config(tmp_path: Path) -> None:
    signed_bundle = _signed_policy_bundle()
    store = _MemorySyncStore(
        {
            "policy_bundle": signed_bundle,
            "policy_bundle_keyring": policy_bundle_test_keyring(workspace_id=_WORKSPACE_ID),
            "policy": {"mode": "enforce", "defaultAction": "block"},
        }
    )

    payload = synced_policy_payload(store)
    validated_bundle, rejection_reason = synced_policy_bundle_validation(store)
    effective_config = overlay_synced_guard_policy(_local_block_config(tmp_path), payload)

    assert validated_bundle is not None
    assert rejection_reason is None
    assert validated_bundle["bundleHash"] == signed_bundle["bundleHash"]
    assert payload is not None
    assert payload["updatedAt"] == _SYNCED_AT
    assert payload["bundleHash"] == signed_bundle["bundleHash"]
    assert payload["bundleVersion"] == signed_bundle["bundleVersion"]
    assert effective_config.mode == "observe"
    assert effective_config.default_action == "allow"
    assert effective_config.new_network_domain_action == "allow"
    assert effective_config.subprocess_action == "allow"
    assert effective_config.receipt_redaction_level == "none"
