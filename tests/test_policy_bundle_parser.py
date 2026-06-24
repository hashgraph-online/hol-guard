"""Policy bundle parser contract tests (HGC071-HGC075)."""

from __future__ import annotations

import base64
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from codex_plugin_scanner.guard.policy_bundle_parser import (
    canonical_policy_bundle_payload,
    computed_policy_bundle_hash,
    payload_hash_for_policy_bundle,
    validated_policy_bundle_payload,
)
from codex_plugin_scanner.guard.policy_bundle_trusted_keys import (
    policy_bundle_verification_key_from_public_key,
    validate_synced_policy_bundle,
)
from codex_plugin_scanner.guard.store import GuardStore


def _guard_store(tmp_path: Path) -> GuardStore:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    return GuardStore(guard_home)


def _sample_policy_bundle(*, bundle_hash: str | None = None) -> dict[str, object]:
    bundle: dict[str, object] = {
        "contractVersion": "guard-policy-bundle.v1",
        "bundleVersion": "policy-2026-04-19.1",
        "bundleHash": bundle_hash or "",
        "issuedAt": "2026-04-19T00:00:10+00:00",
        "expiresAt": None,
        "verifier": {
            "algorithm": "sha256",
            "keyId": "guard-policy-bundle-v1",
            "signature": None,
        },
        "rolloutState": "enforcing",
        "policyDefaults": {
            "mode": "enforce",
            "defaultAction": "warn",
            "unknownPublisherAction": "review",
            "changedHashAction": "require-reapproval",
            "newNetworkDomainAction": "warn",
            "subprocessAction": "block",
            "telemetryEnabled": False,
            "syncEnabled": True,
        },
        "rules": [
            {
                "ruleId": "pkg-block",
                "action": "block",
                "reason": "Block risky package installs before execution.",
                "matcherFamilies": ["package-request"],
                "scope": {
                    "agents": [],
                    "devices": [],
                    "ecosystems": ["npm"],
                    "environments": ["development"],
                    "harnesses": ["codex"],
                    "locations": [],
                },
            }
        ],
        "acknowledgements": [],
    }
    if bundle_hash is None:
        bundle["bundleHash"] = computed_policy_bundle_hash(bundle)
    return bundle


def _signed_policy_bundle(
    *,
    key_id: str = "guard-policy-bundle-test-key",
) -> tuple[dict[str, object], tuple[object, ...]]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key_pem = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )
    trusted_key = policy_bundle_verification_key_from_public_key(
        key_id=key_id,
        public_key_pem=public_key_pem,
    )
    bundle = _sample_policy_bundle()
    bundle["workspaceId"] = "workspace-1"
    verifier = dict(bundle["verifier"]) if isinstance(bundle["verifier"], dict) else {}
    verifier["algorithm"] = "rsa-pss-sha256"
    verifier["keyId"] = key_id
    verifier["publicKeyPem"] = public_key_pem
    verifier["signature"] = None
    bundle["verifier"] = verifier
    bundle["bundleHash"] = computed_policy_bundle_hash(bundle)
    bundle["payloadHash"] = payload_hash_for_policy_bundle(bundle)
    verifier["signature"] = base64.b64encode(
        private_key.sign(
            canonical_policy_bundle_payload(bundle),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
    ).decode("utf-8")
    bundle["verifier"] = verifier
    return bundle, (trusted_key,)


def test_hgc071_valid_policy_bundle_parses() -> None:
    bundle = _sample_policy_bundle()

    validated_bundle, reason = validated_policy_bundle_payload(bundle)

    assert reason is None
    assert validated_bundle is not None
    assert validated_bundle["bundleVersion"] == "policy-2026-04-19.1"
    assert validated_bundle["bundleHash"] == computed_policy_bundle_hash(bundle)
    assert validated_bundle["rules"] == bundle["rules"]


def test_hgc071_signed_policy_bundle_parses() -> None:
    bundle, trusted_keys = _signed_policy_bundle()

    validated_bundle, reason = validated_policy_bundle_payload(
        bundle,
        trusted_verification_keys=trusted_keys,
        anchored_verification_keys=trusted_keys,
    )

    assert reason is None
    assert validated_bundle is not None
    assert validated_bundle["workspaceId"] == "workspace-1"
    assert validated_bundle["payloadHash"] == payload_hash_for_policy_bundle(bundle)
    verifier = validated_bundle["verifier"]
    assert isinstance(verifier, dict)
    assert verifier["algorithm"] == "rsa-pss-sha256"


def test_hgc073_signed_policy_bundle_rejects_invalid_signature() -> None:
    bundle, trusted_keys = _signed_policy_bundle()
    verifier = dict(bundle["verifier"]) if isinstance(bundle["verifier"], dict) else {}
    verifier["signature"] = base64.b64encode(b"tampered-signature").decode("utf-8")
    bundle["verifier"] = verifier

    validated_bundle, reason = validated_policy_bundle_payload(
        bundle,
        trusted_verification_keys=trusted_keys,
        anchored_verification_keys=trusted_keys,
    )

    assert validated_bundle is None
    assert reason == "bundle_signature_invalid"


def test_hgc073_bundle_hash_ignores_public_key_rotation() -> None:
    first_bundle, _ = _signed_policy_bundle()
    second_bundle, _ = _signed_policy_bundle()
    first_verifier = first_bundle["verifier"]
    second_verifier = second_bundle["verifier"]

    assert isinstance(first_verifier, dict)
    assert isinstance(second_verifier, dict)

    assert first_bundle["bundleHash"] == computed_policy_bundle_hash(first_bundle)
    assert second_bundle["bundleHash"] == computed_policy_bundle_hash(second_bundle)
    assert first_bundle["bundleHash"] == second_bundle["bundleHash"]
    assert first_verifier["publicKeyPem"] != second_verifier["publicKeyPem"]


def test_hgc071_legacy_sha256_bundle_omits_workspace_id_when_unset() -> None:
    bundle = _sample_policy_bundle()

    validated_bundle, reason = validated_policy_bundle_payload(bundle)

    assert reason is None
    assert validated_bundle is not None
    assert "payloadHash" not in validated_bundle
    assert "workspaceId" not in validated_bundle


def test_hgc071_sha256_bundle_hash_ignores_public_key_field() -> None:
    bundle = _sample_policy_bundle()
    legacy_hash = computed_policy_bundle_hash(bundle)
    verifier = dict(bundle["verifier"]) if isinstance(bundle["verifier"], dict) else {}
    verifier["publicKeyPem"] = "unused-public-key"
    bundle["verifier"] = verifier

    assert computed_policy_bundle_hash(bundle) == legacy_hash


def test_hgc072_invalid_schema_rejected() -> None:
    bundle = _sample_policy_bundle()
    del bundle["rules"]

    validated_bundle, reason = validated_policy_bundle_payload(bundle)

    assert validated_bundle is None
    assert reason == "missing_required_field"


def test_hgc073_tampered_hash_rejected() -> None:
    bundle = _sample_policy_bundle(bundle_hash="sha256:tampered")

    validated_bundle, reason = validated_policy_bundle_payload(bundle)

    assert validated_bundle is None
    assert reason == "bundle_hash_mismatch"


def test_hgc073_missing_core_key_raises_for_hash() -> None:
    bundle = _sample_policy_bundle()
    del bundle["rules"]

    try:
        computed_policy_bundle_hash(bundle)
    except ValueError as exc:
        assert "missing_policy_bundle_key:rules" in str(exc)
    else:
        raise AssertionError("expected ValueError for missing policy bundle key")


def test_hgc074_persists_active_cloud_policy_version_in_guard_store(tmp_path: Path) -> None:
    home = tmp_path / "guard-home"
    store = GuardStore(home)
    bundle = _sample_policy_bundle()
    validated_bundle, reason = validated_policy_bundle_payload(bundle)

    assert reason is None
    assert validated_bundle is not None

    store.set_sync_payload("policy_bundle", validated_bundle, "2026-04-19T00:00:10+00:00")

    reopened = GuardStore(home)
    persisted = reopened.get_sync_payload("policy_bundle")

    assert isinstance(persisted, dict)
    assert persisted["bundleVersion"] == validated_bundle["bundleVersion"]


def test_hgc075_preserves_last_known_good_policy_on_invalid_update(tmp_path: Path) -> None:
    store = _guard_store(tmp_path)
    now = "2026-04-19T00:00:10+00:00"
    valid_bundle = _sample_policy_bundle()
    validated_bundle, reason = validated_policy_bundle_payload(valid_bundle)

    assert reason is None
    assert validated_bundle is not None

    store.set_sync_payload("policy_bundle", validated_bundle, now)
    store.set_sync_payload("policy_bundle_last_good", validated_bundle, now)

    invalid_bundle = dict(valid_bundle)
    del invalid_bundle["rules"]
    rejected_bundle, rejection_reason = validated_policy_bundle_payload(invalid_bundle)

    assert rejected_bundle is None
    assert rejection_reason == "missing_required_field"

    store.set_sync_payload(
        "policy_bundle_last_error",
        {"reason": rejection_reason or "invalid_policy_bundle"},
        now,
    )

    assert store.get_sync_payload("policy_bundle_last_good") == validated_bundle
    assert store.get_sync_payload("policy_bundle") == validated_bundle
    assert store.get_sync_payload("policy_bundle_last_error") == {
        "reason": "missing_required_field",
    }


def test_signed_policy_bundle_rejects_attacker_self_signed_key() -> None:
    attacker_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    attacker_public_key_pem = (
        attacker_private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )
    bundle = _sample_policy_bundle()
    bundle["workspaceId"] = "workspace-1"
    verifier = dict(bundle["verifier"]) if isinstance(bundle["verifier"], dict) else {}
    verifier["algorithm"] = "rsa-pss-sha256"
    verifier["keyId"] = "guard-policy-bundle-v1"
    verifier["publicKeyPem"] = attacker_public_key_pem
    verifier["signature"] = None
    bundle["verifier"] = verifier
    bundle["bundleHash"] = computed_policy_bundle_hash(bundle)
    bundle["payloadHash"] = payload_hash_for_policy_bundle(bundle)
    verifier["signature"] = base64.b64encode(
        attacker_private_key.sign(
            canonical_policy_bundle_payload(bundle),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
    ).decode("utf-8")
    bundle["verifier"] = verifier

    validated_bundle, reason = validated_policy_bundle_payload(bundle)

    assert validated_bundle is None
    assert reason == "untrusted_signing_key"


def test_signed_policy_bundle_accepts_trusted_sync_verification_keys() -> None:
    bundle, trusted_keys = _signed_policy_bundle()

    validated_bundle, reason = validated_policy_bundle_payload(
        bundle,
        trusted_verification_keys=trusted_keys,
        anchored_verification_keys=trusted_keys,
    )

    assert reason is None
    assert validated_bundle is not None


def test_signed_policy_bundle_rejects_sync_only_keys_without_anchor() -> None:
    bundle, trusted_keys = _signed_policy_bundle()
    sync_payload = {
        "policyBundleVerificationKeys": [trusted_keys[0].to_dict()],
    }

    validated_bundle, reason, _ = validate_synced_policy_bundle(
        bundle,
        stored_keyring=None,
        sync_payload=sync_payload,
    )

    assert validated_bundle is None
    assert reason == "untrusted_signing_key"


def test_validate_synced_policy_bundle_does_not_persist_unanchored_sync_keys() -> None:
    bundle, anchored_keys = _signed_policy_bundle(key_id="legitimate-anchor-key")
    attacker_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    attacker_public_key_pem = (
        attacker_private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )
    attacker_key = policy_bundle_verification_key_from_public_key(
        key_id="attacker-sync-key",
        public_key_pem=attacker_public_key_pem,
    )
    stored_keyring = {
        "keys": [anchored_keys[0].to_dict()],
    }
    sync_payload = {
        "policyBundleVerificationKeys": [
            anchored_keys[0].to_dict(),
            attacker_key.to_dict(),
        ],
    }

    validated_bundle, reason, persistable_keys = validate_synced_policy_bundle(
        bundle,
        stored_keyring=stored_keyring,
        sync_payload=sync_payload,
    )

    assert reason is None
    assert validated_bundle is not None
    assert {key.key_id for key in persistable_keys} == {"legitimate-anchor-key"}

    attacker_bundle = _sample_policy_bundle()
    attacker_bundle["workspaceId"] = "workspace-1"
    attacker_verifier = dict(attacker_bundle["verifier"]) if isinstance(attacker_bundle["verifier"], dict) else {}
    attacker_verifier["algorithm"] = "rsa-pss-sha256"
    attacker_verifier["keyId"] = attacker_key.key_id
    attacker_verifier["publicKeyPem"] = attacker_public_key_pem
    attacker_verifier["signature"] = None
    attacker_bundle["verifier"] = attacker_verifier
    attacker_bundle["bundleHash"] = computed_policy_bundle_hash(attacker_bundle)
    attacker_bundle["payloadHash"] = payload_hash_for_policy_bundle(attacker_bundle)
    attacker_verifier["signature"] = base64.b64encode(
        attacker_private_key.sign(
            canonical_policy_bundle_payload(attacker_bundle),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
    ).decode("utf-8")
    attacker_bundle["verifier"] = attacker_verifier

    promoted_keyring = {"keys": [item.to_dict() for item in persistable_keys]}
    promoted_bundle, promoted_reason, _ = validate_synced_policy_bundle(
        attacker_bundle,
        stored_keyring=promoted_keyring,
        sync_payload=None,
    )

    assert promoted_bundle is None
    assert promoted_reason == "untrusted_signing_key"


def test_validate_synced_policy_bundle_ignores_malformed_sync_keyring() -> None:
    bundle, trusted_keys = _signed_policy_bundle()
    stored_keyring = {
        "keys": [trusted_keys[0].to_dict()],
    }
    sync_payload = {
        "policyBundleVerificationKeys": ["not-a-key-object"],
    }

    validated_bundle, reason, _ = validate_synced_policy_bundle(
        bundle,
        stored_keyring=stored_keyring,
        sync_payload=sync_payload,
    )

    assert reason is None
    assert validated_bundle is not None


def test_signed_policy_bundle_rejects_expired_signing_key() -> None:
    bundle, trusted_keys = _signed_policy_bundle()
    expired_key = policy_bundle_verification_key_from_public_key(
        key_id=trusted_keys[0].key_id,
        public_key_pem=trusted_keys[0].public_key_pem,
        valid_until="2020-01-01T00:00:00Z",
    )

    validated_bundle, reason = validated_policy_bundle_payload(
        bundle,
        trusted_verification_keys=(expired_key,),
        anchored_verification_keys=(expired_key,),
    )

    assert validated_bundle is None
    assert reason == "untrusted_signing_key"


def test_hgc075_updates_last_known_good_on_valid_replacement(tmp_path: Path) -> None:
    store = _guard_store(tmp_path)
    now = "2026-04-19T00:00:10+00:00"
    first_bundle = _sample_policy_bundle()
    first_validated, first_reason = validated_policy_bundle_payload(first_bundle)

    assert first_reason is None
    assert first_validated is not None

    store.set_sync_payload("policy_bundle", first_validated, now)
    store.set_sync_payload("policy_bundle_last_good", first_validated, now)

    replacement_bundle = _sample_policy_bundle()
    replacement_bundle["bundleVersion"] = "policy-2026-04-20.1"
    replacement_bundle["bundleHash"] = computed_policy_bundle_hash(replacement_bundle)
    replacement_validated, replacement_reason = validated_policy_bundle_payload(replacement_bundle)

    assert replacement_reason is None
    assert replacement_validated is not None

    store.set_sync_payload("policy_bundle", replacement_validated, now)
    store.set_sync_payload("policy_bundle_last_good", replacement_validated, now)

    assert store.get_sync_payload("policy_bundle") == replacement_validated
    assert store.get_sync_payload("policy_bundle_last_good") == replacement_validated


def _sample_rule(
    rule_id: str,
    action: str,
    ecosystems: list[str],
    matcher_families: list[str] | None = None,
) -> dict[str, object]:
    return {
        "ruleId": rule_id,
        "action": action,
        "reason": f"Reason for {rule_id}.",
        "matcherFamilies": matcher_families or ["package-request"],
        "scope": {
            "agents": [],
            "devices": [],
            "ecosystems": ecosystems,
            "environments": ["development"],
            "harnesses": ["codex"],
            "locations": [],
        },
    }


def _bundle_with_rules(rules: list[dict[str, object]]) -> dict[str, object]:
    bundle = _sample_policy_bundle()
    bundle["rules"] = rules
    bundle["bundleHash"] = computed_policy_bundle_hash(bundle)
    return bundle


def test_hgps046_multi_rule_bundle_validates() -> None:
    rules = [
        _sample_rule("pkg-block", "block", ["npm"]),
        _sample_rule("mcp-allow", "allow", [], ["mcp"]),
        _sample_rule("tool-review", "review", ["python"], ["tool-action"]),
    ]
    bundle = _bundle_with_rules(rules)
    payload, reason = validated_policy_bundle_payload(bundle)
    assert payload is not None, reason
    assert len(payload["rules"]) == 3
    assert {rule["ruleId"] for rule in payload["rules"]} == {"pkg-block", "mcp-allow", "tool-review"}


def test_hgps048_multi_rule_bundle_rejects_malformed_entry() -> None:
    rules = [
        _sample_rule("pkg-block", "block", ["npm"]),
        {
            "ruleId": "bad-rule",
            "action": "not-an-action",
            "reason": "Bad action.",
            "matcherFamilies": ["package-request"],
        },
    ]
    bundle = _bundle_with_rules(rules)
    payload, reason = validated_policy_bundle_payload(bundle)
    assert payload is None
    assert reason == "invalid_rules"


def test_hgps50_sync_acknowledgement_counts_preserved() -> None:
    rules = [_sample_rule("pkg-block", "block", ["npm"])]
    acknowledgements = [
        {"deviceId": "device-a", "status": "synced"},
        {"deviceId": "device-b", "status": "pending"},
        {"deviceId": "device-c", "status": "failed"},
        {"deviceId": "device-d", "status": "offline"},
    ]
    bundle = _bundle_with_rules(rules)
    bundle["acknowledgements"] = acknowledgements
    bundle["bundleHash"] = computed_policy_bundle_hash(bundle)
    payload, reason = validated_policy_bundle_payload(bundle)
    assert payload is not None, reason
    acks = payload["acknowledgements"]
    assert len(acks) == 4
    statuses = {ack["deviceId"]: ack["status"] for ack in acks}
    assert statuses["device-a"] == "synced"
    assert statuses["device-b"] == "pending"
    assert statuses["device-c"] == "failed"
    assert statuses["device-d"] == "offline"
    assert sum(1 for ack in acks if ack["status"] == "synced") == 1
    assert sum(1 for ack in acks if ack["status"] == "pending") == 1
    assert sum(1 for ack in acks if ack["status"] == "failed") == 1


def test_hgps047_runtime_sync_persists_multi_rule_bundle(tmp_path: Path) -> None:
    store = _guard_store(tmp_path)
    now = "2026-04-19T00:00:10+00:00"
    rules = [
        _sample_rule("mcp-allow", "allow", [], ["mcp"]),
        _sample_rule("pkg-block", "block", ["npm"]),
    ]
    acknowledgements = [
        {"deviceId": "agent-1", "status": "synced"},
        {"deviceId": "agent-2", "status": "synced"},
        {"deviceId": "agent-3", "status": "pending"},
        {"deviceId": "agent-4", "status": "failed"},
    ]
    bundle = _bundle_with_rules(rules)
    bundle["acknowledgements"] = acknowledgements
    validated_bundle, reason = validated_policy_bundle_payload(bundle)

    assert reason is None
    assert validated_bundle is not None
    assert len(validated_bundle["rules"]) == 2

    store.set_sync_payload("policy_bundle", validated_bundle, now)
    reopened = GuardStore(tmp_path / "guard-home")
    persisted = reopened.get_sync_payload("policy_bundle")

    assert isinstance(persisted, dict)
    assert persisted["bundleVersion"] == validated_bundle["bundleVersion"]
    persisted_rules = persisted["rules"]
    assert isinstance(persisted_rules, list)
    assert len(persisted_rules) == 2
    persisted_acks = persisted["acknowledgements"]
    assert isinstance(persisted_acks, list)
    assert sum(1 for ack in persisted_acks if ack["status"] == "synced") == 2
    assert sum(1 for ack in persisted_acks if ack["status"] == "pending") == 1
    assert sum(1 for ack in persisted_acks if ack["status"] == "failed") == 1
