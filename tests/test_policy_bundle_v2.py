"""Signed canonical policy bundle v2 contract tests."""

from __future__ import annotations

import base64
from datetime import datetime, timezone
from pathlib import Path
from typing import cast

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from codex_plugin_scanner.guard.policy_bundle_trusted_keys import (
    PolicyBundleVerificationKey,
    policy_bundle_verification_key_from_public_key,
    validate_synced_policy_bundle,
)
from codex_plugin_scanner.guard.policy_bundle_v2 import (
    POLICY_BUNDLE_V2_CANONICALIZATION,
    POLICY_BUNDLE_V2_CONTRACT,
    canonical_policy_bundle_v2_payload,
    computed_policy_bundle_v2_hash,
    payload_hash_for_policy_bundle_v2,
    validate_policy_bundle_v2_transition,
    validated_policy_bundle_v2_acknowledgement,
    validated_policy_bundle_v2_payload,
)
from codex_plugin_scanner.guard.policy_document_yaml import load_policy_document

_FIXTURE = Path(__file__).parents[1] / "spec" / "guard-policy" / "v1alpha1" / "fixtures" / "valid" / "basic.yaml"


def _verification_key(
    private_key: rsa.RSAPrivateKey,
    *,
    key_id: str = "policy-v2-key-1",
) -> PolicyBundleVerificationKey:
    public_key_pem = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )
    return policy_bundle_verification_key_from_public_key(
        key_id=key_id,
        public_key_pem=public_key_pem,
    )


def _signed_bundle(
    private_key: rsa.RSAPrivateKey,
    verification_key: PolicyBundleVerificationKey,
    *,
    bundle_version: int = 8,
    rollback: dict[str, object] | None = None,
) -> dict[str, object]:
    document = load_policy_document(_FIXTURE)
    bundle: dict[str, object] = {
        "envelopeVersion": 2,
        "contractVersion": POLICY_BUNDLE_V2_CONTRACT,
        "bundleVersion": bundle_version,
        "bundleHash": "",
        "payloadHash": "",
        "issuedAt": "2026-07-15T12:00:00Z",
        "expiresAt": "2030-07-15T12:00:00Z",
        "workspaceId": "workspace-alpha",
        "canonicalization": POLICY_BUNDLE_V2_CANONICALIZATION,
        "verifier": {
            "algorithm": "rsa-pss-sha256",
            "keyId": verification_key.key_id,
            "keyFingerprint": verification_key.fingerprint_sha256,
            "publicKeyPem": verification_key.public_key_pem,
            "signature": "",
        },
        "payload": document.to_mapping(),
        "rollback": rollback,
    }
    bundle["payloadHash"] = payload_hash_for_policy_bundle_v2(bundle)
    bundle["bundleHash"] = computed_policy_bundle_v2_hash(bundle)
    signature = private_key.sign(
        canonical_policy_bundle_v2_payload(bundle),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    verifier = bundle["verifier"]
    assert isinstance(verifier, dict)
    verifier["signature"] = base64.b64encode(signature).decode("ascii")
    return bundle


def _acknowledgement(
    *,
    sequence: int,
    status: str,
) -> dict[str, object]:
    return {
        "contractVersion": POLICY_BUNDLE_V2_CONTRACT,
        "workspaceId": "workspace-alpha",
        "deviceId": "device-alpha",
        "bundleVersion": 8,
        "bundleHash": "sha256:bundle-alpha",
        "sequence": sequence,
        "status": status,
        "observedAt": "2026-07-15T12:01:00Z",
    }


def test_signed_v2_bundle_validates_canonical_document_and_rsa_pss_signature() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verification_key = _verification_key(private_key)
    bundle = _signed_bundle(private_key, verification_key)

    validated, reason = validated_policy_bundle_v2_payload(
        bundle,
        trusted_verification_keys=(verification_key,),
        anchored_verification_keys=(verification_key,),
        now=datetime(2026, 7, 16, tzinfo=timezone.utc),
    )

    assert reason is None
    assert validated == bundle


def test_shared_sync_validator_dispatches_v2_without_changing_v1_parser() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verification_key = _verification_key(private_key)
    bundle = _signed_bundle(private_key, verification_key)

    validated, reason, persisted_keys = validate_synced_policy_bundle(
        bundle,
        stored_keyring={"keys": [verification_key.to_dict()]},
    )

    assert reason is None
    assert validated == bundle
    assert persisted_keys == (verification_key,)


def test_v2_bundle_rejects_payload_tampering_before_apply() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verification_key = _verification_key(private_key)
    bundle = _signed_bundle(private_key, verification_key)
    payload = bundle["payload"]
    assert isinstance(payload, dict)
    metadata = cast(dict[str, object], payload["metadata"])
    assert isinstance(metadata, dict)
    metadata["revision"] = 99

    validated, reason = validated_policy_bundle_v2_payload(
        bundle,
        trusted_verification_keys=(verification_key,),
        anchored_verification_keys=(verification_key,),
        now=datetime(2026, 7, 16, tzinfo=timezone.utc),
    )

    assert validated is None
    assert reason == "payload_hash_mismatch"


def test_v2_bundle_rejects_invalid_signature() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verification_key = _verification_key(private_key)
    bundle = _signed_bundle(private_key, verification_key)
    verifier = cast(dict[str, object], bundle["verifier"])
    verifier["signature"] = "AA=="

    validated, reason = validated_policy_bundle_v2_payload(
        bundle,
        trusted_verification_keys=(verification_key,),
        anchored_verification_keys=(verification_key,),
        now=datetime(2026, 7, 16, tzinfo=timezone.utc),
    )

    assert validated is None
    assert reason == "bundle_signature_invalid"


def test_v2_bundle_rejects_expired_envelope() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verification_key = _verification_key(private_key)
    bundle = _signed_bundle(private_key, verification_key)

    validated, reason = validated_policy_bundle_v2_payload(
        bundle,
        trusted_verification_keys=(verification_key,),
        anchored_verification_keys=(verification_key,),
        now=datetime(2031, 7, 16, tzinfo=timezone.utc),
    )

    assert validated is None
    assert reason == "bundle_expired"


def test_v2_bundle_rejects_unsigned_unknown_fields() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verification_key = _verification_key(private_key)
    bundle = _signed_bundle(private_key, verification_key)
    bundle["unexpected"] = "unsigned"

    validated, reason = validated_policy_bundle_v2_payload(
        bundle,
        trusted_verification_keys=(verification_key,),
        anchored_verification_keys=(verification_key,),
        now=datetime(2026, 7, 16, tzinfo=timezone.utc),
    )

    assert validated is None
    assert reason == "unknown_field"


def test_v2_bundle_rejects_unanchored_rotated_key() -> None:
    first_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    first_key = _verification_key(first_private_key)
    rotated_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rotated_key = _verification_key(rotated_private_key, key_id="policy-v2-key-2")
    bundle = _signed_bundle(rotated_private_key, rotated_key)

    validated, reason = validated_policy_bundle_v2_payload(
        bundle,
        trusted_verification_keys=(first_key, rotated_key),
        anchored_verification_keys=(first_key,),
        now=datetime(2026, 7, 16, tzinfo=timezone.utc),
    )

    assert validated is None
    assert reason == "untrusted_signing_key"


def test_v2_transition_rejects_replay_and_same_version_substitution() -> None:
    assert (
        validate_policy_bundle_v2_transition(
            {"bundleVersion": 7, "bundleHash": "sha256:old"},
            current_bundle_version=8,
            current_bundle_hash="sha256:current",
        )
        == "bundle_downgrade_rejected"
    )
    assert (
        validate_policy_bundle_v2_transition(
            {"bundleVersion": 8, "bundleHash": "sha256:different"},
            current_bundle_version=8,
            current_bundle_hash="sha256:current",
        )
        == "bundle_version_conflict"
    )


def test_v2_transition_accepts_only_authorized_monotonic_rollback() -> None:
    rollback: dict[str, object] = {
        "rollbackOfBundleHash": "sha256:current",
        "rollbackOfBundleVersion": 8,
        "lastGoodBundleHash": "sha256:historical-good",
        "lastGoodBundleVersion": 6,
        "reason": "Restore the last verified policy.",
        "actor": "operator-alpha",
        "createdAt": "2026-07-15T12:02:00Z",
        "authorization": "approval-receipt-alpha",
    }
    incoming: dict[str, object] = {
        "bundleVersion": 9,
        "bundleHash": "sha256:rollback-envelope",
        "rollback": rollback,
    }

    assert (
        validate_policy_bundle_v2_transition(
            incoming,
            current_bundle_version=8,
            current_bundle_hash="sha256:current",
        )
        is None
    )
    rollback["rollbackOfBundleHash"] = "sha256:other"
    assert (
        validate_policy_bundle_v2_transition(
            incoming,
            current_bundle_version=8,
            current_bundle_hash="sha256:current",
        )
        == "rollback_target_mismatch"
    )


def test_v2_acknowledgement_enforces_sequence_and_state_transitions() -> None:
    received = _acknowledgement(sequence=1, status="received")
    validated = _acknowledgement(sequence=2, status="validated")
    applied = _acknowledgement(sequence=3, status="applied")

    assert validated_policy_bundle_v2_acknowledgement(received) == (received, None)
    assert validated_policy_bundle_v2_acknowledgement(
        validated,
        previous=received,
    ) == (validated, None)
    assert validated_policy_bundle_v2_acknowledgement(
        applied,
        previous=validated,
    ) == (applied, None)
    replayed, reason = validated_policy_bundle_v2_acknowledgement(
        received,
        previous=applied,
    )
    assert replayed is None
    assert reason == "acknowledgement_replay"


def test_v2_acknowledgement_rejects_sequence_conflicts_and_terminal_reapply() -> None:
    applied = _acknowledgement(sequence=3, status="applied")
    conflict = {**applied, "status": "failed"}
    retried = _acknowledgement(sequence=4, status="received")

    assert validated_policy_bundle_v2_acknowledgement(
        conflict,
        previous=applied,
    ) == (None, "acknowledgement_sequence_conflict")
    assert validated_policy_bundle_v2_acknowledgement(
        retried,
        previous=applied,
    ) == (None, "acknowledgement_transition_rejected")
