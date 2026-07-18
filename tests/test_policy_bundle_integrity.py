"""Signed policy bundle integrity validation tests."""

from __future__ import annotations

import base64

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
)


def _signed_policy_bundle() -> tuple[dict[str, object], tuple[object, ...]]:
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
        key_id="guard-policy-bundle-test-key",
        public_key_pem=public_key_pem,
    )
    bundle: dict[str, object] = {
        "contractVersion": "guard-policy-bundle.v1",
        "workspaceId": "workspace-1",
        "bundleVersion": "policy-2026-04-19.1",
        "bundleHash": "",
        "issuedAt": "2026-04-19T00:00:10+00:00",
        "expiresAt": None,
        "verifier": {
            "algorithm": "rsa-pss-sha256",
            "keyId": trusted_key.key_id,
            "publicKeyPem": public_key_pem,
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
        "rules": [],
        "acknowledgements": [],
    }
    bundle["bundleHash"] = computed_policy_bundle_hash(bundle)
    bundle["payloadHash"] = payload_hash_for_policy_bundle(bundle)
    verifier = dict(bundle["verifier"])
    verifier["signature"] = base64.b64encode(
        private_key.sign(
            canonical_policy_bundle_payload(bundle),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
    ).decode("utf-8")
    bundle["verifier"] = verifier
    return bundle, (trusted_key,)


def test_hgc073_signed_policy_bundle_rejects_payload_hash_mismatch() -> None:
    bundle, trusted_keys = _signed_policy_bundle()
    bundle["payloadHash"] = f"sha256:{'0' * 64}"

    validated_bundle, reason = validated_policy_bundle_payload(
        bundle,
        trusted_verification_keys=trusted_keys,
        anchored_verification_keys=trusted_keys,
    )

    assert validated_bundle is None
    assert reason == "payload_hash_mismatch"


def test_hgc073_signed_policy_bundle_rejects_invalid_payload_hash() -> None:
    for payload_hash in (None, "", 123):
        bundle, trusted_keys = _signed_policy_bundle()
        bundle["payloadHash"] = payload_hash

        validated_bundle, reason = validated_policy_bundle_payload(
            bundle,
            trusted_verification_keys=trusted_keys,
            anchored_verification_keys=trusted_keys,
        )

        assert validated_bundle is None
        assert reason == "payload_hash_invalid"
