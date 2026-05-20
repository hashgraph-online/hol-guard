"""Tests for HOL Guard supply-chain bundle verification and offline decisions."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, generate_private_key

from codex_plugin_scanner.guard.runtime.supply_chain_bundle import (
    SupplyChainBundleExpiredError,
    SupplyChainBundleKeyringError,
    SupplyChainBundleMalformedError,
    SupplyChainBundlePayloadHashError,
    SupplyChainBundleRollbackError,
    canonical_supply_chain_bundle_payload,
    evaluate_cached_supply_chain_bundle,
    load_supply_chain_bundle_response,
    verify_supply_chain_bundle_response,
)

WORKSPACE_ID = "workspace-alpha"


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _generate_key_pair() -> tuple[bytes, bytes]:
    private_key = generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def _fingerprint(public_key_pem: bytes) -> str:
    return hashlib.sha256(public_key_pem.decode("utf-8").strip().encode("utf-8")).hexdigest()


def _bundle_dict(
    *,
    bundle_version: str = "1747612800000-deadbeef",
    default_action: str = "block",
    exploit_level: str = "active",
    expires_at: datetime | None = None,
    generated_at: datetime | None = None,
    known_exploited: bool = True,
    malware_state: str = "known",
    normalized_severity: str = "critical",
    risk_score: int = 980,
) -> dict[str, object]:
    generated = generated_at or datetime(2026, 5, 19, tzinfo=timezone.utc)
    expires = expires_at or (generated + timedelta(hours=12))
    return {
        "advisories": [
            {
                "advisoryId": "GHSA-vh95-rmgr-6w4m",
                "aliases": ["CVE-2020-7598"],
                "confidence": 990,
                "exploitLevel": exploit_level,
                "knownExploited": known_exploited,
                "malwareState": "none",
                "normalizedSeverity": normalized_severity,
                "recommendedFixVersion": "1.2.9",
                "sourceKey": "ghsa",
                "summary": "Prototype pollution in minimist",
                "title": "Prototype pollution in minimist",
            }
        ],
        "bundleVersion": bundle_version,
        "expiresAt": _iso(expires),
        "feedSnapshotHash": "feed-snapshot-1",
        "generatedAt": _iso(generated),
        "keyId": "guard-bundle-key-2026-05",
        "packages": [
            {
                "confidence": 990,
                "defaultAction": default_action,
                "ecosystem": "npm",
                "exploitLevel": exploit_level,
                "knownExploited": known_exploited,
                "malwareState": malware_state,
                "name": "minimist",
                "namespace": None,
                "normalizedSeverity": normalized_severity,
                "packageAgeState": "watch",
                "purl": "pkg:npm/minimist@1.2.8",
                "reachability": "reachable",
                "recommendedFixVersion": "1.2.9",
                "relatedAdvisoryIds": ["GHSA-vh95-rmgr-6w4m"],
                "riskScore": risk_score,
                "sourceIntegrityState": "high-risk",
                "version": "1.2.8",
            }
        ],
        "policyHash": "policy-hash-1",
        "policyRules": [],
        "scoringVersion": "scf-v1",
        "sourceHashes": [
            {
                "payloadHash": "ghsa-feed-hash",
                "sourceKey": "ghsa",
                "staleStatus": "fresh",
            }
        ],
        "tier": "premium",
        "workspaceId": WORKSPACE_ID,
    }


def _sign_bundle_response(
    bundle: dict[str, object],
    *,
    private_key_pem: bytes,
    previous_keys: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    loaded_key = serialization.load_pem_private_key(private_key_pem, password=None)
    assert isinstance(loaded_key, RSAPrivateKey)
    canonical_payload = canonical_supply_chain_bundle_payload(bundle)
    payload_hash = hashlib.sha256(canonical_payload).hexdigest()
    signature = loaded_key.sign(
        canonical_payload,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    public_key_pem = loaded_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    verification_keys = [
        {
            "fingerprintSha256": _fingerprint(public_key_pem),
            "keyId": str(bundle["keyId"]),
            "publicKeyPem": public_key_pem.decode("utf-8").strip(),
            "state": "active",
            "validUntil": None,
        }
    ]
    if previous_keys:
        verification_keys.extend(previous_keys)
    return {
        "bundle": bundle,
        "payloadHash": payload_hash,
        "signature": base64.b64encode(signature).decode("utf-8"),
        "signatureAlgorithm": "rsa-pss-sha256",
        "verificationKeys": verification_keys,
    }


def test_supply_chain_bundle_verification_accepts_rotated_keyring() -> None:
    old_private_key, old_public_key = _generate_key_pair()
    first_response = load_supply_chain_bundle_response(
        json.dumps(_sign_bundle_response(_bundle_dict(), private_key_pem=old_private_key))
    )
    verify_supply_chain_bundle_response(first_response, now=first_response.bundle.generated_at_timestamp + 5)

    new_private_key, new_public_key = _generate_key_pair()
    rotated_response = load_supply_chain_bundle_response(
        json.dumps(
            _sign_bundle_response(
                _bundle_dict(bundle_version="1747616400000-rotated"),
                private_key_pem=new_private_key,
                previous_keys=[
                    {
                        "fingerprintSha256": _fingerprint(old_public_key),
                        "keyId": "guard-bundle-key-2026-04",
                        "publicKeyPem": old_public_key.decode("utf-8").strip(),
                        "state": "grace",
                        "validUntil": "2026-06-01T00:00:00Z",
                    }
                ],
            )
        )
    )

    verify_supply_chain_bundle_response(
        rotated_response,
        trusted_keys=first_response.verification_keys,
        cached_bundle_version=first_response.bundle.bundle_version,
        now=rotated_response.bundle.generated_at_timestamp + 5,
    )

    unanchored = load_supply_chain_bundle_response(
        json.dumps(
            _sign_bundle_response(
                _bundle_dict(bundle_version="1747620000000-untrusted"),
                private_key_pem=new_private_key,
            )
        )
    )

    with pytest.raises(SupplyChainBundleKeyringError):
        verify_supply_chain_bundle_response(
            unanchored,
            trusted_keys=first_response.verification_keys,
            cached_bundle_version=first_response.bundle.bundle_version,
            now=unanchored.bundle.generated_at_timestamp + 5,
        )

    assert _fingerprint(new_public_key)


def test_supply_chain_bundle_rejects_payload_hash_mismatch_and_rollback() -> None:
    private_key, _public_key = _generate_key_pair()
    response_payload = _sign_bundle_response(_bundle_dict(), private_key_pem=private_key)
    mismatched_payload = dict(response_payload)
    mismatched_payload["payloadHash"] = "bad-payload-hash"
    response = load_supply_chain_bundle_response(json.dumps(mismatched_payload))

    with pytest.raises(SupplyChainBundlePayloadHashError):
        verify_supply_chain_bundle_response(response, now=response.bundle.generated_at_timestamp + 5)

    rollback_payload = load_supply_chain_bundle_response(json.dumps(response_payload))
    with pytest.raises(SupplyChainBundleRollbackError):
        verify_supply_chain_bundle_response(
            rollback_payload,
            cached_bundle_version="1747616400000-newerhash",
            now=rollback_payload.bundle.generated_at_timestamp + 5,
        )


def test_supply_chain_bundle_rejects_expired_and_malformed_payloads() -> None:
    private_key, _public_key = _generate_key_pair()
    expired_bundle = _bundle_dict(
        generated_at=datetime(2026, 5, 18, tzinfo=timezone.utc),
        expires_at=datetime(2026, 5, 18, 1, tzinfo=timezone.utc),
    )
    expired_response = load_supply_chain_bundle_response(
        json.dumps(_sign_bundle_response(expired_bundle, private_key_pem=private_key))
    )

    with pytest.raises(SupplyChainBundleExpiredError):
        verify_supply_chain_bundle_response(
            expired_response,
            now=datetime(2026, 5, 19, tzinfo=timezone.utc).timestamp(),
        )

    malformed_payload = _sign_bundle_response(_bundle_dict(), private_key_pem=private_key)
    del malformed_payload["bundle"]["packages"]  # type: ignore[index]

    with pytest.raises(SupplyChainBundleMalformedError):
        load_supply_chain_bundle_response(json.dumps(malformed_payload))


def test_supply_chain_bundle_offline_evaluation_blocks_high_confidence_and_monitors_stale_low_risk() -> None:
    private_key, _public_key = _generate_key_pair()
    blocking_response = load_supply_chain_bundle_response(
        json.dumps(_sign_bundle_response(_bundle_dict(), private_key_pem=private_key))
    )
    blocking_decision = evaluate_cached_supply_chain_bundle(
        blocking_response,
        package_name="minimist",
        package_version="1.2.8",
        now=blocking_response.bundle.generated_at_timestamp + 60,
    )

    assert blocking_decision.action == "block"
    assert blocking_decision.stale is False
    assert blocking_decision.reason == "known_malware_or_kev"

    low_risk_bundle = _bundle_dict(
        default_action="monitor",
        exploit_level="none",
        expires_at=datetime(2026, 5, 18, 1, tzinfo=timezone.utc),
        known_exploited=False,
        malware_state="none",
        normalized_severity="low",
        risk_score=220,
    )
    low_risk_response = load_supply_chain_bundle_response(
        json.dumps(_sign_bundle_response(low_risk_bundle, private_key_pem=private_key))
    )
    stale_decision = evaluate_cached_supply_chain_bundle(
        low_risk_response,
        package_name="minimist",
        package_version="1.2.8",
        now=datetime(2026, 5, 19, tzinfo=timezone.utc).timestamp(),
    )

    assert stale_decision.action == "monitor"
    assert stale_decision.stale is True
    assert stale_decision.reason == "stale_low_confidence"
