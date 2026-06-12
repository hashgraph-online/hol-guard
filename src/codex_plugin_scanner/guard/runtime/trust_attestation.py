from __future__ import annotations

import base64
import hashlib
import json
import os
from collections.abc import Mapping
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

GUARD_TRUST_ATTESTATION_PAYLOAD_VERSION = "guard-aibom-trust-attestation.v1"
GUARD_TRUST_ATTESTATION_SIGNATURE_ALGORITHM = "rsa-pss-sha256"


@dataclass(frozen=True, slots=True)
class GuardTrustAttestationSigningConfig:
    active_key_id: str
    private_key_pem: str


@dataclass(frozen=True, slots=True)
class GuardTrustAttestationVerificationKey:
    key_id: str
    public_key_pem: str
    fingerprint_sha256: str


def canonical_trust_attestation_payload(payload: Mapping[str, object]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def payload_hash_for_trust_attestation(payload: Mapping[str, object]) -> str:
    return hashlib.sha256(canonical_trust_attestation_payload(payload)).hexdigest()


def resolve_trust_attestation_signing_config(
    environ: Mapping[str, str] | None = None,
) -> GuardTrustAttestationSigningConfig | None:
    env = environ or os.environ
    active_key_id = _sanitize_env(env.get("GUARD_AIBOM_TRUST_ATTESTATION_KEY_ID")) or "guard-aibom-trust-key-default"
    private_key_pem = _normalize_pem(
        _sanitize_env(env.get("GUARD_AIBOM_TRUST_ATTESTATION_PRIVATE_KEY"))
    )
    if not private_key_pem:
        return None
    return GuardTrustAttestationSigningConfig(
        active_key_id=active_key_id,
        private_key_pem=private_key_pem,
    )


def build_trust_attestation_verification_key(
    config: GuardTrustAttestationSigningConfig,
) -> GuardTrustAttestationVerificationKey:
    private_key = _load_private_key(config.private_key_pem)
    public_key_pem = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
        .strip()
    )
    return GuardTrustAttestationVerificationKey(
        key_id=config.active_key_id,
        public_key_pem=public_key_pem,
        fingerprint_sha256=_public_key_fingerprint(public_key_pem),
    )


def build_trust_attestation_payload(
    *,
    agent_id: str,
    item_id: str,
    item_kind: str,
    content_hash: str,
    captured_at: str,
    evidence_hash: str,
    scope: str,
    layer_id: str | None = None,
    layer_type: str | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "payloadVersion": GUARD_TRUST_ATTESTATION_PAYLOAD_VERSION,
        "agentId": agent_id,
        "itemId": item_id,
        "itemKind": item_kind,
        "contentHash": content_hash,
        "capturedAt": captured_at,
        "evidenceHash": evidence_hash,
        "scope": scope,
    }
    if layer_id is not None:
        payload["layerId"] = layer_id
    if layer_type is not None:
        payload["layerType"] = layer_type
    return payload


def sign_trust_attestation(
    *,
    payload: Mapping[str, object],
    config: GuardTrustAttestationSigningConfig,
    signed_at: str,
) -> dict[str, object]:
    private_key = _load_private_key(config.private_key_pem)
    canonical_payload = canonical_trust_attestation_payload(payload)
    signature = private_key.sign(
        canonical_payload,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    verification_key = build_trust_attestation_verification_key(config)
    return {
        "payloadVersion": GUARD_TRUST_ATTESTATION_PAYLOAD_VERSION,
        "payloadHash": hashlib.sha256(canonical_payload).hexdigest(),
        "signature": base64.b64encode(signature).decode("ascii"),
        "signatureAlgorithm": GUARD_TRUST_ATTESTATION_SIGNATURE_ALGORITHM,
        "signedAt": signed_at,
        "keyId": verification_key.key_id,
        "publicKeyPem": verification_key.public_key_pem,
        "fingerprintSha256": verification_key.fingerprint_sha256,
    }


def verify_trust_attestation(
    *,
    payload: Mapping[str, object],
    envelope: Mapping[str, object],
    trusted_keys: tuple[GuardTrustAttestationVerificationKey, ...] | None = None,
) -> None:
    raw_payload_hash = envelope.get("payloadHash")
    raw_signature_algorithm = envelope.get("signatureAlgorithm")
    raw_key_id = envelope.get("keyId")
    raw_public_key_pem = envelope.get("publicKeyPem")
    raw_fingerprint_sha256 = envelope.get("fingerprintSha256")
    raw_signature = envelope.get("signature")
    if not isinstance(raw_payload_hash, str) or not raw_payload_hash:
        raise ValueError("Trust attestation envelope is incomplete")
    if not isinstance(raw_signature_algorithm, str) or not raw_signature_algorithm:
        raise ValueError("Trust attestation envelope is incomplete")
    if not isinstance(raw_key_id, str) or not raw_key_id:
        raise ValueError("Trust attestation envelope is incomplete")
    if not isinstance(raw_public_key_pem, str) or not raw_public_key_pem:
        raise ValueError("Trust attestation envelope is incomplete")
    if not isinstance(raw_fingerprint_sha256, str) or not raw_fingerprint_sha256:
        raise ValueError("Trust attestation envelope is incomplete")
    if not isinstance(raw_signature, str) or not raw_signature:
        raise ValueError("Trust attestation envelope is incomplete")
    payload_hash: str = raw_payload_hash
    signature_algorithm: str = raw_signature_algorithm
    key_id: str = raw_key_id
    public_key_pem: str = raw_public_key_pem
    fingerprint_sha256: str = raw_fingerprint_sha256
    signature: str = raw_signature
    if signature_algorithm != GUARD_TRUST_ATTESTATION_SIGNATURE_ALGORITHM:
        raise ValueError("Unsupported trust attestation signature algorithm")
    canonical_payload = canonical_trust_attestation_payload(payload)
    if hashlib.sha256(canonical_payload).hexdigest() != payload_hash:
        raise ValueError("Trust attestation payload hash mismatch")
    if _public_key_fingerprint(public_key_pem) != fingerprint_sha256:
        raise ValueError("Trust attestation public key fingerprint mismatch")
    if trusted_keys is not None and not any(
        trusted_key.key_id == key_id
        and trusted_key.fingerprint_sha256 == fingerprint_sha256
        and _normalize_pem(trusted_key.public_key_pem) == _normalize_pem(public_key_pem)
        for trusted_key in trusted_keys
    ):
        raise ValueError("Trust attestation key is not trusted")
    public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    if not isinstance(public_key, RSAPublicKey):
        raise ValueError("Trust attestation public key must be RSA")
    try:
        public_key.verify(
            base64.b64decode(signature),
            canonical_payload,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
    except InvalidSignature as exc:
        raise ValueError("Trust attestation signature verification failed") from exc


def _load_private_key(private_key_pem: str) -> RSAPrivateKey:
    private_key = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
    if not isinstance(private_key, RSAPrivateKey):
        raise ValueError("Trust attestation private key must be RSA")
    return private_key


def _public_key_fingerprint(public_key_pem: str) -> str:
    normalized_pem = _normalize_pem(public_key_pem)
    return hashlib.sha256(normalized_pem.encode("utf-8")).hexdigest()


def _sanitize_env(value: str | None) -> str:
    return value.replace('\\n', '\n').replace("\r\n", "\n").strip().strip("'\"") if isinstance(value, str) else ""


def _normalize_pem(value: str) -> str:
    return value.replace("\r\n", "\n").strip()
