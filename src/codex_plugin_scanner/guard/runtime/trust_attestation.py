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
    private_key_pem = _normalize_pem(_sanitize_env(env.get("GUARD_AIBOM_TRUST_ATTESTATION_PRIVATE_KEY")))
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


def apply_trust_attestation_metadata(
    metadata: dict[str, object],
    *,
    agent_id: str,
    item_id: str,
    item_kind: str,
    content_hash: str,
) -> dict[str, object]:
    config = resolve_trust_attestation_signing_config()
    if config is None:
        return metadata

    enriched = dict(metadata)

    raw_trust_resolution = enriched.get("trustResolution")
    if isinstance(raw_trust_resolution, dict):
        trust_resolution = dict(raw_trust_resolution)
        raw_resolution_metadata = trust_resolution.get("metadata")
        resolution_metadata = dict(raw_resolution_metadata) if isinstance(raw_resolution_metadata, dict) else {}
        evidence_hash = resolution_metadata.get("evidenceHash")
        captured_at = trust_resolution.get("capturedAt")
        if isinstance(evidence_hash, str) and evidence_hash and isinstance(captured_at, str) and captured_at:
            resolution_metadata["attestation"] = sign_trust_attestation(
                payload=build_trust_attestation_payload(
                    agent_id=agent_id,
                    item_id=item_id,
                    item_kind=item_kind,
                    content_hash=content_hash,
                    captured_at=captured_at,
                    evidence_hash=evidence_hash,
                    scope="trust_resolution",
                ),
                config=config,
                signed_at=captured_at,
            )
            resolution_metadata["attestationStatus"] = "signed"
            trust_resolution["metadata"] = resolution_metadata
            enriched["trustResolution"] = trust_resolution

    raw_trust_layers = enriched.get("trustLayers")
    if isinstance(raw_trust_layers, list):
        signed_layers: list[object] = []
        for raw_layer in raw_trust_layers:
            if not isinstance(raw_layer, dict):
                signed_layers.append(raw_layer)
                continue
            layer = dict(raw_layer)
            raw_layer_metadata = layer.get("metadata")
            layer_metadata = dict(raw_layer_metadata) if isinstance(raw_layer_metadata, dict) else {}
            evidence_hash = layer_metadata.get("evidenceHash")
            captured_at = layer.get("capturedAt")
            layer_id = layer.get("layerId")
            layer_type = layer.get("layerType")
            if (
                isinstance(evidence_hash, str)
                and evidence_hash
                and isinstance(captured_at, str)
                and captured_at
                and isinstance(layer_id, str)
                and layer_id
                and isinstance(layer_type, str)
                and layer_type
            ):
                layer_metadata["attestation"] = sign_trust_attestation(
                    payload=build_trust_attestation_payload(
                        agent_id=agent_id,
                        item_id=item_id,
                        item_kind=item_kind,
                        content_hash=content_hash,
                        captured_at=captured_at,
                        evidence_hash=evidence_hash,
                        scope="trust_layer",
                        layer_id=layer_id,
                        layer_type=layer_type,
                    ),
                    config=config,
                    signed_at=captured_at,
                )
                layer_metadata["attestationStatus"] = "signed"
                layer["metadata"] = layer_metadata
            signed_layers.append(layer)
        enriched["trustLayers"] = signed_layers

    return enriched


def sign_trust_attestation(
    *,
    payload: Mapping[str, object],
    config: GuardTrustAttestationSigningConfig,
    signed_at: str,
) -> dict[str, object]:
    private_key = _load_private_key(config.private_key_pem)
    canonical_payload = canonical_trust_attestation_payload(_payload_with_signed_at(payload, signed_at))
    signature = private_key.sign(
        canonical_payload,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    verification_key = _verification_key_from_private_key(
        private_key,
        key_id=config.active_key_id,
    )
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
    canonical_payload = canonical_trust_attestation_payload(_payload_with_signed_at(payload, envelope.get("signedAt")))
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


def _verification_key_from_private_key(
    private_key: RSAPrivateKey,
    *,
    key_id: str,
) -> GuardTrustAttestationVerificationKey:
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
        key_id=key_id,
        public_key_pem=public_key_pem,
        fingerprint_sha256=_public_key_fingerprint(public_key_pem),
    )


def _payload_with_signed_at(
    payload: Mapping[str, object],
    signed_at: object,
) -> dict[str, object]:
    enriched = dict(payload)
    if isinstance(signed_at, str) and signed_at:
        enriched["signedAt"] = signed_at
    return enriched


def _public_key_fingerprint(public_key_pem: str) -> str:
    normalized_pem = _normalize_pem(public_key_pem)
    return hashlib.sha256(normalized_pem.encode("utf-8")).hexdigest()


def _sanitize_env(value: str | None) -> str:
    return value.replace("\\n", "\n").replace("\r\n", "\n").strip().strip("'\"") if isinstance(value, str) else ""


def _normalize_pem(value: str) -> str:
    return value.replace("\r\n", "\n").strip()
