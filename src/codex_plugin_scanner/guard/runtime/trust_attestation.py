from __future__ import annotations

import base64
import hashlib
import os
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from ..native_runner_authority import (
    NativeRunnerAuthorityError,
    NativeRunnerAuthorityRefusalError,
    native_runner_authority,
)
from .evidence_hash import canonical_guard_evidence_payload

GUARD_TRUST_ATTESTATION_PAYLOAD_VERSION_V3 = "guard-aibom-trust-attestation.v3"
GUARD_TRUST_ATTESTATION_DOMAIN = "hol-guard:aibom-trust-attestation:v3"
GUARD_TRUST_ATTESTATION_SIGNATURE_ALGORITHM = "rsa-pss-sha256"
GUARD_TRUST_ATTESTATION_SIGNATURE_ALGORITHM_ECDSA_P256 = "ecdsa-p256-sha256"
_TRUTHY_ENV_VALUES = frozenset({"1", "true", "yes", "on"})
_FALSY_ENV_VALUES = frozenset({"0", "false", "no", "off"})
_DEFAULT_TRUST_ATTESTATION_KEY_FILE = "trust_attestation_key.pem"
_DEFAULT_TRUST_ATTESTATION_KEY_ID = "guard-aibom-trust-key-local"


@dataclass(frozen=True, slots=True)
class GuardTrustAttestationSigningConfig:
    active_key_id: str
    private_key_pem: str
    public_jwk_thumbprint: str | None = None
    signature_algorithm: str = GUARD_TRUST_ATTESTATION_SIGNATURE_ALGORITHM


@dataclass(frozen=True, slots=True)
class GuardTrustAttestationVerificationKey:
    key_id: str
    public_key_pem: str
    fingerprint_sha256: str
    public_jwk_thumbprint: str | None = None


def canonical_trust_attestation_payload(payload: Mapping[str, object]) -> bytes:
    return canonical_guard_evidence_payload(payload).encode("utf-8")


def resolve_trust_attestation_signing_config(
    environ: Mapping[str, str] | None = None,
    *,
    guard_home: Path | None = None,
) -> GuardTrustAttestationSigningConfig | None:
    """Resolve the trust attestation signing configuration.

    Priority (highest wins):
    1. ``GUARD_AIBOM_TRUST_ATTESTATION_PRIVATE_KEY`` env var (explicit override)
    2. ``GUARD_AIBOM_TRUST_ATTESTATION_HEADLESS_SHORT_LIVED=1`` env var (ephemeral key per process)
    3. Persistent auto-generated key in ``guard_home`` (default for new users)
    4. ``None`` (attestation disabled)
    """
    env = environ or os.environ
    active_key_id = _sanitize_env(env.get("GUARD_AIBOM_TRUST_ATTESTATION_KEY_ID")) or _DEFAULT_TRUST_ATTESTATION_KEY_ID
    private_key_pem = _normalize_pem(_sanitize_env(env.get("GUARD_AIBOM_TRUST_ATTESTATION_PRIVATE_KEY")))
    if not private_key_pem:
        if _headless_short_lived_attestation_enabled(env):
            return _resolve_headless_short_lived_trust_attestation_signing_config(active_key_id=active_key_id)
        if guard_home is not None:
            return _resolve_persistent_trust_attestation_signing_config(
                active_key_id=active_key_id,
                guard_home=guard_home,
            )
        return None
    return GuardTrustAttestationSigningConfig(
        active_key_id=active_key_id,
        private_key_pem=private_key_pem,
    )


def resolve_guard_oauth_trust_attestation_signing_config(
    credentials: Mapping[str, object] | None,
) -> GuardTrustAttestationSigningConfig | None:
    if not isinstance(credentials, Mapping):
        return None
    private_key_pem = _normalize_pem(_sanitize_object_string(credentials.get("dpop_private_key_pem")))
    public_jwk_thumbprint = _sanitize_object_string(credentials.get("dpop_public_jwk_thumbprint")) or None
    if not private_key_pem or public_jwk_thumbprint is None:
        return None
    try:
        _load_private_key(private_key_pem)
    except ValueError:
        return None
    return GuardTrustAttestationSigningConfig(
        active_key_id=public_jwk_thumbprint,
        private_key_pem=private_key_pem,
        public_jwk_thumbprint=public_jwk_thumbprint,
        signature_algorithm=GUARD_TRUST_ATTESTATION_SIGNATURE_ALGORITHM_ECDSA_P256,
    )


def trust_attestation_v2_enabled(environ: Mapping[str, str] | None = None) -> bool:
    """Trust attestation v2 is enabled by default. Set GUARD_AIBOM_TRUST_ATTESTATION_V2=0 to opt out."""
    env = environ or os.environ
    raw = _sanitize_env(env.get("GUARD_AIBOM_TRUST_ATTESTATION_V2")).lower()
    return raw not in _FALSY_ENV_VALUES


def _headless_short_lived_attestation_enabled(environ: Mapping[str, str]) -> bool:
    raw = environ.get("GUARD_AIBOM_TRUST_ATTESTATION_HEADLESS_SHORT_LIVED")
    return _sanitize_env(raw).lower() in _TRUTHY_ENV_VALUES


def _resolve_persistent_trust_attestation_signing_config(
    *,
    active_key_id: str,
    guard_home: Path,
) -> GuardTrustAttestationSigningConfig | None:
    """Load or auto-generate a persistent EC P-256 key stored in guard_home.

    The key is written to ``guard_home / trust_attestation_key.pem`` with 0600
    permissions. On subsequent runs the same key is loaded, ensuring the server
    registers the same device key across restarts. Returns ``None`` if the key
    file cannot be created or read.
    """
    key_path = guard_home / _DEFAULT_TRUST_ATTESTATION_KEY_FILE
    try:
        private_key_pem = key_path.read_text(encoding="utf-8").strip()
        if not private_key_pem:
            raise ValueError("Empty trust attestation key file")
        private_key = _load_private_key(private_key_pem)
    except Exception:
        # Key file is missing, empty, or corrupted. Generate a new key
        # using atomic exclusive creation to avoid race conditions between
        # concurrent Guard processes. If another process already created
        # the file, read its key instead.
        try:
            private_key = ec.generate_private_key(ec.SECP256R1())
            private_key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ).decode("utf-8")
            key_path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(private_key_pem)
        except FileExistsError:
            # Another process created the file, or the file was corrupt and
            # already existed. Read its key; if it fails, remove and retry.
            try:
                private_key_pem = key_path.read_text(encoding="utf-8").strip()
                private_key = _load_private_key(private_key_pem)
            except Exception:
                key_path.unlink(missing_ok=True)
                private_key = ec.generate_private_key(ec.SECP256R1())
                private_key_pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                ).decode("utf-8")
                fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    f.write(private_key_pem)
        except Exception:
            return None
    public_key_pem = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
        .strip()
    )
    return GuardTrustAttestationSigningConfig(
        active_key_id=active_key_id,
        private_key_pem=_normalize_pem(private_key_pem),
        public_jwk_thumbprint=_public_key_fingerprint(public_key_pem),
        signature_algorithm=GUARD_TRUST_ATTESTATION_SIGNATURE_ALGORITHM_ECDSA_P256,
    )


@lru_cache(maxsize=4)
def _resolve_headless_short_lived_trust_attestation_signing_config(
    *,
    active_key_id: str,
) -> GuardTrustAttestationSigningConfig:
    private_key = ec.generate_private_key(ec.SECP256R1())
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    public_key_pem = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
        .strip()
    )
    return GuardTrustAttestationSigningConfig(
        active_key_id=active_key_id,
        private_key_pem=private_key_pem,
        public_jwk_thumbprint=_public_key_fingerprint(public_key_pem),
        signature_algorithm=GUARD_TRUST_ATTESTATION_SIGNATURE_ALGORITHM_ECDSA_P256,
    )


_SIGNED_PAYLOAD_RULES = {"require_signed_at": True, "require_nonce": True, "require_subject_bindings": True}


def build_trust_attestation_payload(
    *,
    agent_id: str,
    analyzer_id: str | None = None,
    analyzer_spec_version: str | None = None,
    analyzer_version: str | None = None,
    item_id: str,
    item_kind: str,
    content_hash: str,
    captured_at: str,
    evidence_hash: str,
    evidence_schema_version: str | None = None,
    scope: str,
    challenge_id: str | None = None,
    expires_at: str | None = None,
    installation_id: str | None = None,
    nonce: str | None = None,
    sequence: int | None = None,
    upload_id: str | None = None,
    policy_version: str | None = None,
    workspace_id: str | None = None,
    device_id: str | None = None,
    layer_id: str | None = None,
    layer_type: str | None = None,
    adapter_id: str | None = None,
    adapter_version: str | None = None,
    config_path_hash: str | None = None,
    repository_id: str | None = None,
    claim_hash: str | None = None,
) -> dict[str, object]:
    fields: dict[str, object] = {
        "agent_id": agent_id,
        "analyzer_id": analyzer_id,
        "analyzer_spec_version": analyzer_spec_version,
        "analyzer_version": analyzer_version,
        "item_id": item_id,
        "item_kind": item_kind,
        "content_hash": content_hash,
        "captured_at": captured_at,
        "evidence_hash": evidence_hash,
        "evidence_schema_version": evidence_schema_version,
        "scope": scope,
        "challenge_id": challenge_id,
        "expires_at": expires_at,
        "installation_id": installation_id,
        "nonce": nonce,
        "sequence": sequence,
        "upload_id": upload_id,
        "policy_version": policy_version,
        "workspace_id": workspace_id,
        "device_id": device_id,
        "layer_id": layer_id,
        "layer_type": layer_type,
        "adapter_id": adapter_id,
        "adapter_version": adapter_version,
        "config_path_hash": config_path_hash,
        "repository_id": repository_id,
        "claim_hash": claim_hash,
    }
    return _admitted_payload(native_runner_authority("trust_attestation_shape", {"op": "build", "fields": fields}))


def apply_trust_attestation_metadata(
    metadata: dict[str, object],
    *,
    agent_id: str,
    analyzer_id: str | None = None,
    analyzer_spec_version: str | None = None,
    analyzer_version: str | None = None,
    item_id: str,
    item_kind: str,
    content_hash: str,
    challenge_id: str | None = None,
    expires_at: str | None = None,
    installation_id: str | None = None,
    nonce: str | None = None,
    sequence: int | None = None,
    upload_id: str | None = None,
    policy_version: str | None = None,
    workspace_id: str | None = None,
    device_id: str | None = None,
    adapter_id: str | None = None,
    adapter_version: str | None = None,
    config_path_hash: str | None = None,
    repository_id: str | None = None,
    signing_config: GuardTrustAttestationSigningConfig | None = None,
) -> dict[str, object]:
    enriched = dict(metadata)
    fields: dict[str, object] = {
        "agent_id": agent_id,
        "analyzer_id": analyzer_id,
        "analyzer_spec_version": analyzer_spec_version,
        "analyzer_version": analyzer_version,
        "item_id": item_id,
        "item_kind": item_kind,
        "content_hash": content_hash,
        "challenge_id": challenge_id,
        "expires_at": expires_at,
        "installation_id": installation_id,
        "nonce": nonce or secrets.token_urlsafe(24),
        "sequence": sequence,
        "upload_id": upload_id,
        "policy_version": policy_version,
        "workspace_id": workspace_id,
        "device_id": device_id,
        "adapter_id": adapter_id,
        "adapter_version": adapter_version,
        "config_path_hash": config_path_hash,
        "repository_id": repository_id,
    }
    trust_resolution, trust_layers, signing = _attestation_plan(
        enriched.get("trustResolution"), enriched.get("trustLayers"), fields
    )
    if trust_resolution is None:
        enriched.pop("trustResolution", None)
    else:
        enriched["trustResolution"] = trust_resolution
    if trust_layers:
        enriched["trustLayers"] = trust_layers
    else:
        enriched.pop("trustLayers", None)

    config = signing_config or resolve_trust_attestation_signing_config()
    if config is None or not signing:
        return enriched

    # Every payload of the item is checked before any is signed; the first
    # refusal fails the item exactly as signing it alone would.
    private_key = _load_private_key(config.private_key_pem)
    validated_payloads = [_admitted_payload(entry) for _, entry in signing]
    for (claim, entry), validated in zip(signing, validated_payloads, strict=True):
        raw_claim_metadata = claim.get("metadata")
        claim_metadata = dict(raw_claim_metadata) if isinstance(raw_claim_metadata, dict) else {}
        claim_metadata["attestation"] = _sign_validated_payload(
            validated, private_key=private_key, config=config, signed_at=str(entry["signed_at"])
        )
        claim_metadata["attestationStatus"] = "signed"
        claim_metadata["attestationBindings"] = entry["bindings"]
        claim["metadata"] = claim_metadata
    return enriched


_SigningPlan = tuple[dict[str, Any] | None, list[dict[str, Any]], list[tuple[dict[str, Any], dict[str, Any]]]]


def _attestation_plan(raw_resolution: object, raw_layers: object, fields: dict[str, object]) -> _SigningPlan:
    """Return the locally derived claims the native gate admits and how to sign each.

    Each admitted claim comes back with its prior proof stripped and its
    metadata marked unsigned. Each signing entry pairs a claim with the native
    verdict on its payload, its signing time and its attestation bindings.
    """

    if not isinstance(raw_resolution, dict) and not (isinstance(raw_layers, list) and raw_layers):
        return None, [], []
    try:
        return _plan({"resolution": raw_resolution, "layers": raw_layers}, fields)
    except NativeRunnerAuthorityRefusalError:
        # Shared fields the encoder refuses would refuse every claim alike, so
        # that refusal fails the item instead of erasing its claims.
        _plan({"resolution": None, "layers": []}, fields)
    # A claim the bounded encoder refuses (unencodable or oversized) drops
    # alone; the item keeps every other claim instead of losing all of them.
    resolution, _, signing = (
        _plan_alone({"resolution": raw_resolution}, fields) if isinstance(raw_resolution, dict) else (None, [], [])
    )
    layers: list[dict[str, Any]] = []
    if isinstance(raw_layers, list):
        for raw_layer in raw_layers:
            if isinstance(raw_layer, dict):
                _, admitted, layer_signing = _plan_alone({"resolution": None, "layers": [raw_layer]}, fields)
                layers.extend(admitted)
                signing.extend(layer_signing)
    return resolution, layers, signing


def _plan_alone(request: dict[str, object], fields: dict[str, object]) -> _SigningPlan:
    try:
        return _plan(request, fields)
    except NativeRunnerAuthorityRefusalError:
        return None, [], []


def _plan(request: dict[str, object], fields: dict[str, object]) -> _SigningPlan:
    answer = native_runner_authority("trust_attestation_shape", {"op": "sign_plan", **request, "fields": fields})
    resolution = answer.get("resolution")
    layers = answer.get("layers")
    signing = answer.get("signing")
    if (
        not (resolution is None or isinstance(resolution, dict))
        or not isinstance(layers, list)
        or not isinstance(signing, list)
        or not all(isinstance(layer, dict) for layer in layers)
    ):
        raise NativeRunnerAuthorityError("native_runner_authority_invalid")
    admitted_layers: list[dict[str, Any]] = [layer for layer in layers if isinstance(layer, dict)]
    pairs: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for entry in signing:
        if not isinstance(entry, dict) or not isinstance(entry.get("bindings"), dict):
            raise NativeRunnerAuthorityError("native_runner_authority_invalid")
        index = entry.get("layer")
        if index is None and isinstance(resolution, dict):
            claim = resolution
        elif type(index) is int and 0 <= index < len(admitted_layers):
            claim = admitted_layers[index]
        else:
            raise NativeRunnerAuthorityError("native_runner_authority_invalid")
        pairs.append((claim, entry))
    return resolution, admitted_layers, pairs


def trust_claim_hash(claim: Mapping[str, object], *, require_layer_identity: bool) -> str:
    """Hash the complete proof-free local claim shown to attestation consumers."""

    answer = native_runner_authority(
        "trust_attestation_shape",
        {"op": "claim_hash", "claim": dict(claim), "require_layer_identity": require_layer_identity},
    )
    claim_hash = answer.get("claim_hash")
    if not isinstance(claim_hash, str):
        raise ValueError("Trust claim is not locally derived or has invalid evidence")
    return claim_hash


def _validate_attestation_payload(
    payload: Mapping[str, object],
    *,
    require_signed_at: bool,
    require_nonce: bool = False,
    require_subject_bindings: bool = False,
) -> dict[str, object]:
    answer = native_runner_authority(
        "trust_attestation_shape",
        {
            "op": "payload",
            "payload": {str(key): value for key, value in payload.items()},
            "require_signed_at": require_signed_at,
            "require_nonce": require_nonce,
            "require_subject_bindings": require_subject_bindings,
        },
    )
    return _admitted_payload(answer)


def _admitted_payload(answer: object) -> dict[str, object]:
    if not isinstance(answer, dict):
        raise NativeRunnerAuthorityError("native_runner_authority_invalid")
    refused = answer.get("refused")
    if isinstance(refused, str):
        raise ValueError(refused)
    normalized = answer.get("payload")
    if not isinstance(normalized, dict):
        raise NativeRunnerAuthorityError("native_runner_authority_invalid")
    return normalized


def sign_trust_attestation(
    *,
    payload: Mapping[str, object],
    config: GuardTrustAttestationSigningConfig,
    signed_at: str,
) -> dict[str, object]:
    private_key = _load_private_key(config.private_key_pem)
    validated_payload = _validate_attestation_payload(
        _payload_with_signed_at(payload, signed_at), **_SIGNED_PAYLOAD_RULES
    )
    return _sign_validated_payload(validated_payload, private_key=private_key, config=config, signed_at=signed_at)


def _sign_validated_payload(
    validated_payload: Mapping[str, object],
    *,
    private_key: RSAPrivateKey | EllipticCurvePrivateKey,
    config: GuardTrustAttestationSigningConfig,
    signed_at: str,
) -> dict[str, object]:
    canonical_payload = canonical_trust_attestation_payload(validated_payload)
    signature = _sign_payload(
        private_key=private_key,
        canonical_payload=canonical_payload,
        signature_algorithm=config.signature_algorithm,
    )
    verification_key = _verification_key_from_private_key(
        private_key,
        key_id=config.active_key_id,
        public_jwk_thumbprint=config.public_jwk_thumbprint,
    )
    return {
        "payloadVersion": str(validated_payload["payloadVersion"]),
        "payloadHash": hashlib.sha256(canonical_payload).hexdigest(),
        "signature": base64.b64encode(signature).decode("ascii"),
        "signatureAlgorithm": config.signature_algorithm,
        "signedAt": signed_at,
        "keyId": verification_key.key_id,
        "publicKeyPem": verification_key.public_key_pem,
        "fingerprintSha256": verification_key.fingerprint_sha256,
        **(
            {"publicJwkThumbprint": verification_key.public_jwk_thumbprint}
            if verification_key.public_jwk_thumbprint is not None
            else {}
        ),
    }


def _load_private_key(private_key_pem: str) -> RSAPrivateKey | EllipticCurvePrivateKey:
    private_key = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
    if not isinstance(private_key, (RSAPrivateKey, EllipticCurvePrivateKey)):
        raise ValueError("Trust attestation private key must be RSA or EC")
    return private_key


def _verification_key_from_private_key(
    private_key: RSAPrivateKey | EllipticCurvePrivateKey,
    *,
    key_id: str,
    public_jwk_thumbprint: str | None = None,
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
        public_jwk_thumbprint=public_jwk_thumbprint,
    )


def _sign_payload(
    *,
    private_key: RSAPrivateKey | EllipticCurvePrivateKey,
    canonical_payload: bytes,
    signature_algorithm: str,
) -> bytes:
    if signature_algorithm == GUARD_TRUST_ATTESTATION_SIGNATURE_ALGORITHM:
        if not isinstance(private_key, RSAPrivateKey):
            raise ValueError("Trust attestation private key must be RSA")
        return private_key.sign(
            canonical_payload,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
    if signature_algorithm == GUARD_TRUST_ATTESTATION_SIGNATURE_ALGORITHM_ECDSA_P256:
        if not isinstance(private_key, EllipticCurvePrivateKey):
            raise ValueError("Trust attestation private key must be EC")
        if not isinstance(private_key.curve, ec.SECP256R1):
            raise ValueError("Trust attestation EC private key must use P-256")
        return private_key.sign(canonical_payload, ec.ECDSA(hashes.SHA256()))
    raise ValueError("Unsupported trust attestation signature algorithm")


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


def _sanitize_object_string(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


def _normalize_pem(value: str) -> str:
    return value.replace("\r\n", "\n").strip()
