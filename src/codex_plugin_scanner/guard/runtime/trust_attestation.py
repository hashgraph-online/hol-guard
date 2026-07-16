from __future__ import annotations

import base64
import hashlib
import os
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from .evidence_hash import canonical_guard_evidence_payload, guard_evidence_hash

GUARD_TRUST_ATTESTATION_PAYLOAD_VERSION = "guard-aibom-trust-attestation.v1"
GUARD_TRUST_ATTESTATION_PAYLOAD_VERSION_V2 = "guard-aibom-trust-attestation.v2"
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


@dataclass(frozen=True, slots=True)
class GuardTrustAttestationVerificationPolicy:
    """Local verification state for rotation, revocation, and replay checks."""

    revoked_key_ids: frozenset[str] = frozenset()
    key_not_before: tuple[tuple[str, str], ...] = ()
    minimum_sequence: int | None = None
    seen_replay_keys: frozenset[str] = frozenset()
    now: str | None = None
    require_nonce: bool = True


def canonical_trust_attestation_payload(payload: Mapping[str, object]) -> bytes:
    return canonical_guard_evidence_payload(payload).encode("utf-8")


def payload_hash_for_trust_attestation(payload: Mapping[str, object]) -> str:
    return guard_evidence_hash(payload)


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
        public_jwk_thumbprint=config.public_jwk_thumbprint,
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
    payload: dict[str, object] = {
        "payloadVersion": GUARD_TRUST_ATTESTATION_PAYLOAD_VERSION_V3,
        "domainSeparator": GUARD_TRUST_ATTESTATION_DOMAIN,
        "agentId": agent_id,
        "itemId": item_id,
        "itemKind": item_kind,
        "contentHash": content_hash,
        "capturedAt": captured_at,
        "evidenceHash": evidence_hash,
        "scope": scope,
    }
    if analyzer_id is not None:
        payload["analyzerId"] = analyzer_id
    if analyzer_version is not None:
        payload["analyzerVersion"] = analyzer_version
    if analyzer_spec_version is not None:
        payload["analyzerSpecVersion"] = analyzer_spec_version
    if evidence_schema_version is not None:
        payload["evidenceSchemaVersion"] = evidence_schema_version
    if policy_version is not None:
        payload["policyVersion"] = policy_version
    if workspace_id is not None:
        payload["workspaceId"] = workspace_id
    if device_id is not None:
        payload["deviceId"] = device_id
    if installation_id is not None:
        payload["installationId"] = installation_id
    if upload_id is not None:
        payload["uploadId"] = upload_id
    if challenge_id is not None:
        payload["challengeId"] = challenge_id
    if nonce is not None:
        payload["nonce"] = nonce
    if sequence is not None:
        payload["sequence"] = sequence
    if expires_at is not None:
        payload["expiresAt"] = expires_at
    if layer_id is not None:
        payload["layerId"] = layer_id
    if layer_type is not None:
        payload["layerType"] = layer_type
    if adapter_id is not None:
        payload["adapterId"] = adapter_id
    if adapter_version is not None:
        payload["adapterVersion"] = adapter_version
    if config_path_hash is not None:
        payload["configPathHash"] = config_path_hash
    if repository_id is not None:
        payload["repositoryId"] = repository_id
    if claim_hash is not None:
        payload["claimHash"] = claim_hash
    return _validate_attestation_payload(payload, require_signed_at=False)


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
    raw_trust_resolution = enriched.get("trustResolution")
    trust_resolution = _validated_local_trust_claim(raw_trust_resolution, require_layer_identity=False)
    if trust_resolution is None:
        enriched.pop("trustResolution", None)
    else:
        enriched["trustResolution"] = trust_resolution

    raw_trust_layers = enriched.get("trustLayers")
    trust_layers = (
        [
            layer
            for raw_layer in raw_trust_layers
            if (layer := _validated_local_trust_claim(raw_layer, require_layer_identity=True)) is not None
        ]
        if isinstance(raw_trust_layers, list)
        else []
    )
    if trust_layers:
        enriched["trustLayers"] = trust_layers
    else:
        enriched.pop("trustLayers", None)

    config = signing_config or resolve_trust_attestation_signing_config()
    if config is None:
        return enriched

    include_v2_bindings = workspace_id is not None or device_id is not None
    effective_nonce = nonce or secrets.token_urlsafe(24)
    effective_policy_version = policy_version or "guard-local-policy:default"
    common_attestation_bindings = {
        key: value
        for key, value in {
            "domainSeparator": GUARD_TRUST_ATTESTATION_DOMAIN,
            "challengeId": challenge_id,
            "deviceId": device_id,
            "analyzerId": analyzer_id if include_v2_bindings else None,
            "analyzerSpecVersion": analyzer_spec_version if include_v2_bindings else None,
            "analyzerVersion": analyzer_version if include_v2_bindings else None,
            "expiresAt": expires_at,
            "installationId": installation_id,
            "nonce": effective_nonce,
            "policyVersion": effective_policy_version,
            "sequence": sequence,
            "uploadId": upload_id,
            "workspaceId": workspace_id,
            "adapterId": adapter_id,
            "adapterVersion": adapter_version,
            "configPathHash": config_path_hash,
            "repositoryId": repository_id,
        }.items()
        if value is not None
    }

    if trust_resolution is not None:
        raw_resolution_metadata = trust_resolution.get("metadata")
        resolution_metadata = dict(raw_resolution_metadata) if isinstance(raw_resolution_metadata, dict) else {}
        evidence_hash = resolution_metadata.get("evidenceHash")
        evidence_schema_version = resolution_metadata.get("evidenceSchemaVersion")
        captured_at = trust_resolution.get("capturedAt")
        claim_hash = trust_claim_hash(trust_resolution, require_layer_identity=False)
        if (
            isinstance(evidence_hash, str)
            and evidence_hash
            and isinstance(evidence_schema_version, str)
            and evidence_schema_version
            and isinstance(captured_at, str)
            and captured_at
        ):
            resolution_metadata["attestation"] = sign_trust_attestation(
                payload=build_trust_attestation_payload(
                    agent_id=agent_id,
                    analyzer_id=analyzer_id if include_v2_bindings else None,
                    analyzer_spec_version=analyzer_spec_version if include_v2_bindings else None,
                    analyzer_version=analyzer_version if include_v2_bindings else None,
                    item_id=item_id,
                    item_kind=item_kind,
                    content_hash=content_hash,
                    captured_at=captured_at,
                    challenge_id=challenge_id,
                    expires_at=expires_at,
                    evidence_hash=evidence_hash,
                    evidence_schema_version=evidence_schema_version,
                    installation_id=installation_id,
                    nonce=effective_nonce,
                    policy_version=effective_policy_version,
                    sequence=sequence,
                    scope="trust_resolution",
                    upload_id=upload_id,
                    workspace_id=workspace_id,
                    device_id=device_id,
                    adapter_id=adapter_id,
                    adapter_version=adapter_version,
                    config_path_hash=config_path_hash,
                    repository_id=repository_id,
                    claim_hash=claim_hash,
                ),
                config=config,
                signed_at=captured_at,
            )
            resolution_metadata["attestationStatus"] = "signed"
            resolution_metadata["attestationBindings"] = {
                **common_attestation_bindings,
                "evidenceSchemaVersion": evidence_schema_version,
                "claimHash": claim_hash,
            }
            trust_resolution["metadata"] = resolution_metadata
            enriched["trustResolution"] = trust_resolution

    if trust_layers:
        signed_layers: list[dict[str, object]] = []
        for layer in trust_layers:
            raw_layer_metadata = layer.get("metadata")
            layer_metadata = dict(raw_layer_metadata) if isinstance(raw_layer_metadata, dict) else {}
            evidence_hash = layer_metadata.get("evidenceHash")
            evidence_schema_version = layer_metadata.get("evidenceSchemaVersion")
            captured_at = layer.get("capturedAt")
            layer_id = layer.get("layerId")
            layer_type = layer.get("layerType")
            claim_hash = trust_claim_hash(layer, require_layer_identity=True)
            if (
                isinstance(evidence_hash, str)
                and evidence_hash
                and isinstance(evidence_schema_version, str)
                and evidence_schema_version
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
                        analyzer_id=analyzer_id if include_v2_bindings else None,
                        analyzer_spec_version=analyzer_spec_version if include_v2_bindings else None,
                        analyzer_version=analyzer_version if include_v2_bindings else None,
                        item_id=item_id,
                        item_kind=item_kind,
                        content_hash=content_hash,
                        captured_at=captured_at,
                        challenge_id=challenge_id,
                        expires_at=expires_at,
                        evidence_hash=evidence_hash,
                        evidence_schema_version=evidence_schema_version,
                        installation_id=installation_id,
                        nonce=effective_nonce,
                        policy_version=effective_policy_version,
                        sequence=sequence,
                        scope="trust_layer",
                        upload_id=upload_id,
                        workspace_id=workspace_id,
                        device_id=device_id,
                        layer_id=layer_id,
                        layer_type=layer_type,
                        adapter_id=adapter_id,
                        adapter_version=adapter_version,
                        config_path_hash=config_path_hash,
                        repository_id=repository_id,
                        claim_hash=claim_hash,
                    ),
                    config=config,
                    signed_at=captured_at,
                )
                layer_metadata["attestationStatus"] = "signed"
                layer_metadata["attestationBindings"] = {
                    **common_attestation_bindings,
                    "evidenceSchemaVersion": evidence_schema_version,
                    "claimHash": claim_hash,
                }
                layer["metadata"] = layer_metadata
            signed_layers.append(layer)
        enriched["trustLayers"] = signed_layers

    return enriched


_PRIOR_ATTESTATION_METADATA_KEYS = frozenset(
    {
        "attestation",
        "attestationBindings",
        "attestationRef",
        "attestationVerification",
    }
)


def _validated_local_trust_claim(
    raw_claim: object,
    *,
    require_layer_identity: bool,
) -> dict[str, object] | None:
    """Return a proof-free locally derived claim or reject it fail-closed."""

    if not isinstance(raw_claim, dict):
        return None
    provenance = raw_claim.get("provenance")
    if not isinstance(provenance, dict):
        return None
    if provenance.get("origin") != "hol-guard-local" or provenance.get("verificationStatus") != "locally_derived":
        return None
    derivation = provenance.get("derivation")
    if not isinstance(derivation, str) or not derivation:
        return None
    if raw_claim.get("evidenceAuthority") != "device_claim" or raw_claim.get("affectsV4Score") is not False:
        return None
    captured_at = raw_claim.get("capturedAt")
    if _parse_attestation_timestamp(captured_at) is None:
        return None
    if require_layer_identity:
        if not isinstance(raw_claim.get("layerId"), str) or not raw_claim.get("layerId"):
            return None
        if not isinstance(raw_claim.get("layerType"), str) or not raw_claim.get("layerType"):
            return None
    elif raw_claim.get("resolutionSource") != "local":
        return None
    raw_metadata = raw_claim.get("metadata")
    if not isinstance(raw_metadata, dict):
        return None
    evidence = raw_metadata.get("evidence")
    evidence_hash = raw_metadata.get("evidenceHash")
    evidence_schema_version = raw_metadata.get("evidenceSchemaVersion")
    if not isinstance(evidence, dict):
        return None
    if not isinstance(evidence_hash, str) or evidence_hash != guard_evidence_hash(evidence):
        return None
    if not isinstance(evidence_schema_version, str) or not evidence_schema_version.startswith("guard-aibom-"):
        return None
    claim = dict(raw_claim)
    metadata = {key: value for key, value in raw_metadata.items() if key not in _PRIOR_ATTESTATION_METADATA_KEYS}
    metadata["attestationStatus"] = "unsigned"
    claim["metadata"] = metadata
    return claim


def trust_claim_hash(claim: Mapping[str, object], *, require_layer_identity: bool) -> str:
    """Hash the complete proof-free local claim shown to attestation consumers."""

    normalized = _validated_local_trust_claim(dict(claim), require_layer_identity=require_layer_identity)
    if normalized is None:
        raise ValueError("Trust claim is not locally derived or has invalid evidence")
    return guard_evidence_hash(normalized)


_ATTESTATION_PAYLOAD_REQUIRED_FIELDS = frozenset(
    {
        "payloadVersion",
        "domainSeparator",
        "agentId",
        "itemId",
        "itemKind",
        "contentHash",
        "capturedAt",
        "claimHash",
        "evidenceHash",
        "scope",
    }
)
_ATTESTATION_PAYLOAD_OPTIONAL_STRING_FIELDS = frozenset(
    {
        "adapterId",
        "adapterVersion",
        "analyzerId",
        "analyzerSpecVersion",
        "analyzerVersion",
        "challengeId",
        "configPathHash",
        "deviceId",
        "evidenceSchemaVersion",
        "expiresAt",
        "installationId",
        "layerId",
        "layerType",
        "nonce",
        "policyVersion",
        "repositoryId",
        "signedAt",
        "uploadId",
        "workspaceId",
    }
)
_ATTESTATION_PAYLOAD_ALLOWED_FIELDS = (
    _ATTESTATION_PAYLOAD_REQUIRED_FIELDS | _ATTESTATION_PAYLOAD_OPTIONAL_STRING_FIELDS | {"sequence"}
)
_ATTESTATION_SUBJECT_BINDING_FIELDS = frozenset(
    {"adapterId", "adapterVersion", "configPathHash", "policyVersion", "repositoryId"}
)


def _parse_attestation_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    normalized = value.strip()
    if normalized.endswith(("Z", "z")):
        normalized = f"{normalized[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _validate_attestation_payload(
    payload: Mapping[str, object],
    *,
    require_signed_at: bool,
    require_nonce: bool = False,
    require_subject_bindings: bool = False,
) -> dict[str, object]:
    normalized = {str(key): value for key, value in payload.items()}
    unknown = set(normalized) - _ATTESTATION_PAYLOAD_ALLOWED_FIELDS
    if unknown:
        raise ValueError(f"Unknown trust attestation payload fields: {', '.join(sorted(unknown))}")
    missing = _ATTESTATION_PAYLOAD_REQUIRED_FIELDS - set(normalized)
    if missing:
        raise ValueError(f"Missing trust attestation payload fields: {', '.join(sorted(missing))}")
    for field in _ATTESTATION_PAYLOAD_REQUIRED_FIELDS | _ATTESTATION_PAYLOAD_OPTIONAL_STRING_FIELDS:
        if field not in normalized:
            continue
        value = normalized[field]
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"Trust attestation payload field {field} must be a non-empty string")
        normalized[field] = value.strip()
    if normalized.get("payloadVersion") != GUARD_TRUST_ATTESTATION_PAYLOAD_VERSION_V3:
        raise ValueError("Unsupported trust attestation payload version")
    if normalized.get("domainSeparator") != GUARD_TRUST_ATTESTATION_DOMAIN:
        raise ValueError("Trust attestation domain separator mismatch")
    if normalized.get("scope") not in {"trust_resolution", "trust_layer"}:
        raise ValueError("Unsupported trust attestation scope")
    if _parse_attestation_timestamp(normalized.get("capturedAt")) is None:
        raise ValueError("Trust attestation capturedAt is invalid")
    if "expiresAt" in normalized and _parse_attestation_timestamp(normalized["expiresAt"]) is None:
        raise ValueError("Trust attestation expiresAt is invalid")
    if require_signed_at and _parse_attestation_timestamp(normalized.get("signedAt")) is None:
        raise ValueError("Trust attestation signedAt is invalid")
    if not require_signed_at and "signedAt" in normalized:
        raise ValueError("Trust attestation builder cannot accept signedAt")
    if require_nonce and "nonce" not in normalized:
        raise ValueError("Trust attestation nonce is required")
    if require_subject_bindings:
        missing_bindings = _ATTESTATION_SUBJECT_BINDING_FIELDS - set(normalized)
        if missing_bindings:
            raise ValueError(f"Missing trust attestation subject bindings: {', '.join(sorted(missing_bindings))}")
    if "sequence" in normalized and (
        not isinstance(normalized["sequence"], int)
        or isinstance(normalized["sequence"], bool)
        or int(normalized["sequence"]) < 0
    ):
        raise ValueError("Trust attestation sequence must be a non-negative integer")
    if normalized.get("scope") == "trust_layer":
        if "layerId" not in normalized or "layerType" not in normalized:
            raise ValueError("Trust layer attestation requires layer identity")
    elif "layerId" in normalized or "layerType" in normalized:
        raise ValueError("Trust resolution attestation cannot contain layer identity")
    return normalized


def sign_trust_attestation(
    *,
    payload: Mapping[str, object],
    config: GuardTrustAttestationSigningConfig,
    signed_at: str,
) -> dict[str, object]:
    private_key = _load_private_key(config.private_key_pem)
    validated_payload = _validate_attestation_payload(
        _payload_with_signed_at(payload, signed_at),
        require_signed_at=True,
        require_nonce=True,
        require_subject_bindings=True,
    )
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


def verify_trust_attestation(
    *,
    payload: Mapping[str, object],
    envelope: Mapping[str, object],
    trusted_keys: tuple[GuardTrustAttestationVerificationKey, ...] | None = None,
    policy: GuardTrustAttestationVerificationPolicy | None = None,
    claim: Mapping[str, object] | None = None,
) -> str:
    allowed_envelope_fields = {
        "payloadVersion",
        "payloadHash",
        "signature",
        "signatureAlgorithm",
        "signedAt",
        "keyId",
        "publicKeyPem",
        "fingerprintSha256",
        "publicJwkThumbprint",
    }
    unknown_envelope_fields = {str(key) for key in envelope} - allowed_envelope_fields
    if unknown_envelope_fields:
        raise ValueError(f"Unknown trust attestation envelope fields: {', '.join(sorted(unknown_envelope_fields))}")
    raw_payload_hash = envelope.get("payloadHash")
    raw_signature_algorithm = envelope.get("signatureAlgorithm")
    raw_key_id = envelope.get("keyId")
    raw_public_key_pem = envelope.get("publicKeyPem")
    raw_fingerprint_sha256 = envelope.get("fingerprintSha256")
    raw_public_jwk_thumbprint = envelope.get("publicJwkThumbprint")
    raw_signature = envelope.get("signature")
    raw_payload_version = envelope.get("payloadVersion")
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
    if raw_payload_version != GUARD_TRUST_ATTESTATION_PAYLOAD_VERSION_V3:
        raise ValueError("Unsupported trust attestation envelope version")
    payload_hash: str = raw_payload_hash
    signature_algorithm: str = raw_signature_algorithm
    key_id: str = raw_key_id
    public_key_pem: str = raw_public_key_pem
    fingerprint_sha256: str = raw_fingerprint_sha256
    public_jwk_thumbprint = raw_public_jwk_thumbprint if isinstance(raw_public_jwk_thumbprint, str) else None
    signature: str = raw_signature
    if signature_algorithm not in {
        GUARD_TRUST_ATTESTATION_SIGNATURE_ALGORITHM,
        GUARD_TRUST_ATTESTATION_SIGNATURE_ALGORITHM_ECDSA_P256,
    }:
        raise ValueError("Unsupported trust attestation signature algorithm")
    validated_payload = _validate_attestation_payload(
        _payload_with_signed_at(payload, envelope.get("signedAt")),
        require_signed_at=True,
        require_nonce=True,
        require_subject_bindings=True,
    )
    if claim is not None:
        require_layer_identity = validated_payload.get("scope") == "trust_layer"
        if trust_claim_hash(claim, require_layer_identity=require_layer_identity) != validated_payload["claimHash"]:
            raise ValueError("Trust attestation claim hash mismatch")
    canonical_payload = canonical_trust_attestation_payload(validated_payload)
    if hashlib.sha256(canonical_payload).hexdigest() != payload_hash:
        raise ValueError("Trust attestation payload hash mismatch")
    if _public_key_fingerprint(public_key_pem) != fingerprint_sha256:
        raise ValueError("Trust attestation public key fingerprint mismatch")
    if trusted_keys is not None and not any(
        trusted_key.key_id == key_id
        and trusted_key.fingerprint_sha256 == fingerprint_sha256
        and _normalize_pem(trusted_key.public_key_pem) == _normalize_pem(public_key_pem)
        and (public_jwk_thumbprint is None or trusted_key.public_jwk_thumbprint == public_jwk_thumbprint)
        for trusted_key in trusted_keys
    ):
        raise ValueError("Trust attestation key is not trusted")
    verification_policy = policy or GuardTrustAttestationVerificationPolicy(require_nonce=False)
    if key_id in verification_policy.revoked_key_ids:
        raise ValueError("Trust attestation key is revoked")
    signed_at = _parse_attestation_timestamp(validated_payload.get("signedAt"))
    captured_at = _parse_attestation_timestamp(validated_payload.get("capturedAt"))
    if signed_at is None or captured_at is None or captured_at > signed_at:
        raise ValueError("Trust attestation timestamp ordering is invalid")
    key_not_before = dict(verification_policy.key_not_before).get(key_id)
    parsed_key_not_before = _parse_attestation_timestamp(key_not_before)
    if key_not_before is not None and (parsed_key_not_before is None or signed_at < parsed_key_not_before):
        raise ValueError("Trust attestation predates the trusted key activation")
    if verification_policy.now is not None:
        current = _parse_attestation_timestamp(verification_policy.now)
        if current is None:
            raise ValueError("Trust attestation verification time is invalid")
        if signed_at > current:
            raise ValueError("Trust attestation is signed in the future")
        expires_at = _parse_attestation_timestamp(validated_payload.get("expiresAt"))
        if expires_at is not None and expires_at <= current:
            raise ValueError("Trust attestation is expired")
    sequence = validated_payload.get("sequence")
    if verification_policy.minimum_sequence is not None and (
        not isinstance(sequence, int) or sequence <= verification_policy.minimum_sequence
    ):
        raise ValueError("Trust attestation sequence is not monotonic")
    if verification_policy.require_nonce and "nonce" not in validated_payload:
        raise ValueError("Trust attestation nonce is required")
    replay_key = trust_attestation_replay_key(validated_payload)
    if replay_key in verification_policy.seen_replay_keys:
        raise ValueError("Trust attestation replay detected")
    public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    if not isinstance(public_key, (RSAPublicKey, EllipticCurvePublicKey)):
        raise ValueError("Trust attestation public key must be RSA or EC")
    try:
        _verify_signature(
            public_key=public_key,
            canonical_payload=canonical_payload,
            signature=base64.b64decode(signature, validate=True),
            signature_algorithm=signature_algorithm,
        )
    except InvalidSignature as exc:
        raise ValueError("Trust attestation signature verification failed") from exc
    return replay_key


def trust_attestation_replay_key(payload: Mapping[str, object]) -> str:
    """Return the stable verifier-side replay identity for an attestation."""

    return guard_evidence_hash(
        {
            "domainSeparator": payload.get("domainSeparator"),
            "nonce": payload.get("nonce"),
            "itemId": payload.get("itemId"),
            "scope": payload.get("scope"),
            "layerId": payload.get("layerId"),
            "workspaceId": payload.get("workspaceId"),
            "repositoryId": payload.get("repositoryId"),
        }
    )


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


def _verify_signature(
    *,
    public_key: RSAPublicKey | EllipticCurvePublicKey,
    canonical_payload: bytes,
    signature: bytes,
    signature_algorithm: str,
) -> None:
    if signature_algorithm == GUARD_TRUST_ATTESTATION_SIGNATURE_ALGORITHM:
        if not isinstance(public_key, RSAPublicKey):
            raise ValueError("Trust attestation public key must be RSA")
        public_key.verify(
            signature,
            canonical_payload,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return
    if signature_algorithm == GUARD_TRUST_ATTESTATION_SIGNATURE_ALGORITHM_ECDSA_P256:
        if not isinstance(public_key, EllipticCurvePublicKey):
            raise ValueError("Trust attestation public key must be EC")
        if not isinstance(public_key.curve, ec.SECP256R1):
            raise ValueError("Trust attestation EC public key must use P-256")
        public_key.verify(signature, canonical_payload, ec.ECDSA(hashes.SHA256()))
        return
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
