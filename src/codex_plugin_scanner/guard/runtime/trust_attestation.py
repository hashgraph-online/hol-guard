from __future__ import annotations

import json
import os
import secrets
from collections.abc import Mapping
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from ..native_runner_authority import (
    NativeRunnerAuthorityError,
    NativeRunnerAuthorityRefusalError,
    native_runner_authority,
)

GUARD_TRUST_ATTESTATION_PAYLOAD_VERSION_V3 = "guard-aibom-trust-attestation.v3"
GUARD_TRUST_ATTESTATION_DOMAIN = "hol-guard:aibom-trust-attestation:v3"
GUARD_TRUST_ATTESTATION_SIGNATURE_ALGORITHM = "rsa-pss-sha256"
GUARD_TRUST_ATTESTATION_SIGNATURE_ALGORITHM_ECDSA_P256 = "ecdsa-p256-sha256"
_TRUTHY_ENV_VALUES = frozenset({"1", "true", "yes", "on"})
_FALSY_ENV_VALUES = frozenset({"0", "false", "no", "off"})
_DEFAULT_TRUST_ATTESTATION_KEY_FILE = "trust_attestation_key.pem"
_DEFAULT_TRUST_ATTESTATION_KEY_ID = "guard-aibom-trust-key-local"
_NATIVE_KEY_FEATURE = "native-trust-attestation-key-v1"
_NATIVE_KEY_COMMAND = "trust-attestation-key"
_NATIVE_KEY_OUTPUT_LIMIT = 16 * 1024 * 1024
_NATIVE_KEY_TIMEOUT_SECONDS = 30.0
# Payload bytes per sign request, leaving room under the 4 MiB native bound.
_NATIVE_KEY_BATCH_BYTES = 3 * 1024 * 1024
_NATIVE_KEY_UNAVAILABLE = "native_trust_attestation_key_unavailable"
_NATIVE_KEY_INVALID = "native_trust_attestation_key_invalid"


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
        _native_key_answer({"op": "load", "key": private_key_pem})
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
    """Load or auto-generate the persistent EC P-256 key stored in guard_home.

    The native runtime keeps the key in ``guard_home / trust_attestation_key.pem``
    with 0600 permissions, so the server registers the same device key across
    restarts. Returns ``None`` if the key file cannot be created or read.
    """
    try:
        answer = _native_key_answer({"op": "persistent", "guard_home": str(guard_home.absolute())})
    except ValueError:
        return None
    return _generated_signing_config(answer, active_key_id=active_key_id)


def _resolve_headless_short_lived_trust_attestation_signing_config(
    *,
    active_key_id: str,
) -> GuardTrustAttestationSigningConfig | None:
    try:
        return _headless_short_lived_trust_attestation_signing_config(active_key_id=active_key_id)
    except ValueError:
        return None


@lru_cache(maxsize=4)
def _headless_short_lived_trust_attestation_signing_config(
    *,
    active_key_id: str,
) -> GuardTrustAttestationSigningConfig:
    config = _generated_signing_config(_native_key_answer({"op": "generate"}), active_key_id=active_key_id)
    if config is None:
        raise ValueError(_NATIVE_KEY_INVALID)
    return config


def _generated_signing_config(
    answer: Mapping[str, object],
    *,
    active_key_id: str,
) -> GuardTrustAttestationSigningConfig | None:
    private_key_pem = answer.get("private_key_pem")
    fingerprint = answer.get("fingerprint_sha256")
    if not isinstance(private_key_pem, str) or not isinstance(fingerprint, str):
        return None
    return GuardTrustAttestationSigningConfig(
        active_key_id=active_key_id,
        private_key_pem=private_key_pem,
        public_jwk_thumbprint=fingerprint,
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
    try:
        validated_payloads = [_admitted_payload(entry) for _, entry in signing]
    except ValueError:
        _raise_for_unloadable_key(config.private_key_pem)
        raise
    attestations = _signed_attestations(
        config,
        [
            (validated, str(entry["signed_at"]))
            for (_, entry), validated in zip(signing, validated_payloads, strict=True)
        ],
    )
    for (claim, entry), attestation in zip(signing, attestations, strict=True):
        raw_claim_metadata = claim.get("metadata")
        claim_metadata = dict(raw_claim_metadata) if isinstance(raw_claim_metadata, dict) else {}
        claim_metadata["attestation"] = attestation
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
    try:
        validated_payload = _validate_attestation_payload(
            _payload_with_signed_at(payload, signed_at), **_SIGNED_PAYLOAD_RULES
        )
    except ValueError:
        _raise_for_unloadable_key(config.private_key_pem)
        raise
    return _signed_attestations(config, [(validated_payload, signed_at)])[0]


def _signed_attestations(
    config: GuardTrustAttestationSigningConfig,
    payloads: list[tuple[dict[str, object], str]],
) -> list[dict[str, object]]:
    """The native runtime's signed envelope for each admitted payload, in order.

    Payloads go in batches that stay under the native request bound, since
    each claim was admitted on its own size, not the item's.
    """

    batches: list[list[dict[str, object]]] = [[]]
    batch_bytes = 0
    for payload, signed_at in payloads:
        entry: dict[str, object] = {"payload": payload, "signed_at": signed_at}
        entry_bytes = len(json.dumps(entry, sort_keys=True))
        if batches[-1] and batch_bytes + entry_bytes > _NATIVE_KEY_BATCH_BYTES:
            batches.append([])
            batch_bytes = 0
        batches[-1].append(entry)
        batch_bytes += entry_bytes
    return [attestation for batch in batches if batch for attestation in _signed_batch(config, batch)]


def _signed_batch(
    config: GuardTrustAttestationSigningConfig, batch: list[dict[str, object]]
) -> list[dict[str, object]]:
    answer = _native_key_answer(
        {
            "op": "sign",
            "key": config.private_key_pem,
            "algorithm": config.signature_algorithm,
            "key_id": config.active_key_id,
            "public_jwk_thumbprint": config.public_jwk_thumbprint,
            "payloads": batch,
        }
    )
    attestations = answer.get("attestations")
    if (
        not isinstance(attestations, list)
        or len(attestations) != len(batch)
        or not all(isinstance(attestation, dict) for attestation in attestations)
    ):
        raise ValueError(_NATIVE_KEY_INVALID)
    return [dict(attestation) for attestation in attestations if isinstance(attestation, dict)]


def _raise_for_unloadable_key(private_key_pem: str) -> None:
    """Raise the key's refusal, which comes before any payload refusal."""

    try:
        _native_key_answer({"op": "load", "key": private_key_pem})
    except ValueError as error:
        if str(error) != _NATIVE_KEY_UNAVAILABLE:
            raise


def _native_key_answer(request: dict[str, object]) -> dict[str, object]:
    """Ask the native runtime, which alone holds the private key, to act on it.

    A refusal is raised as the ``ValueError`` it names; a runtime that cannot
    answer raises ``ValueError`` too, so signing fails closed.
    """

    from ..mdm.runtime_request import runtime_answer

    answer = runtime_answer(
        _NATIVE_KEY_FEATURE,
        _NATIVE_KEY_COMMAND,
        request,
        output_limit=_NATIVE_KEY_OUTPUT_LIMIT,
        timeout_seconds=_NATIVE_KEY_TIMEOUT_SECONDS,
    )
    if answer is None:
        raise ValueError(_NATIVE_KEY_UNAVAILABLE)
    error = answer.get("error")
    if isinstance(error, str):
        raise ValueError(error)
    return answer


def _payload_with_signed_at(
    payload: Mapping[str, object],
    signed_at: object,
) -> dict[str, object]:
    enriched = dict(payload)
    if isinstance(signed_at, str) and signed_at:
        enriched["signedAt"] = signed_at
    return enriched


def _sanitize_env(value: str | None) -> str:
    return value.replace("\\n", "\n").replace("\r\n", "\n").strip().strip("'\"") if isinstance(value, str) else ""


def _sanitize_object_string(value: object) -> str:
    return value.strip() if isinstance(value, str) else ""


def _normalize_pem(value: str) -> str:
    return value.replace("\r\n", "\n").strip()
