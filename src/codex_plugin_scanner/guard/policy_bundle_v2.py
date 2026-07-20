"""Signed canonical Guard policy bundle v2 validation and state transitions."""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from datetime import datetime, timezone
from typing import TypeGuard, cast

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from .policy_bundle_trusted_keys import (
    PolicyBundleVerificationKey,
    resolve_policy_bundle_signing_key,
    signing_key_is_current,
    signing_key_is_trusted,
)
from .policy_document import JsonValue, canonical_json_bytes, canonical_policy_document_bytes
from .policy_document_yaml import PolicyDocumentError, parse_policy_document_yaml

POLICY_BUNDLE_V2_CONTRACT = "guard-policy-bundle.v2"
POLICY_BUNDLE_V2_ENVELOPE_VERSION = 2
POLICY_BUNDLE_V2_CANONICALIZATION = {"algorithm": "rfc8785", "version": "1"}
POLICY_BUNDLE_V2_ACK_STATUSES = frozenset({"received", "validated", "applied", "failed", "offline"})

POLICY_BUNDLE_MAX_BYTES = 2_097_152
POLICY_BUNDLE_MAX_DEPTH = 40
POLICY_BUNDLE_MAX_COLLECTION_ITEMS = 2_048
POLICY_BUNDLE_MAX_STRING_LENGTH = 1_048_576
_SHA256_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
_ALLOWED_TOP_LEVEL = frozenset(
    {
        "envelopeVersion",
        "contractVersion",
        "bundleVersion",
        "bundleHash",
        "payloadHash",
        "issuedAt",
        "expiresAt",
        "workspaceId",
        "canonicalization",
        "verifier",
        "payload",
        "rollback",
    }
)
_ALLOWED_ROLLBACK_KEYS = frozenset(
    {
        "rollbackOfBundleHash",
        "rollbackOfBundleVersion",
        "lastGoodBundleHash",
        "lastGoodBundleVersion",
        "reason",
        "actor",
        "createdAt",
        "authorization",
    }
)
_ALLOWED_VERIFIER_KEYS = frozenset({"algorithm", "keyId", "keyFingerprint", "publicKeyPem", "signature"})
_ALLOWED_ACK_KEYS = frozenset(
    {
        "contractVersion",
        "workspaceId",
        "deviceId",
        "bundleVersion",
        "bundleHash",
        "sequence",
        "status",
        "observedAt",
        "errorCode",
    }
)
_ALLOWED_ACK_TRANSITIONS = {
    "received": frozenset({"received", "validated", "failed", "offline"}),
    "validated": frozenset({"validated", "applied", "failed", "offline"}),
    "applied": frozenset({"applied", "offline"}),
    "failed": frozenset({"failed", "received", "offline"}),
    "offline": frozenset({"offline", "received"}),
}


def _is_object_list(value: object) -> TypeGuard[list[object]]:
    return isinstance(value, list)


def _is_object_mapping(value: object) -> TypeGuard[dict[str, object]]:
    if not isinstance(value, dict):
        return False
    return all(isinstance(key, str) for key in cast(dict[object, object], value))


def _non_empty_string(value: object, *, maximum: int = POLICY_BUNDLE_MAX_STRING_LENGTH) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    if not normalized or normalized != value or len(value.encode("utf-8")) > maximum:
        return None
    return normalized


def _strict_utc_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.endswith("Z"):
        return None
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        return None
    return parsed


def _json_value(value: object, *, depth: int = 0) -> JsonValue:
    if depth > POLICY_BUNDLE_MAX_DEPTH:
        raise ValueError("limit_depth")
    if value is None or isinstance(value, (bool, str)):
        if isinstance(value, str) and len(value.encode("utf-8")) > POLICY_BUNDLE_MAX_STRING_LENGTH:
            raise ValueError("limit_string")
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        raise ValueError("unsupported_number")
    if _is_object_list(value):
        if len(value) > POLICY_BUNDLE_MAX_COLLECTION_ITEMS:
            raise ValueError("limit_collection")
        return [_json_value(item, depth=depth + 1) for item in value]
    if _is_object_mapping(value):
        if len(value) > POLICY_BUNDLE_MAX_COLLECTION_ITEMS:
            raise ValueError("limit_collection")
        result: dict[str, JsonValue] = {}
        for key, item in value.items():
            if len(key.encode("utf-8")) > 128:
                raise ValueError("limit_key")
            result[key] = _json_value(item, depth=depth + 1)
        return result
    raise ValueError("invalid_json_value")


def _mapping(value: JsonValue) -> dict[str, JsonValue] | None:
    return value if isinstance(value, dict) else None


def _unsigned_bundle_core(policy_bundle: dict[str, object]) -> dict[str, JsonValue]:
    normalized = _json_value(policy_bundle)
    core = _mapping(normalized)
    if core is None:
        raise ValueError("invalid_bundle")
    result = dict(core)
    _ = result.pop("bundleHash", None)
    verifier = _mapping(result.get("verifier"))
    if verifier is None:
        raise ValueError("invalid_verifier")
    normalized_verifier = dict(verifier)
    _ = normalized_verifier.pop("signature", None)
    _ = normalized_verifier.pop("publicKeyPem", None)
    result["verifier"] = normalized_verifier
    return result


def computed_policy_bundle_v2_hash(policy_bundle: dict[str, object]) -> str:
    """Return the integrity hash for the signed v2 envelope core."""

    digest = hashlib.sha256(canonical_json_bytes(_unsigned_bundle_core(policy_bundle))).hexdigest()
    return f"sha256:{digest}"


def canonical_policy_bundle_v2_payload(policy_bundle: dict[str, object]) -> bytes:
    """Return the exact bytes covered by the v2 RSA-PSS signature."""

    core = _unsigned_bundle_core(policy_bundle)
    bundle_hash = _non_empty_string(policy_bundle.get("bundleHash"), maximum=128)
    if bundle_hash is None:
        raise ValueError("missing_bundle_hash")
    return canonical_json_bytes({**core, "bundleHash": bundle_hash})


def payload_hash_for_policy_bundle_v2(policy_bundle: dict[str, object]) -> str:
    payload = policy_bundle.get("payload")
    if not _is_object_mapping(payload):
        raise ValueError("invalid_payload")
    document = parse_policy_document_yaml(canonical_json_bytes(_json_value(payload)))
    digest = hashlib.sha256(canonical_policy_document_bytes(document)).hexdigest()
    return f"sha256:{digest}"


def _validate_keys(value: dict[str, object], allowed: frozenset[str]) -> bool:
    return all(key in allowed or key.startswith("x-") for key in value)


def _is_sha256_digest(value: object) -> bool:
    return isinstance(value, str) and _SHA256_DIGEST_PATTERN.fullmatch(value) is not None


def _validate_rollback(value: object) -> str | None:
    if value is None:
        return None
    if not _is_object_mapping(value) or not _validate_keys(value, _ALLOWED_ROLLBACK_KEYS):
        return "invalid_rollback"
    required_strings = (
        "rollbackOfBundleHash",
        "lastGoodBundleHash",
        "reason",
        "actor",
        "createdAt",
        "authorization",
    )
    if any(_non_empty_string(value.get(key)) is None for key in required_strings):
        return "invalid_rollback"
    if not _is_sha256_digest(value.get("rollbackOfBundleHash")) or not _is_sha256_digest(
        value.get("lastGoodBundleHash")
    ):
        return "invalid_rollback"
    versions = (value.get("rollbackOfBundleVersion"), value.get("lastGoodBundleVersion"))
    if any(not isinstance(version, int) or isinstance(version, bool) or version < 1 for version in versions):
        return "invalid_rollback"
    if _strict_utc_timestamp(value.get("createdAt")) is None:
        return "invalid_rollback"
    return None


def _verify_signature(
    policy_bundle: dict[str, object],
    *,
    trusted_verification_keys: tuple[PolicyBundleVerificationKey, ...],
    anchored_verification_keys: tuple[PolicyBundleVerificationKey, ...],
) -> str | None:
    verifier = policy_bundle.get("verifier")
    if not _is_object_mapping(verifier) or not _validate_keys(verifier, _ALLOWED_VERIFIER_KEYS):
        return "invalid_verifier"
    if verifier.get("algorithm") != "rsa-pss-sha256":
        return "invalid_verifier"
    key_id = _non_empty_string(verifier.get("keyId"), maximum=128)
    signature = _non_empty_string(verifier.get("signature"))
    if key_id is None or signature is None:
        return "invalid_verifier"
    signing_key = resolve_policy_bundle_signing_key(key_id, trusted_verification_keys)
    if signing_key is None:
        return "untrusted_signing_key"
    if not signing_key_is_trusted(signing_key, anchored_verification_keys):
        return "untrusted_signing_key"
    if not signing_key_is_current(signing_key):
        return "untrusted_signing_key"
    key_fingerprint = verifier.get("keyFingerprint")
    if key_fingerprint is not None and key_fingerprint != signing_key.fingerprint_sha256:
        return "untrusted_signing_key"
    supplied_public_key = verifier.get("publicKeyPem")
    if supplied_public_key is not None and supplied_public_key != signing_key.public_key_pem:
        return "untrusted_signing_key"
    try:
        public_key = serialization.load_pem_public_key(signing_key.public_key_pem.encode("utf-8"))
    except (UnsupportedAlgorithm, ValueError, TypeError):
        return "invalid_verifier"
    if not isinstance(public_key, RSAPublicKey):
        return "invalid_verifier"
    try:
        signature_bytes = base64.b64decode(signature, validate=True)
    except (binascii.Error, ValueError):
        return "invalid_verifier"
    salt_length = padding.calculate_max_pss_salt_length(public_key, hashes.SHA256())
    try:
        public_key.verify(
            signature_bytes,
            canonical_policy_bundle_v2_payload(policy_bundle),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=salt_length),
            hashes.SHA256(),
        )
    except (InvalidSignature, ValueError, TypeError):
        return "bundle_signature_invalid"
    return None


def validated_policy_bundle_v2_payload(
    policy_bundle: dict[str, object],
    *,
    trusted_verification_keys: tuple[PolicyBundleVerificationKey, ...] = (),
    anchored_verification_keys: tuple[PolicyBundleVerificationKey, ...] = (),
    now: datetime | None = None,
) -> tuple[dict[str, object] | None, str | None]:
    """Validate one bounded signed v2 envelope and its canonical policy document."""

    try:
        encoded = canonical_json_bytes(_json_value(policy_bundle))
    except ValueError as error:
        return None, str(error)
    if len(encoded) > POLICY_BUNDLE_MAX_BYTES:
        return None, "limit_bytes"
    if not _validate_keys(policy_bundle, _ALLOWED_TOP_LEVEL):
        return None, "unknown_field"
    required = _ALLOWED_TOP_LEVEL - {"expiresAt", "rollback"}
    if any(key not in policy_bundle for key in required):
        return None, "missing_required_field"
    if policy_bundle.get("envelopeVersion") != POLICY_BUNDLE_V2_ENVELOPE_VERSION:
        return None, "unsupported_envelope_version"
    if policy_bundle.get("contractVersion") != POLICY_BUNDLE_V2_CONTRACT:
        return None, "unsupported_contract_version"
    bundle_version = policy_bundle.get("bundleVersion")
    if not isinstance(bundle_version, int) or isinstance(bundle_version, bool) or bundle_version < 1:
        return None, "invalid_bundle_version"
    if _non_empty_string(policy_bundle.get("workspaceId"), maximum=128) is None:
        return None, "invalid_workspace_id"
    canonicalization = policy_bundle.get("canonicalization")
    if canonicalization != POLICY_BUNDLE_V2_CANONICALIZATION:
        return None, "unsupported_canonicalization"
    issued_at = _strict_utc_timestamp(policy_bundle.get("issuedAt"))
    if issued_at is None:
        return None, "invalid_issued_at"
    expires_at_value = policy_bundle.get("expiresAt")
    expires_at = None if expires_at_value is None else _strict_utc_timestamp(expires_at_value)
    if expires_at_value is not None and expires_at is None:
        return None, "invalid_expires_at"
    if expires_at is not None and expires_at <= issued_at:
        return None, "invalid_expires_at"
    comparison_time = now or datetime.now(timezone.utc)
    if expires_at is not None and expires_at <= comparison_time:
        return None, "bundle_expired"
    rollback_error = _validate_rollback(policy_bundle.get("rollback"))
    if rollback_error is not None:
        return None, rollback_error
    try:
        expected_payload_hash = payload_hash_for_policy_bundle_v2(policy_bundle)
    except (PolicyDocumentError, ValueError):
        return None, "invalid_policy_document"
    if policy_bundle.get("payloadHash") != expected_payload_hash:
        return None, "payload_hash_mismatch"
    try:
        expected_bundle_hash = computed_policy_bundle_v2_hash(policy_bundle)
    except ValueError:
        return None, "invalid_bundle"
    if policy_bundle.get("bundleHash") != expected_bundle_hash:
        return None, "bundle_hash_mismatch"
    signature_error = _verify_signature(
        policy_bundle,
        trusted_verification_keys=trusted_verification_keys,
        anchored_verification_keys=anchored_verification_keys,
    )
    if signature_error is not None:
        return None, signature_error
    return policy_bundle, None


def validate_policy_bundle_v2_transition(
    policy_bundle: dict[str, object],
    *,
    current_bundle_version: int | None,
    current_bundle_hash: str | None,
    expected_last_good_bundle_version: int | None = None,
    expected_last_good_bundle_hash: str | None = None,
) -> str | None:
    """Reject replay, same-version substitution, and unsigned rollback semantics."""

    incoming_version = policy_bundle.get("bundleVersion")
    incoming_hash = policy_bundle.get("bundleHash")
    if not isinstance(incoming_version, int) or isinstance(incoming_version, bool):
        return "invalid_bundle_version"
    if not isinstance(incoming_hash, str):
        return "invalid_bundle_hash"
    if current_bundle_version is None:
        return None
    if current_bundle_hash is None:
        return "missing_current_bundle_hash"
    if incoming_version < current_bundle_version:
        return "bundle_downgrade_rejected"
    if incoming_version == current_bundle_version:
        return None if incoming_hash == current_bundle_hash else "bundle_version_conflict"
    rollback = policy_bundle.get("rollback")
    if rollback is None:
        return None
    if not _is_object_mapping(rollback):
        return "invalid_rollback"
    if (
        rollback.get("rollbackOfBundleHash") != current_bundle_hash
        or rollback.get("rollbackOfBundleVersion") != current_bundle_version
    ):
        return "rollback_target_mismatch"
    last_good_version = rollback.get("lastGoodBundleVersion")
    if (
        not isinstance(last_good_version, int)
        or isinstance(last_good_version, bool)
        or last_good_version >= current_bundle_version
    ):
        return "rollback_target_mismatch"
    if _non_empty_string(rollback.get("lastGoodBundleHash"), maximum=128) is None:
        return "rollback_target_mismatch"
    if expected_last_good_bundle_version is not None and last_good_version != expected_last_good_bundle_version:
        return "rollback_last_good_mismatch"
    last_good_hash = rollback.get("lastGoodBundleHash")
    if expected_last_good_bundle_hash is not None and last_good_hash != expected_last_good_bundle_hash:
        return "rollback_last_good_mismatch"
    if _non_empty_string(rollback.get("authorization")) is None:
        return "rollback_authorization_missing"
    return None


def validated_policy_bundle_v2_acknowledgement(
    acknowledgement: dict[str, object],
    *,
    previous: dict[str, object] | None = None,
) -> tuple[dict[str, object] | None, str | None]:
    """Validate a monotonic explicit device acknowledgement transition."""

    if not _validate_keys(acknowledgement, _ALLOWED_ACK_KEYS):
        return None, "unknown_field"
    required = _ALLOWED_ACK_KEYS - {"errorCode"}
    if any(key not in acknowledgement for key in required):
        return None, "missing_required_field"
    if acknowledgement.get("contractVersion") != POLICY_BUNDLE_V2_CONTRACT:
        return None, "unsupported_contract_version"
    string_fields = ("workspaceId", "deviceId", "bundleHash")
    if any(_non_empty_string(acknowledgement.get(key), maximum=256) is None for key in string_fields):
        return None, "invalid_acknowledgement"
    bundle_version = acknowledgement.get("bundleVersion")
    sequence = acknowledgement.get("sequence")
    if (
        not isinstance(bundle_version, int)
        or isinstance(bundle_version, bool)
        or bundle_version < 1
        or not isinstance(sequence, int)
        or isinstance(sequence, bool)
        or sequence < 1
    ):
        return None, "invalid_acknowledgement"
    status = acknowledgement.get("status")
    if status not in POLICY_BUNDLE_V2_ACK_STATUSES:
        return None, "invalid_acknowledgement_status"
    if _strict_utc_timestamp(acknowledgement.get("observedAt")) is None:
        return None, "invalid_acknowledgement"
    error_code = acknowledgement.get("errorCode")
    if error_code is not None and _non_empty_string(error_code, maximum=128) is None:
        return None, "invalid_acknowledgement"
    if previous is None:
        return acknowledgement, None
    identity_fields = ("workspaceId", "deviceId", "bundleVersion", "bundleHash")
    if any(previous.get(key) != acknowledgement.get(key) for key in identity_fields):
        return None, "acknowledgement_identity_mismatch"
    previous_sequence = previous.get("sequence")
    previous_status = previous.get("status")
    if not isinstance(previous_sequence, int) or previous_status not in POLICY_BUNDLE_V2_ACK_STATUSES:
        return None, "invalid_previous_acknowledgement"
    if sequence < previous_sequence:
        return None, "acknowledgement_replay"
    if sequence == previous_sequence:
        return (acknowledgement, None) if acknowledgement == previous else (None, "acknowledgement_sequence_conflict")
    if status not in _ALLOWED_ACK_TRANSITIONS[str(previous_status)]:
        return None, "acknowledgement_transition_rejected"
    return acknowledgement, None
