"""Signed canonical Guard policy bundle v2 validation and state transitions.

Rust owns envelope validation, canonical hashing, signature verification,
transition and acknowledgement authority. The only Python-computed input is
the canonical policy-document payload hash, which the resident requests as
evidence when the bundle carries a payload document.
"""

from __future__ import annotations

import hashlib
import time
from datetime import datetime, timedelta, timezone
from typing import TypeGuard, cast

from .native_policy_bundle import PolicyBundleNativeError, policy_bundle_chunks, policy_bundle_verdict
from .policy_bundle_trusted_keys import PolicyBundleVerificationKey
from .policy_document import JsonValue, canonical_json_bytes, canonical_policy_document_bytes
from .policy_document_yaml import PolicyDocumentError, parse_policy_document_yaml

POLICY_BUNDLE_V2_CONTRACT = "guard-policy-bundle.v2"
POLICY_BUNDLE_V2_CANONICALIZATION = {"algorithm": "rfc8785", "version": "1"}
_MAX_DEPTH = 40
_MAX_COLLECTION_ITEMS = 2_048
_MAX_STRING_BYTES = 1_048_576
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def _is_object_mapping(value: object) -> TypeGuard[dict[str, object]]:
    return isinstance(value, dict) and all(isinstance(key, str) for key in cast(dict[object, object], value))


def _json_value(value: object, *, depth: int = 0) -> JsonValue:
    if depth > _MAX_DEPTH:
        raise ValueError("limit_depth")
    if value is None or isinstance(value, (bool, str, int)):
        if isinstance(value, str) and len(value.encode("utf-8")) > _MAX_STRING_BYTES:
            raise ValueError("limit_string")
        return value
    if isinstance(value, float):
        raise ValueError("unsupported_number")
    if isinstance(value, list):
        if len(value) > _MAX_COLLECTION_ITEMS:
            raise ValueError("limit_collection")
        return [_json_value(item, depth=depth + 1) for item in value]
    if _is_object_mapping(value):
        if len(value) > _MAX_COLLECTION_ITEMS:
            raise ValueError("limit_collection")
        return {key: _json_value(item, depth=depth + 1) for key, item in value.items()}
    raise ValueError("invalid_json_value")


def payload_hash_for_policy_bundle_v2(policy_bundle: dict[str, object]) -> str:
    payload = policy_bundle.get("payload")
    if not _is_object_mapping(payload):
        raise ValueError("invalid_payload")
    document = parse_policy_document_yaml(canonical_json_bytes(_json_value(payload)))
    digest = hashlib.sha256(canonical_policy_document_bytes(document)).hexdigest()
    return f"sha256:{digest}"


def policy_bundle_v2_evidence(policy_bundle: dict[str, object]) -> dict[str, object]:
    """Policy-document payload hash evidence the resident asks for."""

    try:
        return {"hash": payload_hash_for_policy_bundle_v2(policy_bundle)}
    except (PolicyDocumentError, ValueError):
        return {"error": True}


def policy_bundle_v2_now_micros(now: datetime | None) -> int:
    return ((now or datetime.now(timezone.utc)) - _EPOCH) // timedelta(microseconds=1)


def _document(policy_bundle: dict[str, object]) -> dict[str, object]:
    return {"bundle_chunks": policy_bundle_chunks(policy_bundle)}


def computed_policy_bundle_v2_hash(policy_bundle: dict[str, object]) -> str:
    """Return the integrity hash for the signed v2 envelope core."""

    return str(policy_bundle_verdict("v2_bundle_hash", _document(policy_bundle))["value"])


def canonical_policy_bundle_v2_payload(policy_bundle: dict[str, object]) -> bytes:
    """Return the exact bytes covered by the v2 RSA-PSS signature."""

    return str(policy_bundle_verdict("v2_canonical_payload", _document(policy_bundle))["value"]).encode("utf-8")


def validated_policy_bundle_v2_payload(
    policy_bundle: dict[str, object],
    *,
    trusted_verification_keys: tuple[PolicyBundleVerificationKey, ...] = (),
    anchored_verification_keys: tuple[PolicyBundleVerificationKey, ...] = (),
    now: datetime | None = None,
) -> tuple[dict[str, object] | None, str | None]:
    """Validate one bounded signed v2 envelope and its canonical policy document."""

    request: dict[str, object] = {
        "trusted_keys": [key.to_dict() for key in trusted_verification_keys],
        "anchored_keys": [key.to_dict() for key in anchored_verification_keys],
        "now_micros": policy_bundle_v2_now_micros(now),
        "key_now": time.time(),
    }
    try:
        request["bundle_chunks"] = policy_bundle_chunks(policy_bundle)
        result = policy_bundle_verdict("validate_v2", request)
        if result.get("needs_evidence") is True:
            result = policy_bundle_verdict(
                "validate_v2", {**request, "evidence": policy_bundle_v2_evidence(policy_bundle)}
            )
        if result.get("ok") is not True:
            return None, "native_policy_bundle_authority_schema_mismatch"
    except PolicyBundleNativeError as error:
        return None, "unsupported_number" if error.code == "non_finite_number" else error.code
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

    signed = {key: policy_bundle[key] for key in ("bundleVersion", "bundleHash", "rollback") if key in policy_bundle}
    try:
        policy_bundle_verdict(
            "v2_transition",
            {
                "bundle_chunks": policy_bundle_chunks(signed),
                "current_version": current_bundle_version,
                "current_hash": current_bundle_hash,
                "expected_last_good_version": expected_last_good_bundle_version,
                "expected_last_good_hash": expected_last_good_bundle_hash,
            },
        )
    except PolicyBundleNativeError as error:
        return error.code
    return None


def validated_policy_bundle_v2_acknowledgement(
    acknowledgement: dict[str, object],
    *,
    previous: dict[str, object] | None = None,
) -> tuple[dict[str, object] | None, str | None]:
    """Validate a monotonic explicit device acknowledgement transition."""

    try:
        policy_bundle_verdict("v2_acknowledgement", {"ack": acknowledgement, "previous": previous})
    except PolicyBundleNativeError as error:
        return None, error.code
    return acknowledgement, None
