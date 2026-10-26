"""Signed canonical Guard policy bundle v2 validation and state transitions.

Rust owns envelope validation, canonical hashing, the policy-document payload
hash, signature verification, transition and acknowledgement authority.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from .native_policy_bundle import (
    PolicyBundleNativeError,
    native_rejection_code,
    policy_bundle_chunks,
    policy_bundle_paged_text,
    policy_bundle_verdict,
)
from .policy_bundle_trusted_keys import PolicyBundleVerificationKey

POLICY_BUNDLE_V2_CONTRACT = "guard-policy-bundle.v2"
POLICY_BUNDLE_V2_CANONICALIZATION = {"algorithm": "rfc8785", "version": "1"}
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def policy_bundle_v2_now_micros(now: datetime | None) -> int:
    return ((now or datetime.now(timezone.utc)) - _EPOCH) // timedelta(microseconds=1)


def _document(policy_bundle: dict[str, object]) -> dict[str, object]:
    return {"bundle_chunks": policy_bundle_chunks(policy_bundle)}


def computed_policy_bundle_v2_hash(policy_bundle: dict[str, object]) -> str:
    """Return the integrity hash for the signed v2 envelope core."""

    return str(policy_bundle_verdict("v2_bundle_hash", _document(policy_bundle))["value"])


def canonical_policy_bundle_v2_payload(policy_bundle: dict[str, object]) -> bytes:
    """Return the exact bytes covered by the v2 RSA-PSS signature."""

    return policy_bundle_paged_text("v2_canonical_payload", _document(policy_bundle)).encode("utf-8")


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
        if result.get("ok") is not True:
            return None, "native_policy_bundle_authority_schema_mismatch"
    except PolicyBundleNativeError as error:
        return None, "unsupported_number" if error.code == "non_finite_number" else native_rejection_code(error)
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
        return native_rejection_code(error)
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
        return None, native_rejection_code(error)
    return acknowledgement, None
