"""Signed canonical Guard policy bundle v2 validation and state transitions.

Rust owns envelope validation, canonical hashing, the policy-document payload
hash, signature verification, transition and acknowledgement authority.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from .native_policy_bundle import (
    PolicyBundleNativeError,
    native_rejection_code,
    policy_bundle_chunks,
    policy_bundle_verdict,
)

POLICY_BUNDLE_V2_CONTRACT = "guard-policy-bundle.v2"
POLICY_BUNDLE_V2_CANONICALIZATION = {"algorithm": "rfc8785", "version": "1"}
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


def policy_bundle_v2_now_micros(now: datetime | None) -> int:
    return ((now or datetime.now(timezone.utc)) - _EPOCH) // timedelta(microseconds=1)


def validate_policy_bundle_v2_transition(
    policy_bundle: dict[str, object],
    *,
    current_bundle_version: int | None,
    current_bundle_hash: str | None,
    expected_last_good_bundle_version: int | None = None,
    expected_last_good_bundle_hash: str | None = None,
    current_cloud_exceptions_issued_at: str | None = None,
    current_cloud_exceptions_hash: str | None = None,
) -> str | None:
    """Reject replay, same-version substitution, and unsigned rollback semantics.

    ``current_cloud_exceptions_issued_at`` is the signed issue time of the Cloud
    exception set already accepted for this bundle, and
    ``current_cloud_exceptions_hash`` that set's identity. The same bundle may
    come back with a newer set, never an older one or none, and at the same
    issue time only with the set already accepted.
    """

    signed = {
        key: policy_bundle[key]
        for key in ("bundleVersion", "bundleHash", "rollback", "cloudExceptions", "cloudExceptionsIssuedAt")
        if key in policy_bundle
    }
    try:
        policy_bundle_verdict(
            "v2_transition",
            {
                "bundle_chunks": policy_bundle_chunks(signed),
                "current_version": current_bundle_version,
                "current_hash": current_bundle_hash,
                "expected_last_good_version": expected_last_good_bundle_version,
                "expected_last_good_hash": expected_last_good_bundle_hash,
                "current_cloud_exceptions_issued_at": current_cloud_exceptions_issued_at,
                "current_cloud_exceptions_hash": current_cloud_exceptions_hash,
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
