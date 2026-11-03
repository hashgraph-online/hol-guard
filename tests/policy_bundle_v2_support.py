"""Test-side v2 bundle helpers: envelope hash, signed payload and one native ``validate_v2`` verdict."""

from __future__ import annotations

import time
from datetime import datetime

from codex_plugin_scanner.guard.native_policy_bundle import (
    PolicyBundleNativeError,
    native_rejection_code,
    policy_bundle_chunks,
    policy_bundle_verdict,
)
from codex_plugin_scanner.guard.policy_bundle_trusted_keys import PolicyBundleVerificationKey
from codex_plugin_scanner.guard.policy_bundle_v2 import policy_bundle_v2_now_micros
from tests.policy_bundle_parser_support import policy_bundle_paged_text


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
