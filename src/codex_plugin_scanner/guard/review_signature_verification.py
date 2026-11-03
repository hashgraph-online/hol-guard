"""Anchored signature verification for Guard Review contracts.

Guard Review admits a remote approval envelope or a decision-memory bundle
only when its signature verifies against key material the workspace has
already anchored. That is a verdict about key material, so Rust decides it:
this module reads the anchored keyrings out of the store, hands the resident
the signed document, and reports whichever code comes back.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from contextlib import contextmanager

from .native_policy_bundle import (
    NATIVE_UNAVAILABLE_REJECTION,
    PolicyBundleNativeError,
    PolicyBundleNativeUnavailableError,
    policy_bundle_chunks,
    policy_bundle_verdict,
)
from .policy_bundle_trusted_keys import (
    PolicyBundleVerificationKey,
    merge_policy_bundle_trusted_keys,
    policy_bundle_keys_from_supply_chain_keyring,
    policy_bundle_keys_from_wire,
    safe_load_policy_bundle_verification_keys,
)
from .review_oauth_binding import GuardReviewContractError
from .review_verification_keyring import REVIEW_VERIFICATION_KEYRING_SYNC_KEY

# The rejections the Review signature kinds speak. Anything else the resident
# reports is a keyring or transport failure, and keeps its own type.
_REVIEW_CONTRACT_CODES = frozenset(
    {
        "expired_signing_key",
        "invalid_signature",
        "invalid_signature_algorithm",
        "invalid_signing_key",
        "invalid_verification_key",
        "missing_signature",
        "missing_signing_key",
        "missing_signing_key_id",
        "missing_verification_keys",
        "review_verification_keys_invalid",
        "signature_mismatch",
        "signing_key_purpose_mismatch",
        "signing_key_workspace_mismatch",
        "unknown_signing_key",
        "untrusted_signing_key",
    }
)


@contextmanager
def _native_outage_is_not_a_key_verdict() -> Iterator[None]:
    """Report a resident outage as itself, never as an expired or unknown key."""

    try:
        yield
    except PolicyBundleNativeUnavailableError as error:
        raise GuardReviewContractError(NATIVE_UNAVAILABLE_REJECTION) from error
    except PolicyBundleNativeError as error:
        if error.code not in _REVIEW_CONTRACT_CODES:
            raise
        raise GuardReviewContractError(error.code) from error


def _anchored_review_verification_keys(store) -> tuple[PolicyBundleVerificationKey, ...]:
    with _native_outage_is_not_a_key_verdict():
        return merge_policy_bundle_trusted_keys(
            policy_bundle_keys_from_supply_chain_keyring(store.get_sync_payload("supply_chain_bundle_keyring")),
            safe_load_policy_bundle_verification_keys(store.get_sync_payload("policy_bundle_keyring")),
            safe_load_policy_bundle_verification_keys(store.get_sync_payload(REVIEW_VERIFICATION_KEYRING_SYNC_KEY)),
        )


def validated_review_verification_keys_from_sync(
    value: object,
    *,
    store,
    workspace_id: str,
) -> tuple[PolicyBundleVerificationKey, ...]:
    """Admit purpose-scoped Review keys only when their material is already anchored."""

    anchored = _anchored_review_verification_keys(store)
    with _native_outage_is_not_a_key_verdict():
        result = policy_bundle_verdict(
            "validate_review_sync_keys",
            {
                "raw": value,
                "anchored_keys": [key.to_dict() for key in anchored],
                "workspace_id": workspace_id,
                "now": time.time(),
            },
        )
        return policy_bundle_keys_from_wire(result.get("keys"))


def _verify_signed_payload(
    payload: dict[str, object],
    *,
    signature_algorithm: str,
    store,
    expected_key_purpose: str | None = None,
    expected_workspace_id: str | None = None,
) -> None:
    anchored = _anchored_review_verification_keys(store)
    with _native_outage_is_not_a_key_verdict():
        policy_bundle_verdict(
            "verify_signed_review_payload",
            {
                "signature_algorithm": signature_algorithm,
                "payload_chunks": policy_bundle_chunks(payload),
                "anchored_keys": [key.to_dict() for key in anchored],
                "expected_purpose": expected_key_purpose,
                "expected_workspace_id": expected_workspace_id,
                "now": time.time(),
            },
        )
