"""Anchored signature verification for Guard Review contracts."""

from __future__ import annotations

import base64
from copy import deepcopy

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey

from .policy_bundle_trusted_keys import (
    PolicyBundleVerificationKey,
    merge_policy_bundle_trusted_keys,
    policy_bundle_keys_from_supply_chain_keyring,
    resolve_policy_bundle_signing_key,
    safe_load_policy_bundle_verification_keys,
    signing_key_is_current,
)
from .review_oauth_binding import GuardReviewContractError
from .review_verification_keyring import REVIEW_VERIFICATION_KEYRING_SYNC_KEY
from .stable_json import stable_json_serialize

_REMOTE_APPROVAL_KEY_PURPOSE = "remote_approval"
_REMOTE_APPROVAL_SIGNATURE_ALGORITHM = "rsa-pss-sha256"
_DECISION_MEMORY_SIGNATURE_ALGORITHM = "rsa-pss-sha256"
_SIGNED_PAYLOAD_STRIP_KEYS = ("payloadHash", "signature", "signatureAlgorithm", "verificationKeys", "bundleHash")


def _non_empty_string(value: object) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def _strip_keys(value: dict[str, object], keys: tuple[str, ...]) -> dict[str, object]:
    clone = deepcopy(value)
    for key in keys:
        clone.pop(key, None)
    return clone


def _canonical_signed_payload(value: dict[str, object]) -> str:
    return stable_json_serialize(_strip_keys(value, _SIGNED_PAYLOAD_STRIP_KEYS))


def _verification_keys_from_payload(value: object) -> tuple[PolicyBundleVerificationKey, ...]:
    if not isinstance(value, list) or not value:
        raise GuardReviewContractError("missing_verification_keys")
    parsed: list[PolicyBundleVerificationKey] = []
    for item in value:
        if not isinstance(item, dict):
            raise GuardReviewContractError("invalid_verification_key")
        parsed.append(PolicyBundleVerificationKey.from_dict(item))
    return tuple(parsed)


def _anchored_review_verification_keys(store) -> tuple[PolicyBundleVerificationKey, ...]:
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

    if not isinstance(value, list):
        raise GuardReviewContractError("review_verification_keys_invalid")
    keys = safe_load_policy_bundle_verification_keys(value)
    if not keys or len(keys) != len(value):
        raise GuardReviewContractError("review_verification_keys_invalid")
    anchored_fingerprints = {key.fingerprint_sha256 for key in _anchored_review_verification_keys(store)}
    for key in keys:
        if key.purpose != _REMOTE_APPROVAL_KEY_PURPOSE:
            raise GuardReviewContractError("signing_key_purpose_mismatch")
        if key.workspace_id != workspace_id:
            raise GuardReviewContractError("signing_key_workspace_mismatch")
        if key.fingerprint_sha256 not in anchored_fingerprints:
            raise GuardReviewContractError("unknown_signing_key")
        if key.state == "revoked" or not signing_key_is_current(key):
            raise GuardReviewContractError("expired_signing_key")
    return keys


def _resolve_anchored_signing_key(
    *,
    advertised_keys: tuple[PolicyBundleVerificationKey, ...],
    anchored_keys: tuple[PolicyBundleVerificationKey, ...],
    key_id: str,
    expected_purpose: str | None = None,
    expected_workspace_id: str | None = None,
) -> PolicyBundleVerificationKey:
    signing_key = resolve_policy_bundle_signing_key(key_id, anchored_keys)
    if signing_key is None:
        raise GuardReviewContractError("unknown_signing_key")
    advertised_key = resolve_policy_bundle_signing_key(key_id, advertised_keys)
    if advertised_key is None:
        raise GuardReviewContractError("missing_signing_key")
    if advertised_key.fingerprint_sha256 != signing_key.fingerprint_sha256:
        raise GuardReviewContractError("untrusted_signing_key")
    if expected_purpose is not None and (
        signing_key.purpose != expected_purpose or advertised_key.purpose != expected_purpose
    ):
        raise GuardReviewContractError("signing_key_purpose_mismatch")
    if expected_workspace_id is not None and (
        signing_key.workspace_id != expected_workspace_id or advertised_key.workspace_id != expected_workspace_id
    ):
        raise GuardReviewContractError("signing_key_workspace_mismatch")
    if not signing_key_is_current(signing_key):
        raise GuardReviewContractError("expired_signing_key")
    return signing_key


def _verify_signed_payload(
    payload: dict[str, object],
    *,
    signature_algorithm: str,
    store,
    expected_key_purpose: str | None = None,
    expected_workspace_id: str | None = None,
) -> None:
    if signature_algorithm not in {_REMOTE_APPROVAL_SIGNATURE_ALGORITHM, _DECISION_MEMORY_SIGNATURE_ALGORITHM}:
        raise GuardReviewContractError("invalid_signature_algorithm")
    signature = _non_empty_string(payload.get("signature"))
    if signature is None:
        raise GuardReviewContractError("missing_signature")
    key_id = _non_empty_string(payload.get("issuerKeyId")) or _non_empty_string(payload.get("keyId"))
    if key_id is None:
        verifier = payload.get("verifier")
        if isinstance(verifier, dict):
            key_id = _non_empty_string(verifier.get("keyId"))
    advertised_keys = _verification_keys_from_payload(payload.get("verificationKeys"))
    if key_id is None and len(advertised_keys) == 1:
        key_id = advertised_keys[0].key_id
    if key_id is None:
        raise GuardReviewContractError("missing_signing_key_id")
    signing_key = _resolve_anchored_signing_key(
        advertised_keys=advertised_keys,
        anchored_keys=_anchored_review_verification_keys(store),
        key_id=key_id,
        expected_purpose=expected_key_purpose,
        expected_workspace_id=expected_workspace_id,
    )
    try:
        public_key = serialization.load_pem_public_key(signing_key.public_key_pem.encode("utf-8"))
    except (UnsupportedAlgorithm, ValueError, TypeError) as error:
        raise GuardReviewContractError("invalid_signing_key") from error
    if not isinstance(public_key, RSAPublicKey):
        raise GuardReviewContractError("invalid_signing_key")
    try:
        signature_bytes = base64.b64decode(signature)
    except Exception as error:  # pragma: no cover - defensive
        raise GuardReviewContractError("invalid_signature") from error
    canonical_payload = _canonical_signed_payload(payload).encode("utf-8")
    try:
        public_key.verify(
            signature_bytes,
            canonical_payload,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.AUTO),
            hashes.SHA256(),
        )
    except (InvalidSignature, ValueError, TypeError) as error:
        raise GuardReviewContractError("signature_mismatch") from error
