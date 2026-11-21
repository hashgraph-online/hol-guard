"""Claim-hash compatibility for native workspace review bindings."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy

from .review_native_claim_bindings import (
    NATIVE_BINDING_FIELDS,
    native_binding_commitment_matches,
)
from .stable_digest import sha256_content_digest
from .stable_json import stable_json_serialize

_CLAIM_HASH_EXCLUDED_KEYS = (
    "claimHash",
    "exactReviewCapability",
    "recommendedScope",
    "nativeActionBinding",
    "nativeIntentBinding",
    "nativePolicyBinding",
)
_LEGACY_CLAIM_HASH_EXCLUDED_KEYS = (
    *_CLAIM_HASH_EXCLUDED_KEYS,
    "nativeBindingVersion",
    "nativeBindingDigest",
)


def _sha256_hex(value: str) -> str:
    return sha256_content_digest(value.encode("utf-8"))


def _strip_keys(value: dict[str, object], keys: tuple[str, ...]) -> dict[str, object]:
    clone = deepcopy(value)
    for key in keys:
        clone.pop(key, None)
    return clone


def _non_empty_string(value: object) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def compute_local_review_request_claim_hash(claim: dict[str, object]) -> str:
    return _sha256_hex(stable_json_serialize(_strip_keys(claim, _CLAIM_HASH_EXCLUDED_KEYS)))


def compute_legacy_local_review_request_claim_hash(claim: dict[str, object]) -> str:
    return _sha256_hex(stable_json_serialize(_strip_keys(claim, _LEGACY_CLAIM_HASH_EXCLUDED_KEYS)))


def _has_native_bindings(claim: Mapping[str, object]) -> bool:
    return any(isinstance(claim.get(key), str) for key in NATIVE_BINDING_FIELDS) or any(
        key in claim for key in ("nativeBindingVersion", "nativeBindingDigest")
    )


def local_review_request_claim_hash_matches(
    claim: dict[str, object], expected_hash: object, *, allow_legacy: bool = False
) -> bool:
    if _has_native_bindings(claim) and not native_binding_commitment_matches(claim):
        return False
    source_hash = _non_empty_string(expected_hash)
    if source_hash == compute_local_review_request_claim_hash(claim):
        return True
    return allow_legacy and source_hash == compute_legacy_local_review_request_claim_hash(claim)
