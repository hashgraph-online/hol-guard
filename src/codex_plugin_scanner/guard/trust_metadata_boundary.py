"""Separate untrusted adapter trust claims from locally derived metadata."""

from __future__ import annotations

import re
from typing import Literal, TypedDict

UNVERIFIED_ADAPTER_EVIDENCE_KEY = "unverifiedAdapterEvidence"


class UnverifiedAdapterTrustEvidence(TypedDict):
    """Non-authoritative adapter claims retained for diagnostics only."""

    source: Literal["adapter_metadata"]
    verificationStatus: Literal["unverified"]
    affectsTrustScore: Literal[False]
    trustClaims: dict[str, object]


_NORMALIZE_KEY_RE = re.compile(r"[^a-z0-9]+")
_TOP_LEVEL_TRUST_KEYS = frozenset(
    {
        "affectsv4score",
        "attestation",
        "attestationbindings",
        "attestationref",
        "attestations",
        "attestationstatus",
        "attestationverification",
        "evidenceauthority",
        "signature",
        "signatures",
        "signedtrust",
        "trustlayer",
        "trustlayers",
        "trustresolution",
        "trustscore",
        "truststatus",
        "verification",
        "verified",
    }
)
_PROOF_KEY_MARKERS = (
    "attestation",
    "signature",
    "publickey",
    "privatekey",
    "fingerprintsha256",
    "keyid",
    "payloadhash",
    "signedat",
)


def _normalized_key(value: object) -> str:
    return _NORMALIZE_KEY_RE.sub("", str(value).lower())


def _is_untrusted_trust_key(key: object) -> bool:
    normalized = _normalized_key(key)
    return normalized in _TOP_LEVEL_TRUST_KEYS or normalized.startswith("trustattestation")


def _is_prior_proof_key(key: object) -> bool:
    normalized = _normalized_key(key)
    return any(marker in normalized for marker in _PROOF_KEY_MARKERS)


def _without_prior_proofs(value: object) -> object:
    if isinstance(value, dict):
        return {
            str(key): _without_prior_proofs(item)
            for key, item in value.items()
            if not _is_prior_proof_key(key)
        }
    if isinstance(value, (list, tuple)):
        return [_without_prior_proofs(item) for item in value]
    return value


def _existing_unverified_claims(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        return {}
    if value.get("source") != "adapter_metadata" or value.get("verificationStatus") != "unverified":
        return {}
    claims = value.get("trustClaims")
    if not isinstance(claims, dict):
        return {}
    return {str(key): _without_prior_proofs(item) for key, item in claims.items()}


def separate_untrusted_adapter_trust_metadata(metadata: dict[str, object]) -> dict[str, object]:
    """Remove adapter-authored trust/proof fields and retain safe claim text.

    The function is idempotent so inventory ingestion and later enrichment can
    both enforce the same boundary without nesting the evidence namespace.
    Cryptographic proof material is intentionally discarded instead of copied.
    """

    clean: dict[str, object] = {}
    trust_claims = _existing_unverified_claims(metadata.get(UNVERIFIED_ADAPTER_EVIDENCE_KEY))
    for key, value in metadata.items():
        if key == UNVERIFIED_ADAPTER_EVIDENCE_KEY:
            continue
        if _is_prior_proof_key(key):
            continue
        if _is_untrusted_trust_key(key):
            trust_claims[str(key)] = _without_prior_proofs(value)
            continue
        clean[str(key)] = value
    if trust_claims:
        evidence: UnverifiedAdapterTrustEvidence = {
            "source": "adapter_metadata",
            "verificationStatus": "unverified",
            "affectsTrustScore": False,
            "trustClaims": trust_claims,
        }
        clean[UNVERIFIED_ADAPTER_EVIDENCE_KEY] = evidence
    return clean


__all__ = [
    "UNVERIFIED_ADAPTER_EVIDENCE_KEY",
    "UnverifiedAdapterTrustEvidence",
    "separate_untrusted_adapter_trust_metadata",
]
