"""Verify a signed trust attestation through the resident, from tests.

The resident's ``trust_attestation_verify`` op owns whether an attestation
holds: the envelope, the payload under the verifier's rules, the claim, the
key and its rotation state, replay, expiry and the signature. Guard itself
only signs attestations; verifying them is the uploader's job. Tests keep this
client to pin what the op decides against attestations Guard signed.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

from cryptography.hazmat.primitives import serialization

from codex_plugin_scanner.guard.native_context import _resolve_digest_home, ensure_resident_prerequisite
from codex_plugin_scanner.guard.native_execution import _resident_request
from codex_plugin_scanner.guard.native_store_policy import _payload
from codex_plugin_scanner.guard.runtime.evidence_hash import guard_evidence_hash
from codex_plugin_scanner.guard.runtime.trust_attestation import (
    GuardTrustAttestationSigningConfig,
    GuardTrustAttestationVerificationKey,
    _load_private_key,
    _public_key_fingerprint,
)

TRUST_ATTESTATION_VERIFY_FEATURE = "trust-attestation-verify-v1"
_REQUEST_SCHEMA = "guard-trust-attestation-verify-request.v1"
_RESULT_SCHEMA = "guard-trust-attestation-verify-result.v1"
_TIMEOUT_SECONDS = 10.0
_MAX_REQUEST_BYTES = 1024 * 1024


class TrustAttestationUnavailableError(ValueError):
    """The verifier could not be reached, so the attestation is not verified.

    A ``ValueError``, because every caller already treats a failed
    verification that way and an unreachable verifier must not read as a pass.
    """

    def __init__(self) -> None:
        super().__init__("Trust attestation verification is unavailable")


def native_verify_trust_attestation(
    *,
    payload: Mapping[str, object],
    envelope: Mapping[str, object],
    claim: Mapping[str, object] | None,
    trusted_keys: Sequence[Mapping[str, object]] | None,
    policy: Mapping[str, object],
    guard_home: Path | None = None,
) -> str:
    """Return the replay key of a verified attestation; raise when it is not.

    ``policy`` carries the verifier's own state under the contract's names.
    A refusal is raised as ``ValueError`` with the resident's wording, which
    is the wording the Python verifier used before the decision moved.
    """

    home = Path(_resolve_digest_home(guard_home))
    if not ensure_resident_prerequisite(home):
        raise TrustAttestationUnavailableError
    wire: dict[str, object] = {
        "schema": _REQUEST_SCHEMA,
        "request_id": f"trust-attestation-verify-{uuid4().hex}",
        "payload": dict(payload),
        "envelope": dict(envelope),
        "claim": dict(claim) if claim is not None else None,
        "trusted_keys": [dict(key) for key in trusted_keys] if trusted_keys is not None else None,
        "policy": dict(policy),
    }
    try:
        response = _resident_request(
            operation="trust_attestation_verify",
            request=wire,
            guard_home=home,
            timeout_seconds=_TIMEOUT_SECONDS,
            required_feature=TRUST_ATTESTATION_VERIFY_FEATURE,
            response_schema=_RESULT_SCHEMA,
            max_request_bytes=_MAX_REQUEST_BYTES,
            record_success=False,
        )
    except (TypeError, ValueError, OSError, RuntimeError):
        raise TrustAttestationUnavailableError from None
    answer = _payload(response, wire, home)
    if not isinstance(answer, dict):
        raise TrustAttestationUnavailableError
    outcome = answer.get("outcome")
    if outcome == "refused":
        message = answer.get("message")
        raise ValueError(message if isinstance(message, str) else "Trust attestation is refused")
    replay_key = answer.get("replay_key")
    if outcome != "verified" or not isinstance(replay_key, str) or not replay_key:
        raise TrustAttestationUnavailableError
    return replay_key


@dataclass(frozen=True, slots=True)
class GuardTrustAttestationVerificationPolicy:
    """Local verification state for rotation, revocation, and replay checks."""

    revoked_key_ids: frozenset[str] = frozenset()
    key_not_before: tuple[tuple[str, str], ...] = ()
    minimum_sequence: int | None = None
    seen_replay_keys: frozenset[str] = frozenset()
    now: str | None = None
    require_nonce: bool = True


def build_trust_attestation_verification_key(
    config: GuardTrustAttestationSigningConfig,
) -> GuardTrustAttestationVerificationKey:
    private_key = _load_private_key(config.private_key_pem)
    public_key_pem = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
        .strip()
    )
    return GuardTrustAttestationVerificationKey(
        key_id=config.active_key_id,
        public_key_pem=public_key_pem,
        fingerprint_sha256=_public_key_fingerprint(public_key_pem),
        public_jwk_thumbprint=config.public_jwk_thumbprint,
    )


def _verification_key_wire(key: GuardTrustAttestationVerificationKey) -> dict[str, object]:
    """One trusted key under the names the verification contract reads."""

    return {
        "key_id": key.key_id,
        "public_key_pem": key.public_key_pem,
        "fingerprint_sha256": key.fingerprint_sha256,
        "public_jwk_thumbprint": key.public_jwk_thumbprint,
    }


def verify_trust_attestation(
    *,
    payload: Mapping[str, object],
    envelope: Mapping[str, object],
    trusted_keys: tuple[GuardTrustAttestationVerificationKey, ...] | None = None,
    policy: GuardTrustAttestationVerificationPolicy | None = None,
    claim: Mapping[str, object] | None = None,
) -> str:
    """Return the replay identity of a verified attestation, or raise.

    The verifier itself is the native runtime's; this call only puts the
    attestation and the caller's own rotation, replay and expiry state on the
    wire. A refusal comes back as ``ValueError`` carrying the runtime's
    wording, and a runtime that cannot answer raises as well, so nothing here
    can read an attestation as verified.
    """

    verification_policy = policy or GuardTrustAttestationVerificationPolicy(require_nonce=False)
    return native_verify_trust_attestation(
        payload=dict(payload),
        envelope=dict(envelope),
        claim=dict(claim) if claim is not None else None,
        trusted_keys=([_verification_key_wire(key) for key in trusted_keys] if trusted_keys is not None else None),
        policy={
            "revoked_key_ids": sorted(verification_policy.revoked_key_ids),
            "key_not_before": dict(verification_policy.key_not_before),
            # The verifier reads the limit as digits, not as a fixed-width
            # number: a Python integer has no width bound, and a limit it
            # cannot decode would reach the caller as an unavailable runtime
            # instead of the monotonic refusal the verifier owes it.
            "minimum_sequence": (
                None if verification_policy.minimum_sequence is None else str(verification_policy.minimum_sequence)
            ),
            "seen_replay_keys": sorted(verification_policy.seen_replay_keys),
            "now": verification_policy.now,
            "require_nonce": verification_policy.require_nonce,
        },
    )


def trust_attestation_replay_key(payload: Mapping[str, object]) -> str:
    """Return the stable verifier-side replay identity for an attestation."""

    return guard_evidence_hash(
        {
            "domainSeparator": payload.get("domainSeparator"),
            "nonce": payload.get("nonce"),
            "itemId": payload.get("itemId"),
            "scope": payload.get("scope"),
            "layerId": payload.get("layerId"),
            "workspaceId": payload.get("workspaceId"),
            "repositoryId": payload.get("repositoryId"),
        }
    )
