"""Resident bridge for the ``trust_attestation_verify`` op.

Rust owns whether a signed trust attestation holds: the envelope's shape, the
payload under the verifier's rules, the claim it was made over, the key and
its rotation state, replay, expiry and the signature itself. This module ships
the attestation and the caller's verifier state to the resident, binds the
reply by ``request_id`` plus ``request_sha256`` and hands back the replay
identity the resident derived. Nothing is re-decided here, so a resident that
cannot answer leaves the attestation unverified rather than accepted.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from uuid import uuid4

from .native_context import _resolve_digest_home, ensure_resident_prerequisite
from .native_execution import _resident_request
from .native_store_policy import _payload

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
