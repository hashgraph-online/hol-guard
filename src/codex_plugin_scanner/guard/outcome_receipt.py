"""Privacy-safe receipts for locally verified Guard outcomes.

These receipts intentionally carry only outcome metadata and a SHA-256 evidence
digest. They never serialize prompts, source code, findings, file paths, commands,
secrets, tokens, usernames, hostnames, or report bodies.

A receipt is *operational evidence*, not a self-authenticating remote attestation:
- ``local_install_verified`` is valid only when tied to a server-issued handoff
  whose installer flow reached binary verification (or product corroboration).
- ``first_local_proof_generated`` records a digest of an already-produced local
  proof and its proof kind. The proof itself remains local unless the user
  explicitly shares it through another product flow.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Literal

from packaging.version import InvalidVersion, Version

SCHEMA_VERSION = "1"
_SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
_HANDOFF_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_PROOF_KIND_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_VERSION_TEXT_RE = re.compile(r"^[0-9][0-9A-Za-z.!+_-]{0,63}$")

Outcome = Literal["local_install_verified", "first_local_proof_generated"]
Verification = Literal[
    "binary_verified_handoff",
    "product_corroborated_handoff",
    "privacy_safe_local_receipt",
]

_ALLOWED_OUTCOMES = frozenset({"local_install_verified", "first_local_proof_generated"})
_ALLOWED_VERIFICATIONS = frozenset(
    {"binary_verified_handoff", "product_corroborated_handoff", "privacy_safe_local_receipt"}
)
_RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "outcome",
        "occurred_at",
        "hol_guard_version",
        "verification",
        "evidence_digest",
        "handoff_id",
        "proof_kind",
        "sensitive_content_included",
    }
)
_SENSITIVE_VALUE_MARKERS = frozenset(
    {
        "password",
        "private",
        "prompt",
        "secret",
        "sourcecode",
        "token",
        "username",
        "hostname",
    }
)


def _contains_sensitive_marker(value: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", value.lower())
    return any(marker in normalized for marker in _SENSITIVE_VALUE_MARKERS)


def _validate_utc_timestamp(value: object) -> None:
    if not isinstance(value, str) or not value.endswith("Z") or len(value) > 40:
        raise ValueError("occurred_at must be a bounded UTC ISO-8601 timestamp ending in Z")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as exc:
        raise ValueError("occurred_at must be a valid UTC ISO-8601 timestamp") from exc
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ValueError("occurred_at must be UTC")


def _validate_guard_version(value: object) -> None:
    if not isinstance(value, str) or not _VERSION_TEXT_RE.fullmatch(value):
        raise ValueError("hol_guard_version must be a bounded PEP 440 version string")
    try:
        Version(value)
    except InvalidVersion as exc:
        raise ValueError("hol_guard_version must be a valid PEP 440 version") from exc


def _validate_receipt_values(
    *,
    schema_version: object,
    outcome: object,
    occurred_at: object,
    hol_guard_version: object,
    verification: object,
    evidence_digest: object,
    handoff_id: object,
    proof_kind: object,
    sensitive_content_included: object,
) -> None:
    if schema_version != SCHEMA_VERSION:
        raise ValueError(f"schema_version must be {SCHEMA_VERSION}")
    if not isinstance(outcome, str) or outcome not in _ALLOWED_OUTCOMES:
        raise ValueError("unsupported outcome")
    if not isinstance(verification, str) or verification not in _ALLOWED_VERIFICATIONS:
        raise ValueError("unsupported verification method")
    _validate_utc_timestamp(occurred_at)
    _validate_guard_version(hol_guard_version)
    if not isinstance(evidence_digest, str) or not _SHA256_RE.fullmatch(evidence_digest):
        raise ValueError("evidence_digest must be a lowercase SHA-256 digest")
    if handoff_id is not None:
        if not isinstance(handoff_id, str) or not _HANDOFF_ID_RE.fullmatch(handoff_id):
            raise ValueError("handoff_id must use the bounded opaque identifier format")
        if _contains_sensitive_marker(handoff_id):
            raise ValueError("handoff_id must not contain sensitive-content markers")
    if proof_kind is not None:
        if not isinstance(proof_kind, str) or not _PROOF_KIND_RE.fullmatch(proof_kind):
            raise ValueError("proof_kind must use the bounded lowercase identifier format")
        if _contains_sensitive_marker(proof_kind):
            raise ValueError("proof_kind must not contain sensitive-content markers")
    if sensitive_content_included is not False:
        raise ValueError("outcome receipts must not include sensitive content")

    if outcome == "local_install_verified":
        if verification not in {"binary_verified_handoff", "product_corroborated_handoff"}:
            raise ValueError("local install requires verified handoff evidence")
        if handoff_id is None:
            raise ValueError("local install verification requires handoff_id")
        if proof_kind is not None:
            raise ValueError("local install receipt must not include proof_kind")
    else:
        if verification != "privacy_safe_local_receipt":
            raise ValueError("first local proof requires privacy_safe_local_receipt verification")
        if proof_kind is None:
            raise ValueError("first local proof requires proof_kind")


@dataclass(frozen=True, slots=True)
class GuardOutcomeReceipt:
    schema_version: Literal["1"]
    outcome: Outcome
    occurred_at: str
    hol_guard_version: str
    verification: Verification
    evidence_digest: str
    handoff_id: str | None
    proof_kind: str | None
    sensitive_content_included: Literal[False] = False

    def __post_init__(self) -> None:
        _validate_receipt_values(
            schema_version=self.schema_version,
            outcome=self.outcome,
            occurred_at=self.occurred_at,
            hol_guard_version=self.hol_guard_version,
            verification=self.verification,
            evidence_digest=self.evidence_digest,
            handoff_id=self.handoff_id,
            proof_kind=self.proof_kind,
            sensitive_content_included=self.sensitive_content_included,
        )

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def sha256_digest(data: bytes) -> str:
    """Hash local evidence without returning or retaining the evidence bytes."""
    return hashlib.sha256(data).hexdigest()


def _iso_utc(value: datetime | None) -> str:
    current = value or datetime.now(timezone.utc)
    if current.tzinfo is None:
        raise ValueError("occurred_at must be timezone-aware")
    return current.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def build_outcome_receipt(
    *,
    outcome: Outcome,
    hol_guard_version: str,
    verification: Verification,
    evidence_digest: str,
    handoff_id: str | None = None,
    proof_kind: str | None = None,
    occurred_at: datetime | None = None,
) -> GuardOutcomeReceipt:
    """Build a versioned receipt after an authoritative local outcome occurs."""
    return GuardOutcomeReceipt(
        schema_version=SCHEMA_VERSION,
        outcome=outcome,
        occurred_at=_iso_utc(occurred_at),
        hol_guard_version=hol_guard_version,
        verification=verification,
        evidence_digest=evidence_digest,
        handoff_id=handoff_id,
        proof_kind=proof_kind,
    )


def assert_privacy_safe_receipt(payload: dict[str, object]) -> None:
    """Validate the complete receipt schema and privacy/value invariants."""
    extras = set(payload) - _RECEIPT_FIELDS
    if extras:
        raise ValueError(f"outcome receipt has unsupported fields: {sorted(extras)!r}")
    missing = _RECEIPT_FIELDS - set(payload)
    if missing:
        raise ValueError(f"outcome receipt is missing required fields: {sorted(missing)!r}")
    _validate_receipt_values(
        schema_version=payload["schema_version"],
        outcome=payload["outcome"],
        occurred_at=payload["occurred_at"],
        hol_guard_version=payload["hol_guard_version"],
        verification=payload["verification"],
        evidence_digest=payload["evidence_digest"],
        handoff_id=payload["handoff_id"],
        proof_kind=payload["proof_kind"],
        sensitive_content_included=payload["sensitive_content_included"],
    )


def canonical_receipt_bytes(receipt: GuardOutcomeReceipt) -> bytes:
    """Return deterministic JSON bytes for transport/idempotency hashing."""
    return json.dumps(receipt.to_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")


def receipt_digest(receipt: GuardOutcomeReceipt) -> str:
    """Digest the safe receipt itself; this is an integrity/idempotency key."""
    return sha256_digest(canonical_receipt_bytes(receipt))
