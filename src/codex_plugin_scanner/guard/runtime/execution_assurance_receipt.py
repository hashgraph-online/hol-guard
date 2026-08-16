"""Typed execution-assurance receipt extending the Guard runtime receipt schema.

This module is a *supplement* to the existing ``GuardReceipt`` model in
``guard.models`` — it does **not** modify that dataclass.  Consumers compose
the two via :func:`receipt_assurance_payload`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final, cast

from .execution_assurance_contract import (
    EXECUTION_ASSURANCE_SCHEMA_VERSION,
    AtomicGuaranteeKind,
    GuardExecutionAssuranceBoundary,
    GuardExecutionAttestationTrust,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SCHEMA_VERSION: Final = EXECUTION_ASSURANCE_SCHEMA_VERSION
_MAX_PROOF_LINES: Final = 64
_MAX_PROOF_LINE_LENGTH: Final = 256
_MAX_TOTAL_PROOF_CHARS: Final = 64 * 256
_MAX_GUARANTEE_KINDS: Final = 64
_SHA256_HEX_LENGTH: Final = 64
_HEX_RE: Final = re.compile(r"[0-9a-f]{64}$")

# Pre-compute valid values once
_VALID_GUARANTEE_KINDS: Final = frozenset(k.value for k in AtomicGuaranteeKind)


# ---------------------------------------------------------------------------
# Validators (module-level free functions)
# ---------------------------------------------------------------------------


def _require_str(value: object, label: str, *, max_length: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > max_length:
        raise ValueError(f"{label} must be a non-empty string of at most {max_length} characters")
    return value


def _require_sha256(value: object, label: str) -> str:
    text = _require_str(value, label, max_length=_SHA256_HEX_LENGTH)
    if len(text) != _SHA256_HEX_LENGTH or not _HEX_RE.match(text):
        raise ValueError(f"{label} must be a lowercase SHA-256 hex digest")
    return text


def _require_enum(value: object, enum_type: type, label: str) -> None:
    if not isinstance(value, enum_type):
        raise ValueError(f"{label} must be a {enum_type.__name__}")


def _require_guarantee_kind(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty string")
    if value not in _VALID_GUARANTEE_KINDS:
        raise ValueError(f"{label} must be one of {sorted(_VALID_GUARANTEE_KINDS)}; got {value!r}")
    return value


def _require_proof_line(value: object, label: str, *, index: int) -> str:
    s = _require_str(value, label, max_length=_MAX_PROOF_LINE_LENGTH)
    if index < 0 or index >= _MAX_PROOF_LINES:
        raise ValueError(f"{label} index {index} out of range [0, {_MAX_PROOF_LINES})")
    return s


# ---------------------------------------------------------------------------
# Receipt dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ExecutionAssuranceReceipt:
    """Typed assurance fields for a Guard execution receipt.

    Composes alongside (does *not* extend) ``guard.models.GuardReceipt``.
    All fields are validated at construction via module-level free functions.
    """

    achieved_boundary: GuardExecutionAssuranceBoundary
    attestation_trust: GuardExecutionAttestationTrust
    execution_context_digest: str
    enforced_guarantee_kinds: tuple[str, ...] = ()
    absent_guarantee_kinds: tuple[str, ...] = ()
    terminal_statement_digest: str | None = None
    proof_lines: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_enum(
            self.achieved_boundary,
            GuardExecutionAssuranceBoundary,
            "achieved_boundary",
        )
        _require_enum(
            self.attestation_trust,
            GuardExecutionAttestationTrust,
            "attestation_trust",
        )

        # Enforced / absent kinds
        for i, kind in enumerate(self.enforced_guarantee_kinds):
            _ = _require_guarantee_kind(kind, f"enforced_guarantee_kinds[{i}]")
        for i, kind in enumerate(self.absent_guarantee_kinds):
            _ = _require_guarantee_kind(kind, f"absent_guarantee_kinds[{i}]")
        total_kinds = len(self.enforced_guarantee_kinds) + len(self.absent_guarantee_kinds)
        if total_kinds > _MAX_GUARANTEE_KINDS:
            raise ValueError(f"total guarantee kinds must be <= {_MAX_GUARANTEE_KINDS}")
        # Deduplicate and sort for stability
        enforced = tuple(sorted(set(self.enforced_guarantee_kinds)))
        absent = tuple(sorted(set(self.absent_guarantee_kinds)))
        if set(enforced) & set(absent):
            raise ValueError("a guarantee kind cannot be both enforced and absent")
        object.__setattr__(self, "enforced_guarantee_kinds", enforced)
        object.__setattr__(self, "absent_guarantee_kinds", absent)

        _ = _require_sha256(self.execution_context_digest, "execution_context_digest")

        if self.terminal_statement_digest is not None:
            _ = _require_sha256(self.terminal_statement_digest, "terminal_statement_digest")

        # Proof lines validation
        if len(self.proof_lines) > _MAX_PROOF_LINES:
            raise ValueError(f"proof_lines must have <= {_MAX_PROOF_LINES} entries")
        total_chars = 0
        for i, line in enumerate(self.proof_lines):
            _ = _require_proof_line(line, "proof_lines", index=i)
            total_chars += len(line)
        if total_chars > _MAX_TOTAL_PROOF_CHARS:
            raise ValueError(f"proof_lines total length must be <= {_MAX_TOTAL_PROOF_CHARS}")

        # A VERIFIED receipt must bind to the attested terminal statement or a
        # proof; unsigned output can never be labeled VERIFIED without evidence.
        if self.attestation_trust is GuardExecutionAttestationTrust.VERIFIED and (
            self.terminal_statement_digest is None and not self.proof_lines
        ):
            raise ValueError("a VERIFIED receipt requires a terminal_statement_digest or proof_lines")

    @property
    def schema_version(self) -> str:
        """Return the schema version for this receipt."""
        return SCHEMA_VERSION

    def to_receipt_fields(self) -> dict[str, object]:
        """Return a JSON-serializable, privacy-safe dict.

        Bounded fields (proof_lines <= 64 lines of <= 256 chars each) are
        excluded — they may contain paths/secrets.  Digests and enum values
        are opaque references.
        """
        result: dict[str, object] = {
            "achieved_boundary": self.achieved_boundary,
            "attestation_trust": self.attestation_trust,
            "execution_context_digest": self.execution_context_digest,
            "enforced_guarantee_kinds": list(self.enforced_guarantee_kinds),
            "absent_guarantee_kinds": list(self.absent_guarantee_kinds),
        }
        if self.terminal_statement_digest is not None:
            result["terminal_statement_digest"] = self.terminal_statement_digest
        result["_schema_version"] = self.schema_version
        return result


# ---------------------------------------------------------------------------
# Store-facing helpers
# ---------------------------------------------------------------------------


def receipt_assurance_payload(receipt: ExecutionAssuranceReceipt) -> dict[str, object]:
    """Return a flat payload dict suitable for persistence / transmission.

    The payload contains only the privacy-safe fields from
    :meth:`ExecutionAssuranceReceipt.to_receipt_fields`.  It does **not**
    reference the underlying ``GuardReceipt`` so the two models stay
    decoupled.
    """
    return receipt.to_receipt_fields()


def validate_assurance_receipt_schema_version(value: object) -> str:
    """Validate that a receipt payload carries the current schema version.

    Returns the schema version on success.  Raises ``ValueError`` if the
    value is missing, not a string, or not the current schema version.
    """
    version: str
    if isinstance(value, dict):
        typed: dict[str, object] = cast("dict[str, object]", value)
        _raw = typed.get("_schema_version")
        if not isinstance(_raw, str):
            raise ValueError("schema_version in dict must be a non-empty string")
        version = _require_str(_raw, "schema_version in dict")
    elif isinstance(value, str):
        version = value
    else:
        msg = "schema_version must be a string or dict with '_schema_version'; " + f"got {type(value).__name__}"
        raise ValueError(msg)
    if version != SCHEMA_VERSION:
        raise ValueError("schema_version must be " + repr(SCHEMA_VERSION) + "; " + f"got {version!r}")
    return version


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "SCHEMA_VERSION",
    "ExecutionAssuranceReceipt",
    "receipt_assurance_payload",
    "validate_assurance_receipt_schema_version",
]
