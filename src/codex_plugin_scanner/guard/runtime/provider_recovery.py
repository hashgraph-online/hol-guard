"""Provider self-healing recovery state machine.

Pure, monotonic recovery logic that drives retry behaviour without touching
daemon bridges, MDM supervisors, or any I/O machinery.  It consumes
:py:class:`ProviderHealthState` from the frozen execution-assurance contract
so degraded / unavailable semantics stay shared.

Design rules:
- Immutable frozen/slots dataclass + str-Enum for the contract.
- No secret leakage: only opaque sha256 digests cross boundaries.
- Bounded exponential backoff caps at 5 attempts -> UNAVAILABLE.
- Deduped notice key is stable per (phase, error_digest).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum
from typing import Final

from codex_plugin_scanner.guard.runtime.execution_assurance_contract import (
    ProviderHealthState,
)

_MAX_ATTEMPTS: Final = 5
_BACKOFF_CAP_SECONDS: Final = 30.0

_SHA256_HEX_LENGTH: Final = 64


class RecoveryPhase(str, Enum):
    """Recovery phase - mirrors ProviderHealthState subset for local tracking."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    RECOVERING = "recovering"
    UNAVAILABLE = "unavailable"


_HEALTH_TO_RECOVERY: dict[ProviderHealthState, RecoveryPhase] = {
    ProviderHealthState.HEALTHY: RecoveryPhase.HEALTHY,
    ProviderHealthState.DEGRADED: RecoveryPhase.DEGRADED,
    ProviderHealthState.UNAVAILABLE: RecoveryPhase.UNAVAILABLE,
    # Unresolved transient/terminal states map into active recovery handling.
    ProviderHealthState.UNKNOWN: RecoveryPhase.RECOVERING,
    ProviderHealthState.VERIFYING: RecoveryPhase.RECOVERING,
    ProviderHealthState.REVOKED: RecoveryPhase.UNAVAILABLE,
    ProviderHealthState.INCOMPATIBLE: RecoveryPhase.UNAVAILABLE,
}


@dataclass(frozen=True, slots=True)
class RecoveryState:
    """Immutable recovery state for one provider instance.

    Attributes:
        phase: Current recovery phase.
        attempt: Number of retry attempts so far (0 .. 5).  5 -> UNAVAILABLE.
        next_retry_seconds: Bounded exponential backoff in seconds.
        last_error_digest: Opaque sha256 digest of the last error
            (never raw text).
        notice_dedupe_key: Stable opaque key for deduplicating recovery
            notices.
    """

    phase: RecoveryPhase
    attempt: int
    next_retry_seconds: float
    last_error_digest: str | None = None
    notice_dedupe_key: str | None = None

    def __post_init__(self) -> None:
        _require_phase(self.phase)
        if not (0 <= self.attempt <= _MAX_ATTEMPTS):
            raise ValueError(f"attempt must be 0..{_MAX_ATTEMPTS}")
        _require_retry_seconds(self.next_retry_seconds)
        if self.next_retry_seconds < 0:
            raise ValueError("next_retry_seconds must be non-negative")
        if self.last_error_digest is not None:
            _ = _require_sha256(self.last_error_digest, "last_error_digest")
        # Auto-compute notice_dedupe_key when not provided
        if self.notice_dedupe_key is None:
            object.__setattr__(
                self,
                "notice_dedupe_key",
                _dedupe_key(self.phase, self.last_error_digest),
            )
        else:
            _ = _require_dedupe_key(self.notice_dedupe_key, "notice_dedupe_key")


# ---------------------------------------------------------------------------
# Validators (module-level free functions - basedpyright can't flag as
# redundant because they accept object-typed params)
# ---------------------------------------------------------------------------


def _require_phase(value: object) -> None:
    """Validate value is a RecoveryPhase; raise ValueError if not."""
    if not isinstance(value, RecoveryPhase):
        raise ValueError("phase must be a RecoveryPhase")


def _require_retry_seconds(value: object) -> None:
    """Validate value is int or float; raise ValueError if not."""
    if not isinstance(value, (int, float)):
        raise ValueError("value must be an int or float")


def _require_sha256(value: object, label: str) -> str:
    """Validate a lowercase hex SHA-256 digest."""
    if not isinstance(value, str) or len(value) != _SHA256_HEX_LENGTH:
        raise ValueError(f"{label} must be a {_SHA256_HEX_LENGTH}-char hex string")
    for c in value:
        if c not in "0123456789abcdef":
            raise ValueError(f"{label} must be lowercase hex")
    return value


def _require_dedupe_key(value: object, label: str) -> str:
    """Validate a short opaque dedupe key."""
    if not isinstance(value, str) or not value or len(value) > 128:
        raise ValueError(f"{label} must be a non-empty string of at most 128 characters")
    return value


# ---------------------------------------------------------------------------
# Pure functions
# ---------------------------------------------------------------------------


def _dedupe_key(phase: RecoveryPhase, error_digest: str | None) -> str:
    """Build a stable opaque dedupe key from phase + error_digest."""
    payload = f"{phase.value}:{error_digest or 'none'}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


__all__ = [
    "ProviderHealthState",
    "RecoveryPhase",
    "RecoveryState",
]
