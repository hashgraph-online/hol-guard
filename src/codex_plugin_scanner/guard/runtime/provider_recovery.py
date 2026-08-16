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


# Mapping between RecoveryPhase and ProviderHealthState variants
_RECOVERY_TO_HEALTH: dict[RecoveryPhase, ProviderHealthState] = {
    RecoveryPhase.HEALTHY: ProviderHealthState.HEALTHY,
    RecoveryPhase.DEGRADED: ProviderHealthState.DEGRADED,
    RecoveryPhase.RECOVERING: ProviderHealthState.DEGRADED,
    RecoveryPhase.UNAVAILABLE: ProviderHealthState.UNAVAILABLE,
}

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


def _require_recovery_state(value: object) -> None:
    """Validate value is a RecoveryState; raise ValueError if not."""
    if not isinstance(value, RecoveryState):
        raise ValueError("value must be a RecoveryState")


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


def next_recovery_state(state: RecoveryState, *, succeeded: bool, error_digest: str | None = None) -> RecoveryState:
    """Advance recovery state machine one step.

    Args:
        state: Current recovery state.
        succeeded: Whether the last attempt succeeded.
        error_digest: Optional sha256 digest of the error.  Raw error text is
            never accepted - only opaque digests.

    Returns:
        New RecoveryState reflecting the transition.

    Rules:
    - On success: reset to HEALTHY with attempt 0 and 0 backoff.
    - On failure: increment attempt, compute backoff, and transition:
      - attempt >= 5 -> UNAVAILABLE (no further retries)
      - attempt 1 -> DEGRADED (first failure from HEALTHY)
      - attempt 2..4 -> RECOVERING (subsequent retrying attempts)
    """
    _require_recovery_state(state)

    if succeeded:
        # Success resets everything.
        return RecoveryState(
            phase=RecoveryPhase.HEALTHY,
            attempt=0,
            next_retry_seconds=0.0,
            last_error_digest=None,
            notice_dedupe_key=_dedupe_key(RecoveryPhase.HEALTHY, None),
        )

    # Failure path - error_digest must be a valid sha256 or None.
    if error_digest is not None:
        _ = _require_sha256(error_digest, "error_digest")

    new_attempt = min(state.attempt + 1, _MAX_ATTEMPTS)
    new_error_digest = error_digest or state.last_error_digest
    new_next_retry = min(2.0**new_attempt, _BACKOFF_CAP_SECONDS)

    # Determine new phase based on attempt and previous phase.
    if new_attempt >= _MAX_ATTEMPTS:
        new_phase = RecoveryPhase.UNAVAILABLE
    elif state.phase is RecoveryPhase.HEALTHY:
        # First failure -> DEGRADED.
        new_phase = RecoveryPhase.DEGRADED
    else:
        # Subsequent failures -> RECOVERING.
        new_phase = RecoveryPhase.RECOVERING

    notice_key = _dedupe_key(new_phase, new_error_digest)
    return RecoveryState(
        phase=new_phase,
        attempt=new_attempt,
        next_retry_seconds=new_next_retry,
        last_error_digest=new_error_digest,
        notice_dedupe_key=notice_key,
    )


def _dedupe_key(phase: RecoveryPhase, error_digest: str | None) -> str:
    """Build a stable opaque dedupe key from phase + error_digest."""
    payload = f"{phase.value}:{error_digest or 'none'}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def recovery_notice(state: RecoveryState, *, previous: RecoveryState | None = None) -> str | None:
    """Return a privacy-safe typed notice or None.

    A notice is emitted only when:
    - The phase has changed since the previous state, AND
    - The new state is not a deduplicated duplicate (key comparison).

    Privacy guarantee: the notice never contains raw error text, paths, or
    secrets - only the phase and attempt count.

    Args:
        state: Current recovery state.
        previous: The previous RecoveryState (or None on first).

    Returns:
        A typed notice string, or None if no new notice is warranted.
    """
    _require_recovery_state(state)

    # No previous state -> emit on first non-trivial state.
    if previous is None:
        if state.phase is RecoveryPhase.HEALTHY:
            return None
        return _build_notice(state)

    # Only emit on phase change.
    if state.phase is previous.phase:
        # Even if phase is the same, if dedupe key changed (different error),
        # emit a retry notice.
        if (
            state.notice_dedupe_key is not None
            and previous.notice_dedupe_key is not None
            and state.notice_dedupe_key != previous.notice_dedupe_key
        ):
            return _build_notice(state)
        return None

    # Phase changed - emit unless dedupe key matches (same error+phase combo).
    if (
        state.notice_dedupe_key is not None
        and previous.notice_dedupe_key is not None
        and state.notice_dedupe_key == previous.notice_dedupe_key
    ):
        return None

    return _build_notice(state)


def _build_notice(state: RecoveryState) -> str:
    """Build a privacy-safe notice string."""
    labels: dict[RecoveryPhase, str] = {
        RecoveryPhase.HEALTHY: "Provider recovered",
        RecoveryPhase.DEGRADED: "Provider degraded - recovering",
        RecoveryPhase.RECOVERING: "Provider recovering",
        RecoveryPhase.UNAVAILABLE: "Provider unavailable - retries exhausted",
    }
    label = labels.get(state.phase, "Provider recovery")
    return f"[{state.phase.value.upper()}] {label} (attempt {state.attempt}/{_MAX_ATTEMPTS})"


def to_provider_health_state(phase: RecoveryPhase) -> ProviderHealthState:
    """Map a RecoveryPhase to the corresponding ProviderHealthState."""
    return _RECOVERY_TO_HEALTH[phase]


def from_provider_health_state(
    health: ProviderHealthState,
) -> RecoveryPhase:
    """Map a ProviderHealthState to the corresponding RecoveryPhase."""
    return _HEALTH_TO_RECOVERY[health]


__all__ = [
    "ProviderHealthState",
    "RecoveryPhase",
    "RecoveryState",
    "from_provider_health_state",
    "next_recovery_state",
    "recovery_notice",
    "to_provider_health_state",
]
