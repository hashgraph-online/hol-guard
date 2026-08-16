"""Bounded, privacy-safe resilience state for the native Guard runtime.

This module owns only process-local availability controls. It does not persist
commands, prompts, paths, payloads, tokens, proofs, or exception text. Python
remains the authoritative policy and fallback control plane.
"""

from __future__ import annotations

import hashlib
import os
import threading
import time
from collections import OrderedDict
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

_MAX_HEALTH_ENTRIES = 128
_CIRCUIT_FAILURE_THRESHOLD = 3
_CIRCUIT_COOLDOWN_SECONDS = 15.0
_ONESHOT_RETRY_COOLDOWN_SECONDS = 0.05
_GLOBAL_ONESHOT_LIMIT = 2
_REASON_MAX_LENGTH = 96
_REASON_CHARACTERS = frozenset("_-.")


@dataclass(frozen=True, slots=True)
class NativeRuntimeHealthSnapshot:
    """Aggregate-only native runtime health suitable for local diagnostics."""

    state: str
    reason: str
    circuit_open: bool
    consecutive_failures: int
    resident_failures: int
    oneshot_failures: int
    overloads: int
    starts: int
    restarts: int
    cooldown_remaining_seconds: float


@dataclass(slots=True)
class _MutableNativeRuntimeHealth:
    state: str = "unknown"
    reason: str = "native_state_uninitialized"
    consecutive_failures: int = 0
    resident_failures: int = 0
    oneshot_failures: int = 0
    overloads: int = 0
    starts: int = 0
    restarts: int = 0
    circuit_until: float = 0.0
    permanently_quarantined: bool = False
    oneshot_in_flight: bool = False
    next_oneshot_allowed_at: float = 0.0


_STATE_LOCK = threading.RLock()
_STATES: OrderedDict[str, _MutableNativeRuntimeHealth] = OrderedDict()
_GLOBAL_ONESHOT = threading.BoundedSemaphore(_GLOBAL_ONESHOT_LIMIT)


def _privacy_safe_key(identity_sha256: str, guard_home: Path) -> str:
    """Derive a stable in-process key without retaining the raw local path."""

    digest = hashlib.sha256()
    digest.update(identity_sha256.encode("ascii", errors="ignore")[:128])
    digest.update(b"\x00")
    try:
        normalized = os.fsencode(guard_home.expanduser().resolve(strict=False))
    except (OSError, RuntimeError, ValueError):
        normalized = os.fsencode(str(guard_home))
    digest.update(normalized)
    return digest.hexdigest()


def _public_reason(reason: str, fallback: str) -> str:
    candidate = reason.strip().lower()[:_REASON_MAX_LENGTH]
    if candidate and all(character.isalnum() or character in _REASON_CHARACTERS for character in candidate):
        return candidate
    return fallback


def _evict_if_needed() -> None:
    while len(_STATES) > _MAX_HEALTH_ENTRIES:
        evicted = False
        for key, state in tuple(_STATES.items()):
            if state.oneshot_in_flight:
                continue
            del _STATES[key]
            evicted = True
            break
        if not evicted:
            break


def _state(identity_sha256: str, guard_home: Path) -> _MutableNativeRuntimeHealth:
    key = _privacy_safe_key(identity_sha256, guard_home)
    state = _STATES.get(key)
    if state is None:
        state = _MutableNativeRuntimeHealth()
        _STATES[key] = state
        _evict_if_needed()
    else:
        _STATES.move_to_end(key)
    return state


def _refresh_circuit(state: _MutableNativeRuntimeHealth, now: float) -> None:
    if state.permanently_quarantined or state.circuit_until <= 0 or now < state.circuit_until:
        return
    state.circuit_until = 0.0
    state.consecutive_failures = max(0, _CIRCUIT_FAILURE_THRESHOLD - 1)
    state.state = "recovering"
    state.reason = "native_circuit_half_open"


def _record_failure(
    state: _MutableNativeRuntimeHealth,
    *,
    reason: str,
    fallback_reason: str,
    now: float,
) -> None:
    if state.permanently_quarantined:
        return
    state.consecutive_failures += 1
    state.reason = _public_reason(reason, fallback_reason)
    if state.consecutive_failures >= _CIRCUIT_FAILURE_THRESHOLD:
        state.state = "circuit_open"
        state.reason = "native_circuit_open"
        state.circuit_until = now + _CIRCUIT_COOLDOWN_SECONDS
    else:
        state.state = "degraded"


def native_record_starting(identity_sha256: str, guard_home: Path) -> None:
    with _STATE_LOCK:
        state = _state(identity_sha256, guard_home)
        if state.permanently_quarantined:
            return
        state.starts += 1
        state.state = "starting"
        state.reason = "native_starting"


def native_record_restart(identity_sha256: str, guard_home: Path) -> None:
    with _STATE_LOCK:
        state = _state(identity_sha256, guard_home)
        if state.permanently_quarantined:
            return
        state.restarts += 1
        state.state = "recovering"
        state.reason = "native_recovering"


def native_record_resident_success(identity_sha256: str, guard_home: Path) -> None:
    with _STATE_LOCK:
        state = _state(identity_sha256, guard_home)
        if state.permanently_quarantined:
            return
        state.state = "healthy"
        state.reason = "native_ready"
        state.consecutive_failures = 0
        state.circuit_until = 0.0


def native_record_resident_failure(
    identity_sha256: str,
    guard_home: Path,
    *,
    reason: str,
) -> None:
    with _STATE_LOCK:
        state = _state(identity_sha256, guard_home)
        state.resident_failures += 1
        _record_failure(
            state,
            reason=reason,
            fallback_reason="native_resident_failed",
            now=time.monotonic(),
        )


def native_record_oneshot_success(identity_sha256: str, guard_home: Path) -> None:
    with _STATE_LOCK:
        state = _state(identity_sha256, guard_home)
        if state.permanently_quarantined:
            return
        state.state = "degraded"
        state.reason = "native_oneshot_fallback"
        state.consecutive_failures = 0
        state.circuit_until = 0.0


def native_record_oneshot_failure(
    identity_sha256: str,
    guard_home: Path,
    *,
    reason: str,
) -> None:
    with _STATE_LOCK:
        state = _state(identity_sha256, guard_home)
        state.oneshot_failures += 1
        _record_failure(
            state,
            reason=reason,
            fallback_reason="native_oneshot_failed",
            now=time.monotonic(),
        )


def native_record_overload(identity_sha256: str, guard_home: Path) -> None:
    with _STATE_LOCK:
        state = _state(identity_sha256, guard_home)
        if state.permanently_quarantined:
            return
        state.overloads += 1
        state.state = "overloaded"
        state.reason = "native_overloaded"


def native_record_integrity_failure(
    identity_sha256: str,
    guard_home: Path,
    *,
    reason: str,
) -> None:
    with _STATE_LOCK:
        state = _state(identity_sha256, guard_home)
        state.state = "quarantined"
        state.reason = _public_reason(reason, "native_integrity_failed")
        state.permanently_quarantined = True
        state.circuit_until = float("inf")
        state.consecutive_failures = max(
            state.consecutive_failures,
            _CIRCUIT_FAILURE_THRESHOLD,
        )


def native_runtime_health_snapshot(
    identity_sha256: str,
    guard_home: Path,
) -> NativeRuntimeHealthSnapshot:
    with _STATE_LOCK:
        state = _state(identity_sha256, guard_home)
        now = time.monotonic()
        _refresh_circuit(state, now)
        circuit_open = state.permanently_quarantined or state.circuit_until > now
        cooldown = _CIRCUIT_COOLDOWN_SECONDS if state.permanently_quarantined else max(0.0, state.circuit_until - now)
        return NativeRuntimeHealthSnapshot(
            state=state.state,
            reason=state.reason,
            circuit_open=circuit_open,
            consecutive_failures=state.consecutive_failures,
            resident_failures=state.resident_failures,
            oneshot_failures=state.oneshot_failures,
            overloads=state.overloads,
            starts=state.starts,
            restarts=state.restarts,
            cooldown_remaining_seconds=round(cooldown, 3),
        )


@contextmanager
def native_oneshot_lease(
    identity_sha256: str,
    guard_home: Path,
) -> Iterator[bool]:
    """Acquire one bounded process-wide native one-shot recovery slot."""

    acquired_global = False
    acquired_key = False
    key = _privacy_safe_key(identity_sha256, guard_home)
    with _STATE_LOCK:
        state = _state(identity_sha256, guard_home)
        now = time.monotonic()
        _refresh_circuit(state, now)
        circuit_open = state.permanently_quarantined or state.circuit_until > now
        if not circuit_open and not state.oneshot_in_flight and now >= state.next_oneshot_allowed_at:
            state.oneshot_in_flight = True
            state.next_oneshot_allowed_at = now + _ONESHOT_RETRY_COOLDOWN_SECONDS
            acquired_key = True
    if acquired_key:
        acquired_global = _GLOBAL_ONESHOT.acquire(blocking=False)
        if not acquired_global:
            with _STATE_LOCK:
                current = _STATES.get(key)
                if current is not None:
                    current.oneshot_in_flight = False
                    current.overloads += 1
                    current.state = "overloaded"
                    current.reason = "native_oneshot_capacity"
            acquired_key = False
    try:
        yield acquired_global and acquired_key
    finally:
        if acquired_global:
            _GLOBAL_ONESHOT.release()
        if acquired_key:
            with _STATE_LOCK:
                current = _STATES.get(key)
                if current is not None:
                    current.oneshot_in_flight = False


__all__ = [
    "NativeRuntimeHealthSnapshot",
    "native_oneshot_lease",
    "native_record_integrity_failure",
    "native_record_oneshot_failure",
    "native_record_oneshot_success",
    "native_record_overload",
    "native_record_resident_failure",
    "native_record_resident_success",
    "native_record_restart",
    "native_record_starting",
    "native_runtime_health_snapshot",
]
