"""Bounded supervision for resident native Guard runtimes.

The supervisor stores only aggregate process-local state keyed by a digest of
the runtime identity and Guard home. It never retains commands, prompts,
payloads, paths, environment values, tokens, proofs, or exception text.
"""

from __future__ import annotations

import hashlib
import os
import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass
from pathlib import Path

_MAX_SUPERVISORS = 128
_MAX_JOURNAL_EVENTS = 64
_RESTART_WINDOW_SECONDS = 60.0
_RESTART_BUDGET = 5
_RESTART_BASE_DELAY_SECONDS = 0.05
_RESTART_MAX_DELAY_SECONDS = 2.0
_CIRCUIT_COOLDOWN_SECONDS = 15.0
_REASON_MAX_LENGTH = 96


@dataclass(frozen=True, slots=True)
class NativeSupervisorStartPermit:
    allowed: bool
    generation: int
    reason: str
    retry_after_seconds: float


@dataclass(frozen=True, slots=True)
class NativeSupervisorSnapshot:
    state: str
    reason: str
    generation: int
    starts: int
    restarts: int
    failures: int
    consecutive_failures: int
    rotations: int
    start_in_flight: bool
    child_alive: bool
    circuit_open: bool
    retry_after_seconds: float


@dataclass(frozen=True, slots=True)
class NativeSupervisorJournalEvent:
    sequence: int
    state: str
    reason: str
    generation: int


@dataclass(slots=True)
class _MutableSupervisor:
    state: str = "disabled"
    reason: str = "native_disabled"
    generation: int = 0
    starts: int = 0
    restarts: int = 0
    failures: int = 0
    consecutive_failures: int = 0
    rotations: int = 0
    start_in_flight: bool = False
    child_alive: bool = False
    next_start_at: float = 0.0
    circuit_until: float = 0.0
    sequence: int = 0
    restart_times: deque[float] | None = None
    journal: deque[NativeSupervisorJournalEvent] | None = None

    def __post_init__(self) -> None:
        if self.restart_times is None:
            self.restart_times = deque(maxlen=_RESTART_BUDGET + 1)
        if self.journal is None:
            self.journal = deque(maxlen=_MAX_JOURNAL_EVENTS)


_LOCK = threading.RLock()
_SUPERVISORS: OrderedDict[str, _MutableSupervisor] = OrderedDict()


def _key(identity_sha256: str, guard_home: Path) -> str:
    digest = hashlib.sha256()
    digest.update(identity_sha256.encode("ascii", errors="ignore")[:128])
    digest.update(b"\x00")
    try:
        normalized = os.fsencode(guard_home.expanduser().resolve(strict=False))
    except (OSError, RuntimeError, ValueError):
        normalized = os.fsencode(str(guard_home))
    digest.update(normalized)
    return digest.hexdigest()


def _safe_reason(reason: str, fallback: str) -> str:
    candidate = reason.strip().lower()[:_REASON_MAX_LENGTH]
    if candidate and all(character.isalnum() or character in {"_", "-", "."} for character in candidate):
        return candidate
    return fallback


def _state(identity_sha256: str, guard_home: Path) -> _MutableSupervisor:
    key = _key(identity_sha256, guard_home)
    supervisor = _SUPERVISORS.get(key)
    if supervisor is None:
        supervisor = _MutableSupervisor()
        _SUPERVISORS[key] = supervisor
        while len(_SUPERVISORS) > _MAX_SUPERVISORS:
            evicted = False
            for candidate_key, candidate in tuple(_SUPERVISORS.items()):
                if candidate.start_in_flight or candidate.child_alive:
                    continue
                del _SUPERVISORS[candidate_key]
                evicted = True
                break
            if not evicted:
                break
    else:
        _SUPERVISORS.move_to_end(key)
    return supervisor


def _record(supervisor: _MutableSupervisor, *, state: str, reason: str) -> None:
    supervisor.state = state
    supervisor.reason = reason
    supervisor.sequence += 1
    assert supervisor.journal is not None
    supervisor.journal.append(
        NativeSupervisorJournalEvent(
            sequence=supervisor.sequence,
            state=state,
            reason=reason,
            generation=supervisor.generation,
        )
    )


def _refresh(supervisor: _MutableSupervisor, now: float) -> None:
    if supervisor.circuit_until > 0 and now >= supervisor.circuit_until:
        supervisor.circuit_until = 0.0
        supervisor.next_start_at = now
        _record(
            supervisor,
            state="recovering",
            reason="native_supervisor_half_open",
        )


def _retry_after(supervisor: _MutableSupervisor, now: float) -> float:
    return round(max(0.0, max(supervisor.next_start_at, supervisor.circuit_until) - now), 3)


def native_supervisor_request_start(
    identity_sha256: str,
    guard_home: Path,
) -> NativeSupervisorStartPermit:
    """Reserve the single start slot for one native runtime identity."""

    with _LOCK:
        supervisor = _state(identity_sha256, guard_home)
        now = time.monotonic()
        _refresh(supervisor, now)
        if supervisor.start_in_flight:
            return NativeSupervisorStartPermit(
                allowed=False,
                generation=supervisor.generation,
                reason="native_start_in_flight",
                retry_after_seconds=0.0,
            )
        retry_after = _retry_after(supervisor, now)
        if retry_after > 0:
            reason = "native_supervisor_circuit_open" if supervisor.circuit_until > now else "native_restart_backoff"
            return NativeSupervisorStartPermit(
                allowed=False,
                generation=supervisor.generation,
                reason=reason,
                retry_after_seconds=retry_after,
            )
        supervisor.start_in_flight = True
        supervisor.generation += 1
        if supervisor.starts:
            supervisor.restarts += 1
            state = "recovering"
            reason = "native_restarting"
        else:
            state = "starting"
            reason = "native_starting"
        supervisor.starts += 1
        _record(supervisor, state=state, reason=reason)
        return NativeSupervisorStartPermit(
            allowed=True,
            generation=supervisor.generation,
            reason=reason,
            retry_after_seconds=0.0,
        )


def native_supervisor_record_ready(
    identity_sha256: str,
    guard_home: Path,
    *,
    generation: int,
) -> None:
    with _LOCK:
        supervisor = _state(identity_sha256, guard_home)
        if generation != supervisor.generation:
            return
        supervisor.start_in_flight = False
        supervisor.child_alive = True
        supervisor.next_start_at = 0.0
        supervisor.circuit_until = 0.0
        supervisor.consecutive_failures = 0
        assert supervisor.restart_times is not None
        supervisor.restart_times.clear()
        _record(supervisor, state="healthy", reason="native_ready")


def native_supervisor_record_start_failed(
    identity_sha256: str,
    guard_home: Path,
    *,
    generation: int,
    reason: str,
) -> None:
    _record_failure(
        identity_sha256,
        guard_home,
        generation=generation,
        reason=reason,
        start_failed=True,
    )


def native_supervisor_record_child_exit(
    identity_sha256: str,
    guard_home: Path,
    *,
    generation: int,
    reason: str,
) -> None:
    _record_failure(
        identity_sha256,
        guard_home,
        generation=generation,
        reason=reason,
        start_failed=False,
    )


def _record_failure(
    identity_sha256: str,
    guard_home: Path,
    *,
    generation: int,
    reason: str,
    start_failed: bool,
) -> None:
    with _LOCK:
        supervisor = _state(identity_sha256, guard_home)
        if generation != supervisor.generation:
            return
        now = time.monotonic()
        supervisor.start_in_flight = False
        supervisor.child_alive = False
        supervisor.failures += 1
        supervisor.consecutive_failures += 1
        assert supervisor.restart_times is not None
        while supervisor.restart_times and now - supervisor.restart_times[0] > _RESTART_WINDOW_SECONDS:
            supervisor.restart_times.popleft()
        supervisor.restart_times.append(now)
        safe_reason = _safe_reason(
            reason,
            "native_start_failed" if start_failed else "native_child_exited",
        )
        if len(supervisor.restart_times) > _RESTART_BUDGET:
            supervisor.circuit_until = now + _CIRCUIT_COOLDOWN_SECONDS
            supervisor.next_start_at = supervisor.circuit_until
            _record(
                supervisor,
                state="circuit_open",
                reason="native_supervisor_circuit_open",
            )
            return
        exponent = min(supervisor.consecutive_failures - 1, 8)
        delay = min(
            _RESTART_MAX_DELAY_SECONDS,
            _RESTART_BASE_DELAY_SECONDS * (2**exponent),
        )
        jitter_digest = hashlib.sha256(
            f"{_key(identity_sha256, guard_home)}:{generation}:{supervisor.consecutive_failures}".encode()
        ).digest()
        jitter = (int.from_bytes(jitter_digest[:2], "big") / 65_535.0) * delay * 0.25
        supervisor.next_start_at = now + delay + jitter
        _record(supervisor, state="degraded", reason=safe_reason)


def native_supervisor_record_rotation(
    identity_sha256: str,
    guard_home: Path,
    *,
    generation: int,
) -> None:
    with _LOCK:
        supervisor = _state(identity_sha256, guard_home)
        if generation != supervisor.generation:
            return
        supervisor.rotations += 1
        _record(supervisor, state="healthy", reason="native_generation_rotated")


def native_supervisor_record_stopped(
    identity_sha256: str,
    guard_home: Path,
    *,
    generation: int,
) -> None:
    with _LOCK:
        supervisor = _state(identity_sha256, guard_home)
        if generation != supervisor.generation:
            return
        supervisor.start_in_flight = False
        supervisor.child_alive = False
        supervisor.next_start_at = 0.0
        supervisor.circuit_until = 0.0
        supervisor.consecutive_failures = 0
        assert supervisor.restart_times is not None
        supervisor.restart_times.clear()
        _record(supervisor, state="disabled", reason="native_stopped")


def native_supervisor_snapshot(
    identity_sha256: str,
    guard_home: Path,
) -> NativeSupervisorSnapshot:
    with _LOCK:
        supervisor = _state(identity_sha256, guard_home)
        now = time.monotonic()
        _refresh(supervisor, now)
        return NativeSupervisorSnapshot(
            state=supervisor.state,
            reason=supervisor.reason,
            generation=supervisor.generation,
            starts=supervisor.starts,
            restarts=supervisor.restarts,
            failures=supervisor.failures,
            consecutive_failures=supervisor.consecutive_failures,
            rotations=supervisor.rotations,
            start_in_flight=supervisor.start_in_flight,
            child_alive=supervisor.child_alive,
            circuit_open=supervisor.circuit_until > now,
            retry_after_seconds=_retry_after(supervisor, now),
        )


def native_supervisor_journal(
    identity_sha256: str,
    guard_home: Path,
) -> tuple[NativeSupervisorJournalEvent, ...]:
    with _LOCK:
        supervisor = _state(identity_sha256, guard_home)
        assert supervisor.journal is not None
        return tuple(supervisor.journal)


__all__ = [
    "NativeSupervisorJournalEvent",
    "NativeSupervisorSnapshot",
    "NativeSupervisorStartPermit",
    "native_supervisor_journal",
    "native_supervisor_record_child_exit",
    "native_supervisor_record_ready",
    "native_supervisor_record_rotation",
    "native_supervisor_record_start_failed",
    "native_supervisor_record_stopped",
    "native_supervisor_request_start",
    "native_supervisor_snapshot",
]
