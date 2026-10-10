"""Daemon start-timeout floor shared with the daemon manager."""

from __future__ import annotations

import math
import os

_HOOK_WORKER_READY_TIMEOUT_ENV = "HOL_GUARD_HOOK_WORKER_READY_TIMEOUT_SECONDS"
_HOOK_PROCESS_READY_TIMEOUT_SECONDS = 14.0
_HOOK_PROCESS_START_TIMEOUT_SECONDS = 30.0
# Hard cap for an operator-raised readiness budget.  Bounded so a stray
# environment value cannot make the daemon wait indefinitely on a dead worker.
_HOOK_PROCESS_READY_TIMEOUT_MAX_SECONDS = 120.0


def _hook_process_ready_timeout_seconds() -> float:
    """Return the daemon-side worker-ready budget.

    The worker's own handshake (spawn -> ``isolated`` -> its isolated evaluator
    reporting ``ready``) must complete inside this window before the daemon
    declares the worker dead.  The isolated evaluator alone can take ~11 s to
    import its module graph on a slow host (QEMU guests, cold CI), so a nested
    budget smaller than the worker's internal evaluator poll deadlocks startup:
    the daemon kills a healthy worker while it is still waiting on its
    evaluator.  Operators on slow hosts can raise this via
    ``HOL_GUARD_HOOK_WORKER_READY_TIMEOUT_SECONDS``; it is clamped to a sane
    range so it cannot be driven to zero or to an unbounded wait.
    """
    raw = os.environ.get(_HOOK_WORKER_READY_TIMEOUT_ENV)
    if raw is None:
        return _HOOK_PROCESS_READY_TIMEOUT_SECONDS
    try:
        parsed = float(raw.strip())
    except ValueError:
        return _HOOK_PROCESS_READY_TIMEOUT_SECONDS
    if not math.isfinite(parsed) or parsed <= 0:
        return _HOOK_PROCESS_READY_TIMEOUT_SECONDS
    return min(_HOOK_PROCESS_READY_TIMEOUT_MAX_SECONDS, max(_HOOK_PROCESS_READY_TIMEOUT_SECONDS, parsed))


def hook_worker_ready_timeout(configured_timeout: float) -> float:
    floor = _hook_process_ready_timeout_seconds()
    ceiling = max(_HOOK_PROCESS_START_TIMEOUT_SECONDS, floor)
    return min(ceiling, max(floor, configured_timeout))
