"""Drain-lane reuse of a recent lease readiness check.

A drain worker leases only exact Review jobs, and the pool starts right after a
main poll has confirmed the Review capability and keyring. Checking both again
before every drain lease asked the native runtime to verify the capability
twice per lease, which during a bulk approval cost as much interpreter time as
settling the jobs did. Drain leases reuse a check made in the last two seconds;
each leased job is still authorized on its own before it settles, so a
capability revoked inside that window only means a job is leased and refused.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from typing import Any

LEASE_READY_REUSE_SECONDS = 2.0
_clock = time.monotonic
# Guards only the dictionaries below; a readiness check never runs under it.
_cache_lock = threading.Lock()
_checked: dict[str, tuple[float, tuple[str, ...]]] = {}
_home_locks: dict[str, threading.Lock] = {}


def lane_lease_ready_operations(
    store: Any,
    *,
    drain: bool,
    check: Callable[[Any], tuple[str, ...]],
) -> tuple[str, ...]:
    """Return the operations ``store`` may lease, reusing a recent check on drain lanes."""

    key = str(store.guard_home)
    if not drain:
        return _remember(key, check(store))
    cached = _recent(key)
    if cached is not None:
        return cached
    with _cache_lock:
        home_lock = _home_locks.setdefault(key, threading.Lock())
    # One drain worker per home checks while that home's other workers wait
    # for its answer; other homes and the main lane are not held up.
    with home_lock:
        cached = _recent(key)
        if cached is not None:
            return cached
        return _remember(key, check(store))


def _recent(key: str) -> tuple[str, ...] | None:
    with _cache_lock:
        checked = _checked.get(key)
    if checked is not None and _clock() - checked[0] < LEASE_READY_REUSE_SECONDS:
        return checked[1]
    return None


def _remember(key: str, operations: tuple[str, ...]) -> tuple[str, ...]:
    with _cache_lock:
        _checked[key] = (_clock(), operations)
    return operations
