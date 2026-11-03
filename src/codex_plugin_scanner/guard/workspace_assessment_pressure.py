"""Host resource pressure for the background workspace assessment worker.

Automatic assessments are background work the developer did not ask for, so
they wait while the host is busy. Runs a user asked for (``manual``,
``fix_verification``) still start. Nothing is dropped: queued runs stay queued
and the next quiet poll observes and claims them.
"""

from __future__ import annotations

import os
import threading
from typing import Any, Final

# One-minute load average per logical CPU at which automatic work waits.
LOAD_PER_CPU_LIMIT: Final = 1.5
RESOURCE_PRESSURE: Final = "resource_pressure"

_lock = threading.Lock()
_deferred: dict[str, str] = {}


def host_resource_pressure() -> str | None:
    """Return ``resource_pressure`` while the host is busy, else ``None``.

    A platform without a load average (Windows) reports no pressure rather
    than holding background work forever.
    """

    try:
        load = os.getloadavg()[0]
    except (AttributeError, OSError):
        return None
    if load / max(os.cpu_count() or 1, 1) >= LOAD_PER_CPU_LIMIT:
        return RESOURCE_PRESSURE
    return None


def record_deferral(store: Any, reason: str | None) -> None:
    key = str(store.guard_home)
    with _lock:
        if reason is None:
            _deferred.pop(key, None)
        else:
            _deferred[key] = reason


def deferral_reason(store: Any) -> str | None:
    """Why the worker is holding automatic runs for this Guard home, if it is."""

    with _lock:
        return _deferred.get(str(store.guard_home))


__all__ = [
    "LOAD_PER_CPU_LIMIT",
    "RESOURCE_PRESSURE",
    "deferral_reason",
    "host_resource_pressure",
    "record_deferral",
]
