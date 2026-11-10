"""The containment health cache the runtime snapshot reads."""

# pyright: reportAttributeAccessIssue=false, reportUnknownMemberType=false

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..routes.request_handler import _GuardDaemonHTTPServer as _GuardDaemonHttpServer


_CONTAINMENT_HEALTH_CACHE_SECONDS = 10.0


def cached_containment_health(
    server: _GuardDaemonHttpServer,
    *,
    force_refresh: bool,
    probe: Callable[[], dict[str, object]],
) -> dict[str, object] | None:
    """Return containment health without holding the cache lock across the probe.

    A fresh cache is shared. When the cache is due, one caller runs the probe
    and everyone else keeps the previous payload. Callers only wait together
    when no payload exists yet.
    """

    arrived_generation: int | None = None
    probe_generation = 0
    while True:
        with server.containment_health_cache_lock:
            if arrived_generation is None:
                arrived_generation = server.containment_health_generation
            cached = server.containment_health_cache
            age = time.monotonic() - server.containment_health_cache_monotonic
            if cached is not None and age <= _CONTAINMENT_HEALTH_CACHE_SECONDS and not force_refresh:
                return dict(cached)
            if server.containment_health_refreshing:
                if cached is not None and not force_refresh:
                    return dict(cached)
                event = server.containment_health_refresh_event
                run_probe = False
            else:
                event = threading.Event()
                server.containment_health_refresh_event = event
                server.containment_health_refreshing = True
                server.containment_health_generation += 1
                probe_generation = server.containment_health_generation
                run_probe = True
        if not run_probe:
            event.wait()
            with server.containment_health_cache_lock:
                done = server.containment_health_completed_generation
                if force_refresh and arrived_generation is not None and done <= arrived_generation:
                    continue
                return None if server.containment_health_cache is None else dict(server.containment_health_cache)
        break
    payload: dict[str, object] | None = None
    failed = False
    try:
        payload = probe()
    except (OSError, RuntimeError, TypeError, ValueError):
        payload = None
        failed = True
    except BaseException:
        failed = True
        raise
    finally:
        with server.containment_health_cache_lock:
            if failed or payload is not None:
                server.containment_health_cache = None if payload is None else dict(payload)
                server.containment_health_cache_monotonic = time.monotonic()
            server.containment_health_refreshing = False
            server.containment_health_completed_generation = probe_generation
            event.set()
    return None if payload is None else dict(payload)
