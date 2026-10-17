"""Cached harness version compatibility for the daemon's dashboard API.

Observations are cached per Guard home and harness with a finite lifetime.
A cached observation is reused only while it is fresh and its executable or
package metadata has not changed; otherwise discovery runs again. Discovery is
reached only from the dashboard API, never from hook or tool admission paths.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from pathlib import Path

from ...version import __version__
from ..adapters.base import HarnessContext
from .acknowledgements import acknowledged_keys, clear_acknowledgements, record_acknowledgement
from .compatibility import STATE_UNTESTED, decide_compatibility
from .discovery import VersionObservation, current_platform, observation_identity_changed, observe_harness_version
from .manifest import ManifestLoad, load_manifest

CACHE_TTL_SECONDS = 5 * 60

_lock = threading.Lock()
_observations: dict[tuple[str, str], VersionObservation] = {}
_manifest: ManifestLoad | None = None


def _bundled_manifest() -> ManifestLoad:
    global _manifest
    if _manifest is None:
        _manifest = load_manifest()
    return _manifest


def invalidate(guard_home: Path, harness: str | None = None) -> None:
    """Drop cached observations, e.g. after install, repair, or refresh."""

    with _lock:
        for key in list(_observations):
            if key[0] == str(guard_home) and (harness is None or key[1] == harness):
                del _observations[key]


def _observation(
    harness: str,
    context: HarnessContext,
    *,
    force: bool,
    clock: Callable[[], float],
    observe: Callable[..., VersionObservation],
) -> VersionObservation:
    key = (str(context.guard_home), harness)
    with _lock:
        cached = _observations.get(key)
    if (
        not force
        and cached is not None
        and clock() - cached.observed_at < CACHE_TTL_SECONDS
        and not observation_identity_changed(cached, context)
    ):
        return cached
    # Discovery can run a bounded probe; keep it outside the lock so other harnesses and homes
    # are not serialized behind it. Concurrent misses may observe twice; the newest result wins.
    observation = observe(harness, context, clock=clock)
    with _lock:
        _observations[key] = observation
    return observation


def compatibility_for(
    harness: str,
    context: HarnessContext,
    *,
    force: bool = False,
    clock: Callable[[], float] = time.time,
    observe: Callable[..., VersionObservation] = observe_harness_version,
    manifest_load: ManifestLoad | None = None,
    guard_version: str = __version__,
    platform: str | None = None,
) -> dict[str, object]:
    observation = _observation(harness, context, force=force, clock=clock, observe=observe)
    return decide_compatibility(
        harness=harness,
        observation=observation,
        manifest_load=manifest_load or _bundled_manifest(),
        guard_version=guard_version,
        platform=platform or current_platform(),
        now=clock(),
        acknowledged_keys=acknowledged_keys(context.guard_home, harness),
    )


class AcknowledgementRejectedError(ValueError):
    """The acknowledgement does not match a current untested observation."""


def acknowledge(
    harness: str,
    key: object,
    context: HarnessContext,
    *,
    clock: Callable[[], float] = time.time,
    observe: Callable[..., VersionObservation] = observe_harness_version,
    manifest_load: ManifestLoad | None = None,
    guard_version: str = __version__,
    platform: str | None = None,
) -> dict[str, object]:
    """Acknowledge the warning for the exact version currently observed.

    The caller must echo the key from the current payload. A stale key, an
    unknown version, or a tested version cannot be acknowledged.
    """

    def current() -> dict[str, object]:
        return compatibility_for(
            harness,
            context,
            clock=clock,
            observe=observe,
            manifest_load=manifest_load,
            guard_version=guard_version,
            platform=platform,
        )

    payload = current()
    ack = payload["acknowledgement"]
    if not isinstance(ack, dict):
        raise AcknowledgementRejectedError("acknowledgement_not_eligible")
    if payload["state"] != STATE_UNTESTED or not ack.get("eligible") or not isinstance(key, str):
        raise AcknowledgementRejectedError("acknowledgement_not_eligible")
    if key != ack.get("key"):
        raise AcknowledgementRejectedError("acknowledgement_stale")
    record_acknowledgement(context.guard_home, harness=harness, key=key)
    return current()


def clear_acknowledgement(
    harness: str,
    context: HarnessContext,
    *,
    clock: Callable[[], float] = time.time,
    observe: Callable[..., VersionObservation] = observe_harness_version,
    manifest_load: ManifestLoad | None = None,
    guard_version: str = __version__,
    platform: str | None = None,
) -> dict[str, object]:
    clear_acknowledgements(context.guard_home, harness=harness)
    return compatibility_for(
        harness,
        context,
        clock=clock,
        observe=observe,
        manifest_load=manifest_load,
        guard_version=guard_version,
        platform=platform,
    )
