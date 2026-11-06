"""Cached harness version compatibility for the daemon's dashboard API.

Observations are cached per Guard home and harness with a finite lifetime.
A cached observation is reused only while it is fresh and its executable or
package metadata has not changed; otherwise discovery runs again. Discovery is
reached only from the dashboard API, never from hook or tool admission paths.
"""

from __future__ import annotations

import copy
import threading
import time
from collections.abc import Callable
from pathlib import Path

from ...version import __version__
from ..adapters.base import HarnessContext
from .acknowledgements import clear_acknowledgements, record_acknowledgement
from .compatibility import OBSERVATION_MAX_AGE_SECONDS, STATE_UNTESTED, decide_compatibility
from .discovery import VersionObservation, current_platform, observation_identity_changed, observe_harness_version

CACHE_TTL_SECONDS = 5 * 60
# A decision is reused only for identical inputs, so one list read costs one runtime call per changed row.
DECISION_TTL_SECONDS = 60
ACKNOWLEDGEMENTS_FILENAME = "harness-version-acknowledgements.json"
MANIFEST_FILENAME = "harness_version_coverage_v1.json"

_lock = threading.Lock()
_observations: dict[tuple[str, str], VersionObservation] = {}
_decisions: dict[tuple[str, str], tuple[tuple[object, ...], float, dict[str, object]]] = {}
_manifest_path = Path(__file__).resolve().parent.parent / "schemas" / MANIFEST_FILENAME


def invalidate(guard_home: Path, harness: str | None = None) -> None:
    """Drop cached observations, e.g. after install, repair, or refresh."""

    with _lock:
        for cache in (_observations, _decisions):
            for key in list(cache):
                if key[0] == str(guard_home) and (harness is None or key[1] == harness):
                    del cache[key]


def _file_stamp(path: Path) -> tuple[int, int] | None:
    try:
        stat = path.stat()
    except OSError:
        return None
    return (stat.st_mtime_ns, stat.st_size)


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
    manifest_path: Path | None = None,
    guard_version: str = __version__,
    platform: str | None = None,
) -> dict[str, object]:
    observation = _observation(harness, context, force=force, clock=clock, observe=observe)
    manifest = manifest_path or _manifest_path
    platform = platform or current_platform()
    now = clock()
    key = (str(context.guard_home), harness)
    inputs = (
        observation,
        str(manifest),
        _file_stamp(manifest),
        guard_version,
        platform,
        _file_stamp(context.guard_home / ACKNOWLEDGEMENTS_FILENAME),
    )
    with _lock:
        cached = _decisions.get(key)
    if not force and cached is not None and cached[0] == inputs and now < cached[1]:
        return copy.deepcopy(cached[2])
    payload = decide_compatibility(
        harness=harness,
        observation=observation,
        manifest_path=manifest,
        guard_version=guard_version,
        platform=platform,
        now=now,
        guard_home=context.guard_home,
    )
    if payload.get("reason") not in {"runtime_unavailable", "runtime_error"}:
        # A stale observation decides differently, so the decision never outlives it.
        expires = min(now + DECISION_TTL_SECONDS, observation.observed_at + OBSERVATION_MAX_AGE_SECONDS)
        with _lock:
            _decisions[key] = (inputs, expires, copy.deepcopy(payload))
    return payload


def _drop_decision(guard_home: Path, harness: str) -> None:
    with _lock:
        _ = _decisions.pop((str(guard_home), harness), None)


class AcknowledgementRejectedError(ValueError):
    """The acknowledgement does not match a current untested observation."""


def acknowledge(
    harness: str,
    key: object,
    context: HarnessContext,
    *,
    clock: Callable[[], float] = time.time,
    observe: Callable[..., VersionObservation] = observe_harness_version,
    manifest_path: Path | None = None,
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
            manifest_path=manifest_path,
            guard_version=guard_version,
            platform=platform,
        )

    payload = current()
    ack = payload.get("acknowledgement")
    if not isinstance(ack, dict):
        raise AcknowledgementRejectedError("acknowledgement_not_eligible")
    if payload.get("state") != STATE_UNTESTED or not ack.get("eligible") or not isinstance(key, str):
        raise AcknowledgementRejectedError("acknowledgement_not_eligible")
    if key != ack.get("key"):
        raise AcknowledgementRejectedError("acknowledgement_stale")
    record_acknowledgement(context.guard_home, harness=harness, key=key)
    _drop_decision(context.guard_home, harness)
    return current()


def clear_acknowledgement(
    harness: str,
    context: HarnessContext,
    *,
    clock: Callable[[], float] = time.time,
    observe: Callable[..., VersionObservation] = observe_harness_version,
    manifest_path: Path | None = None,
    guard_version: str = __version__,
    platform: str | None = None,
) -> dict[str, object]:
    clear_acknowledgements(context.guard_home, harness=harness)
    _drop_decision(context.guard_home, harness)
    return compatibility_for(
        harness,
        context,
        clock=clock,
        observe=observe,
        manifest_path=manifest_path,
        guard_version=guard_version,
        platform=platform,
    )
