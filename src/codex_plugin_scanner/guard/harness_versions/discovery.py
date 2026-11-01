"""Observe which harness version is installed, through the native runtime.

The runtime reads trusted package metadata first and only falls back to a
bounded, fixed-argument ``--version`` probe for a standalone binary. When more
than one installation is found and they disagree, the result is ambiguous: the
caller must not pick the most favorable version. Without a runtime the version
is unknown.

Observations carry an opaque installation id and a bounded reason code. Raw
command output never leaves the runtime.
"""

from __future__ import annotations

import os
import platform
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Final

from ..adapters.base import HarnessContext

_FEATURE: Final = "native-harness-version-discovery-v1"
_COMMAND: Final = "harness-version-discovery"
_SCHEMA: Final = "harness-version-discovery.v1"
_OUTPUT_LIMIT: Final = 64 * 1024
# Up to three installs, each with a 3-second probe.
_TIMEOUT_SECONDS: Final = 20.0
# The process variables the runtime uses to find installs and run a probe.
_ENVIRONMENT: Final = ("PATH", "PATHEXT", "SYSTEMROOT", "TEMP", "TMP")
_STATES: Final = frozenset({"observed", "unavailable", "ambiguous"})
_SOURCES: Final = frozenset({"package-metadata", "version-probe", "none"})


@dataclass(frozen=True, slots=True)
class VersionObservation:
    harness: str
    state: str  # observed | unavailable | ambiguous
    version: str | None  # canonical exact version
    source: str  # package-metadata | version-probe | none
    installation_id: str | None
    reason: str | None
    observed_at: float
    identity: tuple[tuple[str, int, int, int], ...] = ()
    candidates: tuple[str, ...] = ()


def current_platform() -> str:
    system = {"darwin": "darwin", "linux": "linux", "windows": "windows"}.get(platform.system().lower(), "unknown")
    machine = platform.machine().lower()
    arch = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "x86_64", "amd64": "x86_64"}.get(machine, "unknown")
    return f"{system}-{arch}"


def _runtime(op: str, harness: str, context: HarnessContext, **fields: object) -> dict[str, object] | None:
    from ..mdm.runtime_request import runtime_answer

    request: dict[str, object] = {
        "schema": _SCHEMA,
        "op": op,
        "harness": harness,
        "home_dir": str(context.home_dir),
        "guard_home": str(context.guard_home),
        "environment": {name: os.environ[name] for name in _ENVIRONMENT if name in os.environ},
        **fields,
    }
    return runtime_answer(_FEATURE, _COMMAND, request, output_limit=_OUTPUT_LIMIT, timeout_seconds=_TIMEOUT_SECONDS)


def _optional_text(value: object) -> str | None:
    if value is None or isinstance(value, str):
        return value
    raise ValueError


def _identity(value: object) -> tuple[str, int, int, int]:
    if not isinstance(value, list) or len(value) != 4:
        raise ValueError
    path_text, inode, size, mtime = value
    if not isinstance(path_text, str) or not all(isinstance(item, int) for item in (inode, size, mtime)):
        raise ValueError
    return (path_text, inode, size, mtime)


def _observation(harness: str, answer: Mapping[str, object], now: float) -> VersionObservation:
    state, source = answer.get("state"), answer.get("source")
    identity, candidates = answer.get("identity"), answer.get("candidates")
    if state not in _STATES or source not in _SOURCES:
        raise ValueError
    if not isinstance(identity, list) or not isinstance(candidates, list):
        raise ValueError
    if not all(isinstance(item, str) for item in candidates):
        raise ValueError
    return VersionObservation(
        harness,
        str(state),
        _optional_text(answer.get("version")),
        str(source),
        _optional_text(answer.get("installation_id")),
        _optional_text(answer.get("reason")),
        now,
        tuple(_identity(item) for item in identity),
        tuple(candidates),
    )


def observe_harness_version(
    harness: str, context: HarnessContext, *, clock: Callable[[], float] = time.time
) -> VersionObservation:
    """Observe one harness's installed version with provenance."""

    now = clock()
    answer = _runtime("observe", harness, context, now=now)
    if answer is not None:
        try:
            return _observation(harness, answer, now)
        except ValueError:
            pass
    return VersionObservation(harness, "unavailable", None, "none", None, "runtime_unavailable", now)


def observation_identity_changed(observation: VersionObservation, context: HarnessContext) -> bool:
    """Cheaply detect a replaced executable or package, or a changed set of installs."""

    answer = _runtime(
        "identity-changed",
        observation.harness,
        context,
        candidates=list(observation.candidates),
        identity=[list(item) for item in observation.identity],
    )
    return answer is None or answer.get("changed") is not False
