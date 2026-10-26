"""Bridge to the native ``runtime-identity-probe`` command.

The native command inspects each candidate executable without starting it:
it resolves symlinks, hashes the file and infers family and version from the
install layout. It also resolves configured MCP server launches (search path
lookup, relative anchoring and a script's ``#!`` interpreter) to the files to
describe. This module only sends paths or launch specs and checks the shape of
the reply. Its ``artifacts`` and ``locations`` are valid input for
``runtime-identity-assess``.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from .runtime_identity_assessment import RuntimeIdentityError, run_native_identity_command

RUNTIME_PROBE_FEATURE = "runtime-identity-probe-v1"
# Launch resolution is an additive capability of the same command.
RUNTIME_PROBE_LAUNCH_FEATURE = "runtime-identity-launch-v1"
RUNTIME_PROBE_COMMAND = "runtime-identity-probe"
RUNTIME_PROBE_SCHEMA = "guard.runtime-identity-probe.v1"
RUNTIME_PROBE_MAX_PATHS = 128
# The probe hashes whole files, so it gets more time than a plain assessment.
_PROBE_TIMEOUT_SECONDS = 60.0

_LOCATION_STATES = frozenset({"present", "missing", "unknown"})
_LAUNCH_STATES = frozenset({"resolved", "unresolved"})
_ARTIFACT_TEXT_KEYS = ("artifact_id", "family", "os", "arch", "identity_assurance")


@dataclass(frozen=True)
class RuntimeProbe:
    artifacts: tuple[dict[str, object], ...]
    locations: tuple[dict[str, object], ...]
    observations: tuple[dict[str, object], ...]
    # One row per launch spec sent, in order; empty for a path-only probe.
    launches: tuple[dict[str, object], ...] = ()
    candidate_limit_reached: bool = False


def probe_runtime_paths(paths: Sequence[str]) -> RuntimeProbe:
    """Describe the executables at ``paths`` natively, never running them."""

    unique = tuple(dict.fromkeys(paths))
    if len(unique) > RUNTIME_PROBE_MAX_PATHS:
        raise RuntimeIdentityError("runtime_identity_probe_too_many_paths")
    if not unique:
        return RuntimeProbe(artifacts=(), locations=(), observations=())
    return _probe(RUNTIME_PROBE_FEATURE, {"paths": list(unique)})


def probe_runtime_launches(
    launches: Sequence[Mapping[str, object]],
    *,
    environment: Mapping[str, str],
    candidate_limit: int,
) -> RuntimeProbe:
    """Resolve configured launches and describe their executables natively, never running them.

    Each launch carries ``command``, ``launch_dir`` and optionally the server's
    own ``configured_path``. ``environment`` holds only the process values a
    search path may reference; the native command never echoes them.
    """

    if not launches:
        return RuntimeProbe(artifacts=(), locations=(), observations=())
    request: dict[str, object] = {
        "launches": [dict(launch) for launch in launches],
        "environment": dict(environment),
        "candidate_limit": candidate_limit,
    }
    return _probe(RUNTIME_PROBE_LAUNCH_FEATURE, request)


def _probe(feature: str, request: dict[str, object]) -> RuntimeProbe:
    reply = run_native_identity_command(
        feature,
        RUNTIME_PROBE_COMMAND,
        request,
        timeout_seconds=_PROBE_TIMEOUT_SECONDS,
    )
    if reply.get("ok") is not True:
        error = reply.get("error")
        raise RuntimeIdentityError(error if isinstance(error, str) and error else "runtime_identity_probe_failed")
    return _parse_result(reply.get("result"))


def _parse_result(result: object) -> RuntimeProbe:
    if not isinstance(result, dict) or result.get("schema") != RUNTIME_PROBE_SCHEMA:
        raise RuntimeIdentityError("runtime_identity_probe_failed")
    artifacts = result.get("artifacts")
    locations = result.get("locations")
    observations = result.get("observations")
    launches = result.get("launches", [])
    limit_reached = result.get("candidate_limit_reached", False)
    if not (
        isinstance(artifacts, list)
        and isinstance(locations, list)
        and isinstance(observations, list)
        and isinstance(launches, list)
        and isinstance(limit_reached, bool)
    ):
        raise RuntimeIdentityError("runtime_identity_probe_failed")
    artifact_ids: set[object] = {row.get("artifact_id") for row in artifacts if isinstance(row, dict)}
    if not (
        all(_artifact_ok(row) for row in artifacts)
        and all(_location_ok(row, artifact_ids) for row in locations)
        and all(_observation_ok(row) for row in observations)
        and all(_launch_ok(row, index) for index, row in enumerate(launches))
    ):
        raise RuntimeIdentityError("runtime_identity_probe_failed")
    return RuntimeProbe(
        artifacts=tuple(artifacts),
        locations=tuple(locations),
        observations=tuple(observations),
        launches=tuple(launches),
        candidate_limit_reached=limit_reached,
    )


def _artifact_ok(row: object) -> bool:
    if not isinstance(row, dict):
        return False
    assurance = row.get("identity_assurance")
    # The probe infers from paths, so it can never report a trusted identity.
    return (
        all(isinstance(row.get(key), str) for key in _ARTIFACT_TEXT_KEYS)
        and assurance in {"unknown", "self_reported"}
        and (row.get("version") is None or isinstance(row.get("version"), str))
        and isinstance(row.get("executable_sha256"), str)
    )


def _location_ok(row: object, artifact_ids: set[object]) -> bool:
    if not isinstance(row, dict) or not isinstance(row.get("location_id"), str):
        return False
    artifact_id = row.get("artifact_id")
    return row.get("state") in _LOCATION_STATES and (artifact_id is None or artifact_id in artifact_ids)


def _observation_ok(row: object) -> bool:
    return (
        isinstance(row, dict)
        and isinstance(row.get("location_id"), str)
        and isinstance(row.get("requested_path"), str)
        and row.get("state") in _LOCATION_STATES
        and (row.get("resolved_path") is None or isinstance(row.get("resolved_path"), str))
        and (row.get("reason") is None or isinstance(row.get("reason"), str))
    )


def _launch_ok(row: object, index: int) -> bool:
    return (
        isinstance(row, dict)
        and row.get("index") == index
        and row.get("state") in _LAUNCH_STATES
        and (row.get("lookup") is None or isinstance(row.get("lookup"), str))
        and isinstance(row.get("targets"), list)
    )


__all__ = [
    "RUNTIME_PROBE_FEATURE",
    "RUNTIME_PROBE_LAUNCH_FEATURE",
    "RUNTIME_PROBE_MAX_PATHS",
    "RuntimeProbe",
    "probe_runtime_launches",
    "probe_runtime_paths",
]
