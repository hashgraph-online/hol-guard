"""Bridge to the native ``runtime-identity-probe`` command.

The native command inspects each candidate executable without starting it:
it resolves symlinks, hashes the file and infers family and version from the
install layout. It also resolves configured MCP server launches (search path
lookup, relative anchoring and a script's ``#!`` interpreter) to the files to
describe. Asked for instances, it also lists the processes running from those
files, each bound to the build it started from. This module only sends paths
or launch specs and checks the shape of the reply. Its ``artifacts``,
``locations`` and ``instances`` are valid input for ``runtime-identity-assess``.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from .runtime_identity_assessment import RuntimeIdentityError, run_native_identity_command

# Launch resolution and instances are additive capabilities of the same command.
RUNTIME_PROBE_LAUNCH_FEATURE = "runtime-identity-launch-v1"
RUNTIME_PROBE_INSTANCES_FEATURE = "runtime-identity-instances-v1"
RUNTIME_PROBE_COMMAND = "runtime-identity-probe"
RUNTIME_PROBE_SCHEMA = "guard.runtime-identity-probe.v1"
# The probe hashes whole files, so it gets more time than a plain assessment.
_PROBE_TIMEOUT_SECONDS = 60.0

_LOCATION_STATES = frozenset({"present", "missing", "unknown"})
_LAUNCH_STATES = frozenset({"resolved", "unresolved"})
_INSTANCE_STATES = frozenset({"running", "exited", "unknown"})
_INSTANCE_TEXT_KEYS = ("instance_id", "boot_identity", "start_identity", "artifact_id")
_KNOWN_INSTANCE_INVALID = "runtime_identity_probe_known_instance_invalid"
_ARTIFACT_TEXT_KEYS = ("artifact_id", "family", "os", "arch", "identity_assurance")


@dataclass(frozen=True)
class RuntimeProbe:
    artifacts: tuple[dict[str, object], ...]
    locations: tuple[dict[str, object], ...]
    observations: tuple[dict[str, object], ...]
    # One row per launch spec sent, in order; empty for a path-only probe.
    launches: tuple[dict[str, object], ...] = ()
    candidate_limit_reached: bool = False
    # ``None`` when instances were not asked for.
    instances: tuple[dict[str, object], ...] | None = None
    unbound_processes: int = 0
    instance_limit_reached: bool = False


def probe_runtime_launches(
    launches: Sequence[Mapping[str, object]],
    *,
    environment: Mapping[str, str],
    candidate_limit: int,
    known_instances: Sequence[Mapping[str, object]] | None = None,
) -> RuntimeProbe:
    """Resolve configured launches and describe their executables natively, never running them.

    Each launch carries ``command``, ``launch_dir`` and optionally the server's
    own ``configured_path``. ``environment`` holds only the process values a
    search path may reference; the native command never echoes them.

    ``known_instances`` asks for running instances too, passing back what an
    earlier probe bound them to so a file replaced since keeps its old build.
    """

    if not launches:
        return RuntimeProbe(artifacts=(), locations=(), observations=())
    request: dict[str, object] = {
        "launches": [dict(launch) for launch in launches],
        "environment": dict(environment),
        "candidate_limit": candidate_limit,
    }
    if known_instances is None:
        return _probe(RUNTIME_PROBE_LAUNCH_FEATURE, request)
    known = [dict(item) for item in known_instances]
    try:
        return _probe(RUNTIME_PROBE_INSTANCES_FEATURE, {**request, "instances": True, "known_instances": known})
    except RuntimeIdentityError as error:
        if error.code == _KNOWN_INSTANCE_INVALID and known:
            # A damaged record costs what it carried, not the scan.
            return _probe(RUNTIME_PROBE_INSTANCES_FEATURE, {**request, "instances": True, "known_instances": []})
        raise


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
    instances = result.get("instances")
    unbound = result.get("unbound_processes", 0)
    instance_limit_reached = result.get("instance_limit_reached", False)
    if not (
        isinstance(artifacts, list)
        and isinstance(locations, list)
        and isinstance(observations, list)
        and isinstance(launches, list)
        and isinstance(limit_reached, bool)
        and (instances is None or isinstance(instances, list))
        and isinstance(unbound, int)
        and not isinstance(unbound, bool)
        and unbound >= 0
        and isinstance(instance_limit_reached, bool)
    ):
        raise RuntimeIdentityError("runtime_identity_probe_failed")
    artifact_ids: set[object] = {row.get("artifact_id") for row in artifacts if isinstance(row, dict)}
    location_ids: set[object] = {row.get("location_id") for row in locations if isinstance(row, dict)}
    if not (
        all(_artifact_ok(row) for row in artifacts)
        and all(_location_ok(row, artifact_ids) for row in locations)
        and all(_observation_ok(row) for row in observations)
        and all(_launch_ok(row, index) for index, row in enumerate(launches))
        and all(_instance_ok(row, artifact_ids, location_ids) for row in instances or ())
    ):
        raise RuntimeIdentityError("runtime_identity_probe_failed")
    return RuntimeProbe(
        artifacts=tuple(artifacts),
        locations=tuple(locations),
        observations=tuple(observations),
        launches=tuple(launches),
        candidate_limit_reached=limit_reached,
        instances=None if instances is None else tuple(instances),
        unbound_processes=unbound,
        instance_limit_reached=instance_limit_reached,
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
        # Only a process whose file was replaced runs bytes nobody hashed.
        and (isinstance(row.get("executable_sha256"), str) or assurance == "unknown")
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


def _instance_ok(row: object, artifact_ids: set[object], location_ids: set[object]) -> bool:
    if not isinstance(row, dict):
        return False
    pid = row.get("pid")
    location_id = row.get("location_id")
    return (
        all(isinstance(row.get(key), str) and row.get(key) for key in _INSTANCE_TEXT_KEYS)
        and isinstance(pid, int)
        and not isinstance(pid, bool)
        and pid > 0
        and row.get("artifact_id") in artifact_ids
        and (location_id is None or location_id in location_ids)
        and row.get("state") in _INSTANCE_STATES
        and row.get("coverage") == "observed_only"
    )


__all__ = [
    "RUNTIME_PROBE_INSTANCES_FEATURE",
    "RUNTIME_PROBE_LAUNCH_FEATURE",
    "RuntimeProbe",
    "probe_runtime_launches",
]
