"""Read-only posture of the runtimes configured tools launch with.

Collects the executables configured MCP servers would launch, has the native
probe resolve and describe them without starting them, and has the native
assessment match them against runtime advisories. Nothing here feeds hooks, approvals or any
allow or deny decision. Given a Guard home, it also lists the processes this
user can see running from those files, each bound to the build it started
from, so a runtime replaced on disk still reports its old processes. Coverage
is observation only: other users' processes are not seen, so the scope is
never complete and no fix is ever proven. Unknown stays unknown; the report
makes no safety claim.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import replace
from pathlib import Path

from .models import HarnessDetection
from .runtime_identity_assessment import RuntimeIdentityAssessment, RuntimeIdentityError, assess_runtime_identity
from .runtime_identity_candidates import RuntimeCandidates, collect_runtime_candidates
from .runtime_identity_probe import RuntimeProbe

RUNTIME_POSTURE_SCHEMA = "guard.runtime-posture.v1"
ADVISORIES_UNAVAILABLE = "runtime_advisories_unavailable"
BUNDLE_ASSESSMENT_FAILED = "runtime_advisory_bundle_assessment_failed"
HARNESS_CONFIG_UNREADABLE = "harness_config_unreadable"
CANDIDATE_LIMIT_REACHED = "runtime_candidate_limit_reached"
COVERAGE_STATEMENT = (
    "Observed only: executables configured tools would launch, described without running them. "
    "Running processes are not enumerated and no runtime is reported safe."
)
INSTANCE_COVERAGE_STATEMENT = (
    "Observed only: executables configured tools would launch, described without running them, "
    "and the processes this user can see running from them. No runtime is reported safe."
)


def build_runtime_posture(
    detections: Sequence[HarnessDetection],
    *,
    generated_at: str,
    environment: Mapping[str, str] | None = None,
    workspace_dir: Path | None = None,
    skipped_harnesses: Sequence[str] = (),
    advisory_bundle: Mapping[str, object] | None = None,
    advisory_bundle_reason: str | None = None,
    instance_home: Path | None = None,
) -> dict[str, object]:
    """``advisory_bundle`` is the native ``cached_bundle`` input; the native runtime verifies it.

    ``instance_home`` is the Guard home that carries running instances between
    probes; without it processes are not enumerated.
    """
    try:
        candidates, probe = collect_runtime_candidates(
            detections, environment=environment, workspace_dir=workspace_dir, instance_home=instance_home
        )
    except ValueError as error:
        # Reading server entries projects their identity through the native runtime.
        code = str(error) if str(error).startswith("native_") else "runtime_candidates_unavailable"
        return {**_base_payload(generated_at, None), "status": "unavailable", "error": code, "runtimes": []}
    except RuntimeIdentityError as error:
        # The native probe resolves the launches, so without it nothing is known about them.
        base = {**_base_payload(generated_at, None), "skipped_harnesses": list(dict.fromkeys(skipped_harnesses))}
        return {**base, "status": "unavailable", "error": error.code, "runtimes": []}
    base = {**_base_payload(generated_at, candidates), "skipped_harnesses": list(dict.fromkeys(skipped_harnesses))}
    # A harness whose config could not be read, or launches past the candidate
    # limit, leave the inventory incomplete, which is not the same as having no servers.
    status, error_code = "ok", None
    if skipped_harnesses:
        status, error_code = "partial", HARNESS_CONFIG_UNREADABLE
    elif candidates.truncated:
        status, error_code = "partial", CANDIDATE_LIMIT_REACHED
    if not candidates.candidates and advisory_bundle is None:
        return {**base, "status": status, "error": error_code, "runtimes": []}
    advisory_rows: list[dict[str, object]] = []
    matches: dict[str, list[object]] = {}
    instances = probe.instances
    instance_error: str | None = None
    coverage_reason: str | None = advisory_bundle_reason or ADVISORIES_UNAVAILABLE
    coverage = dict(_coverage(reason=coverage_reason, instances=instances))
    source: dict[str, object] | None = None
    request: dict[str, object] = {
        "artifacts": list(probe.artifacts),
        "locations": list(probe.locations),
        "advisories": [],
        "scope_complete": False,
    }
    try:
        assessment, instance_error = _assess_with_instances(request, probe, advisory_bundle)
    except RuntimeIdentityError as error:
        status, error_code = "partial", error.code
        coverage = dict(_coverage(reason="runtime_assessment_failed", instances=instances))
    else:
        source = assessment.advisory_source
        coverage = dict(_coverage(reason=coverage_reason, instances=instances))
        if advisory_bundle is not None and source:
            # The native runtime decides what the bundle covers; this only relays it.
            reason = source.get("coverage_reason")
            coverage = dict(
                _coverage(
                    reason=reason if isinstance(reason, str) else None,
                    available=source.get("advisories_available") is True,
                    instances=instances,
                )
            )
        matches = {
            str(row["artifact_id"]): list(found) if isinstance(found := row.get("matches"), list) else []
            for row in assessment.artifacts
        }
        advisory_rows = [
            {
                "advisory_id": row.advisory_id,
                "verdict": row.verdict,
                "reasons": list(row.reasons),
                "affected_artifact_ids": list(row.affected_artifact_ids),
                "affected_instance_ids": list(row.affected_instance_ids),
                "severity": row.severity,
                "known_exploited": row.known_exploited,
                "title": row.title,
            }
            for row in assessment.advisories
        ]
    return {
        **base,
        "status": status,
        "error": error_code,
        "coverage": coverage,
        "advisory_source": source,
        "runtimes": _runtime_rows(probe, candidates, matches),
        "advisories": advisory_rows,
        "instances": _instance_summary(probe, instance_error),
    }


def _assess_with_instances(
    request: dict[str, object],
    probe: RuntimeProbe,
    advisory_bundle: Mapping[str, object] | None,
) -> tuple[RuntimeIdentityAssessment, str | None]:
    """Assess with the running instances, or the files alone and why the instances were left out."""

    if probe.instances is None:
        return _assess(request, advisory_bundle), None
    try:
        return _assess({**request, "instances": list(probe.instances)}, advisory_bundle), None
    except RuntimeIdentityError as error:
        # Too many processes, or one carried build the assessment rejects, must not cost the files.
        placed = {location.get("artifact_id") for location in probe.locations}
        artifacts = [row for row in probe.artifacts if row.get("artifact_id") in placed]
        return _assess({**request, "artifacts": artifacts}, advisory_bundle), error.code


def _instance_summary(probe: RuntimeProbe, instance_error: str | None) -> dict[str, object]:
    by_artifact = {str(artifact["artifact_id"]): artifact for artifact in probe.artifacts}
    rows: list[dict[str, object]] = []
    for instance in probe.instances or ():
        artifact = by_artifact.get(str(instance["artifact_id"]), {})
        rows.append(
            {
                "instance_id": instance["instance_id"],
                "pid": instance["pid"],
                "location_id": instance["location_id"],
                "state": instance["state"],
                "artifact_id": instance["artifact_id"],
                "version": artifact.get("version"),
                # A process whose file changed since it started runs bytes nobody hashed.
                "identified": artifact.get("executable_sha256") is not None,
            }
        )
    return {
        "enumerated": probe.instances is not None,
        "assessed": probe.instances is not None and instance_error is None,
        "assessment_error": instance_error,
        "running": sum(row["state"] == "running" for row in rows),
        "exited": sum(row["state"] == "exited" for row in rows),
        "unidentified": sum(row["state"] == "running" and not row["identified"] for row in rows),
        "unbound_processes": probe.unbound_processes,
        "limit_reached": probe.instance_limit_reached,
        "rows": rows,
    }


def _assess(request: dict[str, object], advisory_bundle: Mapping[str, object] | None) -> RuntimeIdentityAssessment:
    if advisory_bundle is None:
        return assess_runtime_identity(request)
    try:
        return assess_runtime_identity({**request, "cached_bundle": dict(advisory_bundle)})
    except RuntimeIdentityError as error:
        failure = error.code
    # The bundle must not cost the observation: report the runtimes without it.
    assessment = assess_runtime_identity(request)
    source = {"state": "invalid", "reason": failure, "coverage_reason": BUNDLE_ASSESSMENT_FAILED}
    return replace(assessment, advisory_source={**source, "advisories_available": False})


def _coverage(
    *, reason: str | None, available: bool = False, instances: Sequence[object] | None = None
) -> dict[str, object]:
    return {
        "mode": "observed_only",
        "instances_enumerated": instances is not None,
        "advisories_available": available,
        "reason": reason,
        "statement": COVERAGE_STATEMENT if instances is None else INSTANCE_COVERAGE_STATEMENT,
    }


def _base_payload(generated_at: str, candidates: RuntimeCandidates | None) -> dict[str, object]:
    return {
        "schema": RUNTIME_POSTURE_SCHEMA,
        "generated_at": generated_at,
        "scope_complete": False,
        "coverage": _coverage(reason=ADVISORIES_UNAVAILABLE),
        "advisories": [],
        "candidate_limit_reached": bool(candidates and candidates.truncated),
        "unresolved_launches": [
            {"harness": item.harness, "server": item.server, "command": item.command, "lookup": item.lookup}
            for item in (candidates.unresolved if candidates else ())
        ],
    }


def _runtime_rows(
    probe: RuntimeProbe,
    candidates: RuntimeCandidates,
    matches: Mapping[str, list[object]],
) -> list[dict[str, object]]:
    by_artifact = {str(artifact["artifact_id"]): artifact for artifact in probe.artifacts}
    sources = {candidate.path: candidate.sources for candidate in candidates.candidates}
    rows: list[dict[str, object]] = []
    for observation in probe.observations:
        artifact_id = observation.get("artifact_id")
        artifact = by_artifact.get(str(artifact_id)) if isinstance(artifact_id, str) else None
        requested = str(observation["requested_path"])
        resolved = observation.get("resolved_path")
        row: dict[str, object] = {
            "location_id": observation["location_id"],
            "path": resolved if isinstance(resolved, str) else requested,
            "location_state": observation["state"],
            "reason": observation.get("reason"),
            "coverage": "observed_only",
            "launched_by": [
                {"harness": harness, "server": server, "role": role}
                for harness, server, role in sources.get(requested, ())
            ],
            "artifact_id": artifact_id,
            "family": None,
            "version": None,
            "identity_assurance": "unknown",
            "executable_sha256": None,
            "os": None,
            "arch": None,
            "advisory_matches": [],
        }
        if artifact is not None:
            row.update(
                family=artifact["family"],
                version=artifact.get("version"),
                identity_assurance=artifact["identity_assurance"],
                executable_sha256=artifact.get("executable_sha256"),
                os=artifact["os"],
                arch=artifact["arch"],
                advisory_matches=matches.get(str(artifact_id), []),
            )
        rows.append(row)
    return rows


__all__ = [
    "ADVISORIES_UNAVAILABLE",
    "BUNDLE_ASSESSMENT_FAILED",
    "HARNESS_CONFIG_UNREADABLE",
    "RUNTIME_POSTURE_SCHEMA",
    "build_runtime_posture",
]
