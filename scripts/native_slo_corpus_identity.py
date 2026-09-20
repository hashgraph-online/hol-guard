"""Separate fixed request identity from untimed platform-specific source evidence."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import cast

_SCOPE = "fixed_requests_and_oracle_implementation_v2"
_BASELINE = "2e672d2d950c6ec471005ddba46e49bba16dc23b"
_FIXED_MATRIX_FIELDS = (
    "required_platforms",
    "observed_platform",
    "required_sizes",
    "required_cases",
    "concurrency",
    "daemon_routes",
    "launcher_routes",
)
_PROFILES = frozenset({"unix_source_v1", "windows_refusal_v1", "windows_handles_v1"})


def _object(value: object) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(type(key) is not str for key in value):
        raise RuntimeError("paired corpus identity object is invalid")
    return cast(Mapping[str, object], value)


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _is_digest(value: object) -> bool:
    return type(value) is str and len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def _profile(matrix: Mapping[str, object]) -> str:
    supported = matrix.get("reference_review_supported")
    if type(supported) is not bool:
        raise RuntimeError("source oracle support was not declared")
    platform = matrix.get("observed_platform")
    if platform == "windows-x64":
        return "windows_handles_v1" if supported else "windows_refusal_v1"
    if platform in {"linux-x64", "macos-x64", "macos-arm64"} and supported:
        return "unix_source_v1"
    raise RuntimeError("source oracle platform is unsupported")


def corpus_identity(definition: Mapping[str, object]) -> dict[str, str]:
    """Keep both oracles reviewable while comparing the same timed requests.

    The definition still binds the manifest, oracle implementation, validated
    case IDs and every fixed timing payload. Only observed coverage/scope fields
    leave its matrix projection; they remain in the separate evidence digest.
    Source references occur in untimed contract preflights, not these timers.
    """
    matrix = _object(definition.get("matrix"))
    profile = _profile(matrix)
    shared = {
        **definition,
        "identity_scope": _SCOPE,
        "identity_implementation_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "matrix": {key: matrix[key] for key in _FIXED_MATRIX_FIELDS},
    }
    evidence = {**definition, "source_reference_oracle_profile": profile}
    return {
        "corpus_digest": _digest(shared),
        "corpus_definition_scope": _SCOPE,
        "contract_evidence_digest": _digest(evidence),
        "reference_oracle_profile": profile,
    }


def paired_corpus_identity(
    baseline: Sequence[Mapping[str, object]], candidate: Sequence[Mapping[str, object]]
) -> dict[str, object]:
    """Reject changed requests, unstable arm evidence or undeclared oracle differences."""
    combined = [*baseline, *candidate]
    if not baseline or not candidate:
        raise RuntimeError("paired corpus identity requires both arms")
    digests = {report.get("corpus_digest") for report in combined}
    if len(digests) != 1 or not all(type(value) is str and value for value in digests):
        raise RuntimeError("paired artifacts used different corpus definitions")
    scopes = {report.get("corpus_definition_scope") for report in combined}
    if scopes != {_SCOPE}:
        raise RuntimeError("paired corpus definition scopes differ")
    if not all(_is_digest(value) for value in digests):
        raise RuntimeError("paired corpus request digest is invalid")
    profiles: dict[str, str] = {}
    evidence_digests: dict[str, str] = {}
    source_results: dict[str, bool] = {}
    for arm, reports in (("baseline", baseline), ("candidate", candidate)):
        observed = {report.get("reference_oracle_profile") for report in reports}
        evidence = {report.get("contract_evidence_digest") for report in reports}
        if len(observed) != 1 or not all(type(value) is str and value in _PROFILES for value in observed):
            raise RuntimeError("source oracle profile changed within a paired arm")
        if len(evidence) != 1 or not all(_is_digest(value) for value in evidence):
            raise RuntimeError("contract evidence changed within a paired arm")
        profiles[arm] = cast(str, next(iter(observed)))
        evidence_digests[arm] = cast(str, next(iter(evidence)))
        source_results[arm] = all(
            _object(_object(report.get("contract_corpus")).get("platform_scope")).get("reference_review_qualified")
            is True
            for report in reports
        )
    if profiles["baseline"] == profiles["candidate"]:
        if evidence_digests["baseline"] != evidence_digests["candidate"]:
            raise RuntimeError("paired contract evidence differs without a source oracle transition")
    else:
        if profiles != {"baseline": "windows_refusal_v1", "candidate": "windows_handles_v1"}:
            raise RuntimeError("paired source oracle profiles are not a supported comparison")
        for report in baseline:
            scope = _object(_object(report.get("contract_corpus")).get("platform_scope"))
            if (
                _object(report.get("runtime")).get("build_sha") != _BASELINE
                or scope.get("reference_review_supported") is not False
                or scope.get("reference_review_qualified") is not False
                or scope.get("platform_denial_contract_passed") is not True
            ):
                raise RuntimeError("original Windows source refusal was not proven")
        if not source_results["candidate"]:
            raise RuntimeError("candidate Windows full source contract was not proven")
    return {
        "corpus_definition_scope": _SCOPE,
        "reference_oracle_profiles": profiles,
        "contract_evidence_digests": evidence_digests,
        "reference_feature_evidence": {
            "baseline_full_review": source_results["baseline"],
            "candidate_full_review": source_results["candidate"],
            "headline_timing_eligible": False,
            "reference_performance_comparison_available": False,
        },
    }
