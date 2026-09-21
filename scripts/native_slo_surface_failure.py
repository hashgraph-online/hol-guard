"""Bounded context for an already failed installed-surface validation.

The caller owns the original counters and witness. An optional observer read
runs only after failure, once, without retry, readiness refresh or evaluation.
Neither collection nor the unchanged privacy sanitizer may replace the error.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping

from scripts.native_slo_contract import SAFE_ROUTE_NAMES
from scripts.native_slo_failure import failure_evidence
from scripts.native_slo_observation_failure import contextual_failure, verdict_evidence

_ROUTES = SAFE_ROUTE_NAMES | {"legacy", "legacy_hook_pool", "engine_bypassed"}
_CASE = re.compile(r"[A-Za-z0-9_./-]{1,96}\Z")
_DIGEST = re.compile(r"[a-f0-9]{64}\Z")
_STAGES = frozenset({"route", "witness"})
_WITNESS_FIELDS = (
    "native_call_diagnostic",
    "native_call_count",
    "native_completed_call_count",
    "policy_refusal_diagnostic",
    "policy_refusal_count",
)


def _routes(snapshot: Mapping[str, int]) -> dict[str, int]:
    return {name: value for name, value in snapshot.items() if name in _ROUTES and type(value) is int}


def enrich_surface_failure(
    error: Exception,
    *,
    case_id: str,
    registration_digest: str,
    stage: str,
    expected_route: str,
    observed_route: str,
    routes_before: Mapping[str, int],
    routes_after: Mapping[str, int],
    surface_scope: str | None = None,
    evidence: Mapping[str, object] | None = None,
    read_evidence: Callable[[], Mapping[str, object]] | None = None,
) -> Exception:
    """Return a private wrapper or the identical primary error if enrichment fails."""

    try:
        if _CASE.fullmatch(case_id) is None or _DIGEST.fullmatch(registration_digest) is None or stage not in _STAGES:
            return error
        detail: dict[str, object] = {
            "case": case_id.replace("/", "."),
            "registration_digest": registration_digest,
            "failed_stage": stage,
            "expected_route": expected_route if expected_route in _ROUTES else "unrecognized",
            "observed_route": observed_route if observed_route in _ROUTES else "unrecognized",
            "routes_before": _routes(routes_before),
            "routes_after": _routes(routes_after),
            "unrecognized_routes_before": sum(name not in _ROUTES for name in routes_before),
            "unrecognized_routes_after": sum(name not in _ROUTES for name in routes_after),
            "witness_capture": "existing_case_result" if evidence is not None else "unavailable",
        }
        if surface_scope in {"global", "project"}:
            detail["surface_scope"] = surface_scope
        if evidence is None and read_evidence is not None:
            detail["witness_capture"] = "after_failure"
            try:
                evidence = read_evidence()
            except Exception as observer_error:
                detail["witness_read_failure"] = failure_evidence(observer_error)
        detail["witness_available"] = isinstance(evidence, Mapping)
        if isinstance(evidence, Mapping):
            detail["observed_semantics"] = verdict_evidence(native=evidence.get("native_result"))
            detail.update((name, evidence.get(name)) for name in _WITNESS_FIELDS)
        return contextual_failure(error, **detail)
    except Exception:
        # Diagnostics must never mask the original verdict or assertion, even
        # when the unchanged aggregate privacy/size validation rejects them.
        return error


__all__ = ["enrich_surface_failure"]
