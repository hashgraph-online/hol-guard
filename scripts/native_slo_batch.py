"""Exact post-load route conservation without per-request control-pipe traffic."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import replace

from scripts.native_slo_adapter import Observation


def validate_batch_routes(
    observations: Sequence[Observation], before: Mapping[str, int], after: Mapping[str, int]
) -> tuple[list[Observation], dict[str, int]]:
    """Attribute successful synthetic allows only after independent count checks.

    Concurrent hook spans overlap, so a before/after counter around each hook
    cannot prove that hook's route. The isolated fixture instead requires exact
    conservation for the whole wave. Overload responses stay unattributed at the
    individual level; their native-fail-safe and bypass counts remain separate.
    """
    deltas = {name: after.get(name, 0) - before.get(name, 0) for name in set(before) | set(after)}
    if any(number < 0 for number in deltas.values()):
        raise RuntimeError("batch route counters regressed")
    routes = {name: number for name, number in deltas.items() if number}
    if set(routes) - {"native_resident", "native_fail_safe"}:
        raise RuntimeError("batch left native execution authority")
    allowed = sum(observation.allowed and not observation.overloaded for observation in observations)
    overloaded = sum(observation.overloaded for observation in observations)
    if allowed + overloaded != len(observations):
        raise RuntimeError("batch contains an unexpected semantic decision")
    if routes.get("native_resident", 0) != allowed or routes.get("native_fail_safe", 0) > overloaded:
        raise RuntimeError("batch native route count does not match delivered decisions")
    if overloaded:
        routes["engine_bypassed"] = overloaded - routes.get("native_fail_safe", 0)
        routes = {name: number for name, number in routes.items() if number}
    attributed = [
        replace(observation, route="native_resident" if not observation.overloaded else "overload_batch_validated")
        for observation in observations
    ]
    return attributed, routes


def apply_offered_route_evidence(
    report: dict[str, object], observations: Sequence[Observation], before: Mapping[str, int], after: Mapping[str, int]
) -> None:
    attributed, routes = validate_batch_routes(observations, before, after)
    report["route_attribution"] = "isolated_batch_counter_conservation"
    report["routes"] = routes
    report["evaluated_allowed"] = sum(item.allowed and item.route == "native_resident" for item in attributed)
    report["load_contract_passed"] = (
        report["accounted"] is True
        and report["worker_shutdown_complete"] is True
        and report["completed"] == report["attempted"]
        and (report["concurrency"] == 64 or report["overloaded"] == 0)
    )
