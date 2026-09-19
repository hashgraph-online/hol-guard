"""Strict, bounded evidence contracts for the installed native soak."""

from __future__ import annotations

from collections.abc import Mapping
from typing import TypeAlias, cast

_ROUTES = frozenset({"native_resident", "native_oneshot", "native_fail_safe", "native_degraded", "python_semantic"})
_SOURCES = frozenset({"direct", "process"})
RouteCounts: TypeAlias = dict[str, dict[str, int]]


def require_allowed_response(response: Mapping[str, object]) -> None:
    """Do not count a responsive error, denial, or observe-mode fallback as success."""

    if (
        response.get("decision") != "allow"
        or "error" in response
        or response.get("isError", False) is not False
        or response.get("observe_mode", False) is not False
        or response.get("continue", True) is not True
        or response.get("model_output_action", "allow_original") not in ("allow_original", "allow")
        or response.get("policy_action", "allow") not in ("allow", "warn")
    ):
        raise RuntimeError("Hook response did not return an allowed decision.")


def read_route_counts(details: Mapping[str, object] | None) -> RouteCounts | None:
    """Read both authenticated sources without hiding unknown or invalid counters."""

    workers = details.get("hook_workers") if details is not None else None
    routes = cast(Mapping[object, object], workers).get("routes") if isinstance(workers, Mapping) else None
    direct = details.get("hook_worker_routes") if details is not None else None
    if not isinstance(routes, Mapping) or not isinstance(direct, Mapping):
        return None
    counts: RouteCounts = {}
    sources = (("direct", cast(Mapping[object, object], direct)), ("process", cast(Mapping[object, object], routes)))
    for source, observed in sources:
        counts[source] = {route: 0 for route in sorted(_ROUTES)}
        for name, value in observed.items():
            if not isinstance(name, str) or name not in _ROUTES or type(value) is not int or value < 0:
                return None
            counts[source][name] = value
    return counts


def measured_route_counts(before: RouteCounts, after_details: Mapping[str, object] | None) -> dict[str, int] | None:
    """Reject missing/reset counters instead of manufacturing an empty native proof."""

    after = read_route_counts(after_details)
    if after is None or frozenset(before) != _SOURCES:
        return None
    result = {name: 0 for name in sorted(_ROUTES)}
    for source in _SOURCES:
        if frozenset(before[source]) != _ROUTES:
            return None
        for name in _ROUTES:
            baseline, final = before[source][name], after[source][name]
            if type(baseline) is not int or baseline < 0 or final < baseline:
                return None
            result[name] += final - baseline
    return result


def native_routes_passed(routes: Mapping[str, int] | None, *, requests: int) -> bool:
    """Allow native retries, but require every measured route to remain resident."""

    return (
        requests > 0
        and routes is not None
        and frozenset(routes) == _ROUTES
        and all(type(value) is int and value >= 0 for value in routes.values())
        and routes["native_resident"] >= requests
        and all(value == 0 for name, value in routes.items() if name != "native_resident")
    )
