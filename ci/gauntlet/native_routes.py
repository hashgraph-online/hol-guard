"""Reconcile the Guard answers a case observed with the native routes that made them.

An installed Pi-family extension answers each hook through the native runtime's
``pi-hook-bridge``. A live resident answers in its own process whatever it can
take, and the bridge posts the rest to the daemon, so one case's answers are
split between the daemon's route metrics and the resident's direct-answer
counters. Both are the native resident route. Anything the daemon routed
elsewhere, and any answer neither source accounts for, is not.

An observed case carries the observer's transition probe, which only the daemon
can answer, so the direct-answer term is zero for every case the Gauntlet runs
today. It stays in the reconciliation because the counters are read from the
live resident either way: a non-zero or malformed reading must reach the judge
rather than be assumed absent.
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from typing import Any

# The harness name the Oh My Pi extension and its bridge config carry.
OMP_HARNESS = "omp"
# How long the resident's counters may take to reach the daemon after a case.
_DRAIN_SECONDS = 10.0
_DRAIN_POLL = 0.02


def _count(value: object) -> int | None:
    """A route or answer count, or ``None`` when it is not one."""

    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _native_answers(routes: object, resident_direct: object) -> int | str:
    """Hooks the native resident answered on either lane, or why they do not count."""

    if not isinstance(routes, Mapping):
        return "native route counts are missing"
    daemon = 0
    for name, value in routes.items():
        count = _count(value)
        if count is None:
            return "native route counts are malformed"
        if name != "native_resident":
            if count:
                return "Guard answered outside the native resident route"
            continue
        daemon = count
    direct = _count(resident_direct)
    if direct is None:
        return "resident direct answer counts are malformed"
    return daemon + direct


def native_route_proof_error(routes: object, resident_direct: object) -> str | None:
    """Why the native resident is not proven to have answered this case, or ``None``."""

    answers = _native_answers(routes, resident_direct)
    if isinstance(answers, str):
        return answers
    return None if answers > 0 else "native Guard enforcement route was not proven"


def native_route_error(routes: object, resident_direct: object, observed: int) -> str | None:
    """Why the observed answers do not reconcile with the native routes, or ``None``."""

    if proof_error := native_route_proof_error(routes, resident_direct):
        return proof_error
    answers = _native_answers(routes, resident_direct)
    if answers != observed:
        return "native route counts do not reconcile with observed Guard responses"
    return None


def resident_direct_answers(worker: Any, harness: str = OMP_HARNESS) -> int:
    """Hooks a live resident answered for ``harness`` without the daemon deciding."""

    snapshot = getattr(getattr(worker, "hook_counters", None), "snapshot", None)
    counters = snapshot() if callable(snapshot) else None
    resident = counters.get("resident") if isinstance(counters, Mapping) else None
    answers = resident.get(harness) if isinstance(resident, Mapping) else None
    if not isinstance(answers, Mapping) or "answer" not in answers:
        return 0
    count = _count(answers.get("answer"))
    # A present but unusable value must stay visible to the route judge.
    # Coercing it to zero lets a daemon count that matches the observations
    # pass while the resident evidence is malformed.
    if count is None:
        return -1
    return count


def await_native_routes(worker: Any, observed: int, *, timeout_seconds: float = _DRAIN_SECONDS) -> tuple[Any, int]:
    """The case's route metrics and resident direct answers, once they reconcile.

    The resident reports its direct answers to the daemon on its own schedule,
    so a reading taken the moment the harness exits can still be short. Reading
    until the counts account for every observation keeps that lag out of the
    judge; an unreconcilable case returns its last reading for the judge to
    report.
    """

    deadline = time.monotonic() + timeout_seconds
    while True:
        routes = worker.metrics.snapshot().get("routes", {})
        direct = resident_direct_answers(worker)
        answers = _native_answers(routes, direct)
        # Only a count still short of the observations can grow; anything else
        # is as final as it will get, and the judge reports it.
        if isinstance(answers, str) or answers >= observed or time.monotonic() >= deadline:
            return routes, direct
        time.sleep(_DRAIN_POLL)
