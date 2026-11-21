"""A case's Guard answers must come from the native resident, on either lane."""

from __future__ import annotations

from typing import Any

import pytest

from ci.gauntlet.native_routes import (
    await_native_routes,
    native_route_error,
    native_route_proof_error,
    resident_direct_answers,
)


class _Snapshot:
    def __init__(self, *readings: dict[str, Any]) -> None:
        self._readings = list(readings)
        self.reads = 0

    def snapshot(self) -> dict[str, Any]:
        self.reads += 1
        index = min(self.reads, len(self._readings)) - 1
        return self._readings[index]


class _Worker:
    def __init__(self, metrics: _Snapshot, hook_counters: _Snapshot) -> None:
        self.metrics = metrics
        self.hook_counters = hook_counters


def _counters(answered: int) -> dict[str, Any]:
    return {"epoch": "e1", "resident": {"omp": {"answer": answered, "defer": 0}}, "received": {"omp": answered}}


def test_the_daemon_and_the_resident_answer_the_same_native_route() -> None:
    # A bridged hook the resident settles itself never reaches the daemon's
    # route metrics, so a case's answers are split across both counts.
    assert native_route_error({"native_resident": 3}, 0, 3) is None
    assert native_route_error({}, 3, 3) is None
    assert native_route_error({"native_resident": 1}, 2, 3) is None


def test_answers_that_left_the_native_route_fail() -> None:
    assert native_route_error({"python_semantic": 1}, 0, 1) == "Guard answered outside the native resident route"
    assert native_route_proof_error({"native_fail_safe": 2}, 0) == "Guard answered outside the native resident route"


def test_an_unanswered_case_is_not_proof_of_native_enforcement() -> None:
    assert native_route_proof_error({}, 0) == "native Guard enforcement route was not proven"
    assert native_route_error({"native_resident": 0}, 0, 0) == "native Guard enforcement route was not proven"
    assert native_route_proof_error({"native_resident": 1}, 0) is None


def test_counts_that_miss_an_observation_do_not_reconcile() -> None:
    assert native_route_error({"native_resident": 2}, 0, 3) == (
        "native route counts do not reconcile with observed Guard responses"
    )
    assert native_route_error({"native_resident": 4}, 0, 3) == (
        "native route counts do not reconcile with observed Guard responses"
    )


@pytest.mark.parametrize(
    ("routes", "direct", "expected"),
    [
        ("routes", 0, "native route counts are missing"),
        ({"native_resident": True}, 0, "native route counts are malformed"),
        ({"native_resident": -1}, 0, "native route counts are malformed"),
        ({"native_resident": 1}, "two", "resident direct answer counts are malformed"),
    ],
)
def test_malformed_counts_are_rejected_rather_than_coerced(routes: object, direct: object, expected: str) -> None:
    assert native_route_error(routes, direct, 1) == expected


def test_the_resident_count_comes_from_this_harness_alone() -> None:
    worker = _Worker(_Snapshot({}), _Snapshot(_counters(2)))
    assert resident_direct_answers(worker) == 2
    assert resident_direct_answers(worker, "codex") == 0


def test_a_daemon_without_resident_counters_reports_no_direct_answers() -> None:
    assert resident_direct_answers(object()) == 0
    assert resident_direct_answers(_Worker(_Snapshot({}), _Snapshot({"resident": {}}))) == 0


def test_a_malformed_resident_answer_is_not_treated_as_zero() -> None:
    worker = _Worker(_Snapshot({}), _Snapshot({"resident": {"omp": {"answer": -1}}}))
    assert resident_direct_answers(worker) == -1
    assert native_route_error({"native_resident": 1}, resident_direct_answers(worker), 1) == (
        "resident direct answer counts are malformed"
    )


def test_a_late_resident_report_is_waited_for() -> None:
    # The resident reports its direct answers on the evidence drain, so the
    # first reading after a case can still be short of the hooks it answered.
    metrics = _Snapshot({"routes": {"native_resident": 1}})
    counters = _Snapshot(_counters(0), _counters(0), _counters(2))
    routes, direct = await_native_routes(_Worker(metrics, counters), 3)
    assert (routes, direct) == ({"native_resident": 1}, 2)
    assert counters.reads >= 3


def test_a_case_that_cannot_reconcile_returns_its_last_reading() -> None:
    metrics = _Snapshot({"routes": {"native_resident": 1}})
    counters = _Snapshot(_counters(0))
    routes, direct = await_native_routes(_Worker(metrics, counters), 3, timeout_seconds=0.05)
    assert (routes, direct) == ({"native_resident": 1}, 0)
    assert native_route_error(routes, direct, 3) == (
        "native route counts do not reconcile with observed Guard responses"
    )


def test_a_case_with_no_observations_is_not_waited_for() -> None:
    # Nothing can arrive for a case whose harness never reached Guard, so the
    # judge should hear "not proven" at once instead of after the whole drain.
    metrics = _Snapshot({"routes": {}})
    counters = _Snapshot(_counters(0))
    routes, direct = await_native_routes(_Worker(metrics, counters), 0, timeout_seconds=30.0)
    assert (routes, direct) == ({}, 0)
    assert counters.reads == 1
