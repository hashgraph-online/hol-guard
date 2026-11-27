"""A case's Guard answers must come from the native resident, on either lane."""

from __future__ import annotations

from typing import Any

import pytest

from ci.gauntlet.native_routes import (
    RECEIPT_ONLY_FIELD,
    SinkReceiptTally,
    await_native_routes,
    native_route_error,
    native_route_proof_error,
    native_sink_calls,
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


_UNRECONCILED = "native route counts do not reconcile with observed Guard responses"
_NATIVE_WRAPPER = (
    "'/candidate/hol-guard-runtime' 'contained-workspace-sink' '--harness' 'omp' '--guard-home' '/g'"
    " '--workspace' '/w' '--request-file' '/r' '--request-sha256' '" + "0" * 64 + "' '--home' '/h'"
)
_LAUNCHER_WRAPPER = "'/candidate/.venv/bin/hol-guard' 'execute-contained-test' '--guard-home' '/g'"


def test_a_native_sink_runs_receipt_only_questions_come_out_one_for_one() -> None:
    # The scratch-log run: three observed hook answers, and four daemon routes
    # for the receipt-only questions the runtime sink asked before it ran.
    routes = {"native_resident": 7}
    one = frozenset({"a"})
    assert native_route_error(routes, 0, 3) == _UNRECONCILED
    assert native_route_error(routes, 0, 3, {"native_resident": 4}, one, {"a": 4}) is None
    # One receipt route too many or too few is still a mismatch.
    assert native_route_error(routes, 0, 3, {"native_resident": 3}, one, {"a": 3}) == _UNRECONCILED
    assert native_route_error(routes, 0, 3, {"native_resident": 5}, one, {"a": 5}) == _UNRECONCILED


def test_receipt_only_routes_need_a_bound_native_sink_run() -> None:
    assert native_route_error({"native_resident": 7}, 0, 3, {"native_resident": 4}, frozenset(), {"a": 4}) == (
        "receipt-only routes have no bound native sink run"
    )
    assert native_route_error({"native_resident": 3}, 0, 3, {}, frozenset({"a"}), {}) == (
        "a bound native sink run has no receipt-only route"
    )


def test_each_bound_native_sink_run_needs_its_own_receipts() -> None:
    # Two bound sink runs: all four receipt routes from one call cannot cover
    # the other call, even though the totals reconcile.
    routes, both = {"native_resident": 7}, frozenset({"a", "b"})
    assert native_route_error(routes, 0, 3, {"native_resident": 4}, both, {"a": 2, "b": 2}) is None
    assert native_route_error(routes, 0, 3, {"native_resident": 4}, both, {"a": 4}) == (
        "a bound native sink run has no receipt-only route"
    )
    # Receipts from a call that never ran through the sink are not covered either.
    assert native_route_error(routes, 0, 3, {"native_resident": 4}, frozenset({"a"}), {"a": 2, "z": 2}) == (
        "receipt-only routes have no bound native sink run"
    )
    # A receipt-only payload with no call identity is tallied under "".
    assert native_route_error(routes, 0, 3, {"native_resident": 4}, frozenset({"a"}), {"a": 3, "": 1}) == (
        "sink receipt call counts are malformed"
    )
    # The per-call tally has to account for every receipt route.
    assert native_route_error(routes, 0, 3, {"native_resident": 4}, frozenset({"a"}), {"a": 3}) == (
        "sink receipt routes do not match the calls that asked"
    )
    assert native_route_error(routes, 0, 3, {"native_resident": 4}, frozenset({"a"}), None) == (
        "sink receipt routes do not match the calls that asked"
    )
    for malformed in (["a"], {"a": 0}, {"a": "2"}, {1: 4}):
        assert native_route_error(routes, 0, 3, {"native_resident": 4}, frozenset({"a"}), malformed) == (
            "sink receipt call counts are malformed"
        )


def test_receipt_only_routes_cannot_hide_answers_or_leave_the_native_route() -> None:
    one = frozenset({"a"})
    assert native_route_error({"native_resident": 3}, 0, 3, {"native_resident": 4}, one, {"a": 4}) == (
        "sink receipt routes exceed the daemon's route counts"
    )
    assert native_route_error({"native_resident": 4}, 0, 3, {"native_resident": "1"}, one, {"a": 1}) == (
        "sink receipt route counts are malformed"
    )
    assert native_route_error({"native_resident": 4}, 0, 3, ["native_resident"], one, {"a": 1}) == (
        "sink receipt route counts are malformed"
    )
    # A sink question the daemon failed safe on is still an off-route answer.
    assert (
        native_route_error({"native_resident": 3, "native_fail_safe": 1}, 0, 3, {"native_fail_safe": 1}, one, {"a": 1})
        == "Guard answered outside the native resident route"
    )
    # Taking every route out as a sink question leaves no proof of a hook answer.
    assert native_route_proof_error({"native_resident": 2}, 0, {"native_resident": 2}) == (
        "native Guard enforcement route was not proven"
    )


def test_only_bound_calls_through_the_runtime_sink_count() -> None:
    calls = [
        {"id": "a", "args": {"command": _NATIVE_WRAPPER}},
        {"id": "b", "args": {"command": _LAUNCHER_WRAPPER}},
        {"id": "c", "args": {"command": _NATIVE_WRAPPER}},
        {"id": "d", "args": {"command": "'unterminated"}},
    ]
    assert native_sink_calls(calls, {"a": {}, "b": {}, "d": {}}) == frozenset({"a"})
    assert native_sink_calls(calls, frozenset({"a", "c"})) == frozenset({"a", "c"})
    assert native_sink_calls(calls, {}) == frozenset()


class _Recorder:
    def __init__(self) -> None:
        self.routes: dict[str, int] = {}

    def record_route(self, route: str) -> None:
        self.routes[route] = self.routes.get(route, 0) + 1

    def snapshot(self) -> dict[str, Any]:
        return {"routes": dict(self.routes)}


class _HookWorker:
    def __init__(self) -> None:
        self.metrics = _Recorder()
        self.hook_counters = _Snapshot(_counters(0))

    def review_http_payload(self, *, payload: dict[str, object], route: str = "native_resident") -> dict[str, object]:
        self.metrics.record_route(route)
        return {"decision": "allow"}


def test_the_tally_counts_only_routes_recorded_for_a_receipt_only_payload() -> None:
    worker = _HookWorker()
    tally = SinkReceiptTally(worker)
    worker.review_http_payload(payload={"hook_event_name": "PreToolUse", "tool_call_id": "a"})
    worker.review_http_payload(payload={"tool_call_id": "a", RECEIPT_ONLY_FIELD: True})
    worker.review_http_payload(payload={"tool_call_id": "b", RECEIPT_ONLY_FIELD: "true"})
    worker.review_http_payload(payload={"tool_call_id": "b", RECEIPT_ONLY_FIELD: True}, route="native_fail_safe")
    worker.review_http_payload(payload={RECEIPT_ONLY_FIELD: True})
    worker.metrics.record_route("native_resident")
    assert worker.metrics.routes == {"native_resident": 5, "native_fail_safe": 1}
    assert tally.snapshot() == {
        "routes": {"native_resident": 2, "native_fail_safe": 1},
        "calls": {"a": 1, "b": 1, "": 1},
    }
    routes, direct, tallied = await_native_routes(worker, 3, timeout_seconds=0.0, tally=tally)
    assert (routes, direct, tallied) == (worker.metrics.routes, 0, tally.snapshot())
