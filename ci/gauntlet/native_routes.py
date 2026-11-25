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

The runtime's contained-workspace sink asks Guard once more, receipt-only,
before it runs a call the hook routed to it. The daemon answers that question
on the same route as a hook, but no harness hook observed it, so the case
records those routes apart (``SinkReceiptTally``) and the judge takes them out
one for one, only when the case bound a native sink run.
"""

from __future__ import annotations

import shlex
import threading
import time
from collections.abc import Collection, Mapping
from typing import Any

# The harness name the Oh My Pi extension and its bridge config carry.
OMP_HARNESS = "omp"
# How long the resident's counters may take to reach the daemon after a case.
_DRAIN_SECONDS = 10.0
_DRAIN_POLL = 0.02
# The field the contained-workspace sink stamps on its receipt-only question.
RECEIPT_ONLY_FIELD = "guard_containment_receipt_only"
# The runtime subcommand an Oh My Pi containment rewrite runs.
NATIVE_SINK = "contained-workspace-sink"


def _count(value: object) -> int | None:
    """A route or answer count, or ``None`` when it is not one."""

    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _sink_receipts(routes: Mapping[str, Any], receipts: object) -> dict[str, int] | str:
    """The routes the daemon recorded for sink receipt-only questions, or why they do not count."""

    if receipts is None:
        return {}
    if not isinstance(receipts, Mapping):
        return "sink receipt route counts are malformed"
    counted: dict[str, int] = {}
    for name, value in receipts.items():
        count = _count(value)
        if count is None or not isinstance(name, str):
            return "sink receipt route counts are malformed"
        recorded = _count(routes.get(name, 0))
        if recorded is None or count > recorded:
            return "sink receipt routes exceed the daemon's route counts"
        counted[name] = count
    return counted


def _native_answers(routes: object, resident_direct: object, receipts: object = None) -> int | str:
    """Hooks the native resident answered on either lane, or why they do not count.

    Routes the daemon recorded for a sink's receipt-only question are not hook
    answers and are taken out; one recorded anywhere but the native resident
    still fails the case like any other off-route answer.
    """

    if not isinstance(routes, Mapping):
        return "native route counts are missing"
    sink = _sink_receipts(routes, receipts)
    if isinstance(sink, str):
        return sink
    daemon = 0
    for name, value in routes.items():
        count = _count(value)
        if count is None:
            return "native route counts are malformed"
        if name != "native_resident":
            if count:
                return "Guard answered outside the native resident route"
            continue
        daemon = count - sink.get(name, 0)
    direct = _count(resident_direct)
    if direct is None:
        return "resident direct answer counts are malformed"
    return daemon + direct


def native_route_proof_error(routes: object, resident_direct: object, receipts: object = None) -> str | None:
    """Why the native resident is not proven to have answered this case, or ``None``."""

    answers = _native_answers(routes, resident_direct, receipts)
    if isinstance(answers, str):
        return answers
    return None if answers > 0 else "native Guard enforcement route was not proven"


def _receipt_calls(value: object) -> dict[str, int] | str:
    """Receipt-only routes by the tool call whose sink asked, or why they do not count."""

    if value is None:
        return {}
    if not isinstance(value, Mapping):
        return "sink receipt call counts are malformed"
    counted: dict[str, int] = {}
    for call_id, count in value.items():
        number = _count(count)
        if not isinstance(call_id, str) or not call_id or number is None or number == 0:
            return "sink receipt call counts are malformed"
        counted[call_id] = number
    return counted


def native_route_error(
    routes: object,
    resident_direct: object,
    observed: int,
    receipts: object = None,
    sink_calls: Collection[str] = (),
    receipt_calls: object = None,
) -> str | None:
    """Why the observed answers do not reconcile with the native routes, or ``None``.

    ``receipts`` are the case's sink receipt-only routes, ``receipt_calls`` the
    same routes by the tool call that asked, and ``sink_calls`` the bound
    contained calls that ran through the runtime's sink. Every bound sink call
    asks at least once, and every receipt-only route belongs to one of them.
    """

    if proof_error := native_route_proof_error(routes, resident_direct, receipts):
        return proof_error
    sink = _sink_receipts(routes, receipts) if isinstance(routes, Mapping) else {}
    by_call = _receipt_calls(receipt_calls)
    if isinstance(by_call, str):
        return by_call
    if not isinstance(sink, dict) or sum(sink.values()) != sum(by_call.values()):
        return "sink receipt routes do not match the calls that asked"
    if set(by_call) - set(sink_calls):
        return "receipt-only routes have no bound native sink run"
    if set(sink_calls) - set(by_call):
        return "a bound native sink run has no receipt-only route"
    answers = _native_answers(routes, resident_direct, receipts)
    if answers != observed:
        return "native route counts do not reconcile with observed Guard responses"
    return None


def native_sink_calls(calls: list[dict[str, Any]], contained: Mapping[str, Any] | frozenset[str]) -> frozenset[str]:
    """The bound contained calls the host ran through the runtime's native sink.

    ``calls`` are the host calls before ``effective_calls`` swaps in the reviewed
    input; ``contained_core`` has already bound each wrapper's exact argv.
    """

    native: set[str] = set()
    for call in calls:
        args = call.get("args")
        command = args.get("command") if isinstance(args, dict) else None
        call_id = call.get("id")
        if call_id not in contained or not isinstance(call_id, str) or not isinstance(command, str):
            continue
        try:
            argv = shlex.split(command)
        except ValueError:
            continue
        if len(argv) > 1 and argv[1] == NATIVE_SINK:
            native.add(call_id)
    return frozenset(native)


class SinkReceiptTally:
    """Daemon routes recorded while answering a contained sink's receipt-only question.

    Wraps this worker's own hook entry point and route recorder, so a route is
    tallied only when the payload the daemon reviewed carried the sink's
    receipt-only field, under the tool call that payload names. The route is
    recorded before it is tallied: a tally read before the route counts can
    never exceed them.
    """

    def __init__(self, worker: Any) -> None:
        self._local = threading.local()
        self._lock = threading.Lock()
        self._routes: dict[str, int] = {}
        self._calls: dict[str, int] = {}
        review = worker.review_http_payload
        record = worker.metrics.record_route

        def review_http_payload(*args: Any, **kwargs: Any) -> Any:
            payload = kwargs.get("payload")
            prior = getattr(self._local, "receipt_call", None)
            asked = isinstance(payload, Mapping) and payload.get(RECEIPT_ONLY_FIELD) is True
            call_id = payload.get("tool_call_id") if asked else None
            # A receipt-only payload with no call identity is tallied under ""
            # so the judge sees it and cannot bind it to any call.
            self._local.receipt_call = (call_id if isinstance(call_id, str) else "") if asked else None
            try:
                return review(*args, **kwargs)
            finally:
                self._local.receipt_call = prior

        def record_route(route: str) -> None:
            record(route)
            call_id = getattr(self._local, "receipt_call", None)
            if call_id is not None:
                with self._lock:
                    self._routes[route] = self._routes.get(route, 0) + 1
                    self._calls[call_id] = self._calls.get(call_id, 0) + 1

        worker.review_http_payload = review_http_payload
        worker.metrics.record_route = record_route

    def snapshot(self) -> dict[str, dict[str, int]]:
        """The tallied routes and, for the same routes, the calls that asked."""

        with self._lock:
            return {"routes": dict(self._routes), "calls": dict(self._calls)}


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


def await_native_routes(
    worker: Any,
    observed: int,
    *,
    timeout_seconds: float = _DRAIN_SECONDS,
    tally: SinkReceiptTally | None = None,
) -> tuple[Any, int] | tuple[Any, int, dict[str, dict[str, int]]]:
    """The case's route metrics and resident direct answers, once they reconcile.

    The resident reports its direct answers to the daemon on its own schedule,
    so a reading taken the moment the harness exits can still be short. Reading
    until the counts account for every observation keeps that lag out of the
    judge; an unreconcilable case returns its last reading for the judge to
    report. With a ``tally`` the sink's receipt-only routes are returned too and
    left out of the count being waited for.
    """

    deadline = time.monotonic() + timeout_seconds
    while True:
        tallied = tally.snapshot() if tally is not None else None
        routes = worker.metrics.snapshot().get("routes", {})
        direct = resident_direct_answers(worker)
        answers = _native_answers(routes, direct, tallied["routes"] if tallied is not None else None)
        # Only a count still short of the observations can grow; anything else
        # is as final as it will get, and the judge reports it.
        if isinstance(answers, str) or answers >= observed or time.monotonic() >= deadline:
            return (routes, direct) if tallied is None else (routes, direct, tallied)
        time.sleep(_DRAIN_POLL)
