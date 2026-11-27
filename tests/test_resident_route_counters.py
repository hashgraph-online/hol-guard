from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.resident_evidence_drain import ResidentEvidenceDrain, _decode_batch
from codex_plugin_scanner.guard.resident_route_counters import (
    ResidentRouteCounterSnapshot,
    RouteCounterLog,
    bind_route_counter_sink,
    decode_route_counters,
)

EPOCH = "1f-2e-0"
RESIDENT = {"by_harness": {"codex": {"answer": 3, "direct_lane_workspace_unknown": 1}}}
LOGGED = ("hook_direct_counters", {"epoch": EPOCH, "resident": RESIDENT["by_harness"]})


class _Clock:
    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now


@dataclass
class _Sink:
    lines: list[tuple[str, dict[str, object]]] = field(default_factory=list)

    def record(self, event: str, *, detail: str | None = None) -> bool:
        self.lines.append((event, json.loads(detail or "null")))
        return True


@dataclass
class _Host:
    guard_home: Path
    hook_counters: RouteCounterLog
    store: object = field(default_factory=object)
    activity_writer: object = field(default_factory=object)
    policy_snapshot_publisher: object = field(default_factory=object)

    def _record_post_tool_activity(self, *, harness: str, event: str, payload: Mapping[str, object]) -> None:
        raise AssertionError((harness, event, payload))


def _page(*, counters: object | None = None) -> bytes:
    page: dict[str, object] = {
        "schema": "guard-hook-direct-evidence-batch.v1",
        "epoch": EPOCH,
        "record_count": 0,
        "pages": 1,
        "more": False,
        "failed": False,
    }
    if counters is not None:
        page["counters"] = counters
    return json.dumps(page).encode()


def _log(clock: _Clock, sink: _Sink) -> RouteCounterLog:
    log = RouteCounterLog(interval_seconds=300.0, clock=clock)
    log.bind_sink(sink.record)
    return log


def test_malformed_resident_counters_are_ignored() -> None:
    assert decode_route_counters(RESIDENT) == RESIDENT["by_harness"]
    assert decode_route_counters({"by_harness": {}}) == {}
    for malformed in (
        None,
        [],
        {},
        {"by_harness": []},
        {"by_harness": {"gemini": {"answer": 1}}},
        {"by_harness": {"codex": {"Answer": 1}}},
        {"by_harness": {"codex": {"answer": -1}}},
        {"by_harness": {"codex": {"answer": True}}},
        {"by_harness": {"codex": {"answer": "1"}}},
        {"by_harness": {"codex": {f"code_{index}": 1 for index in range(65)}}},
    ):
        assert decode_route_counters(malformed) is None, malformed


def test_the_log_is_change_only_and_rate_limited() -> None:
    clock, sink = _Clock(), _Sink()
    log = _log(clock, sink)
    assert not log.maybe_log()
    log.observe_page(EPOCH, RESIDENT)
    assert log.maybe_log()
    assert sink.lines == [LOGGED]
    log.observe_page(EPOCH, {"by_harness": {"codex": {"answer": 4}}})
    clock.now += 299.0
    assert not log.maybe_log()
    clock.now += 1.0
    assert log.maybe_log()
    clock.now += 300.0
    assert not log.maybe_log()
    assert len(sink.lines) == 2
    assert sink.lines[-1][1]["resident"] == {"codex": {"answer": 4}}


def test_a_failed_delivery_is_retried_after_the_interval() -> None:
    clock, sink = _Clock(), _Sink()
    failing = {"on": True}

    def flaky(event: str, *, detail: str) -> None:
        if failing["on"]:
            raise OSError("diagnostics unavailable")
        sink.record(event, detail=detail)

    log = RouteCounterLog(clock=clock)
    log.bind_sink(flaky)
    log.observe_page(EPOCH, RESIDENT)
    with pytest.raises(OSError):
        log.maybe_log()
    failing["on"] = False
    assert not log.maybe_log()
    clock.now += 300.0
    assert log.maybe_log()
    assert sink.lines == [LOGGED]


def test_a_dropped_line_is_retried_after_the_interval() -> None:
    clock, sink = _Clock(), _Sink()
    accepting = {"on": False}

    def queue(event: str, *, detail: str) -> bool:
        # `DaemonDiagnostics.record` returns False when its queue drops a line.
        return accepting["on"] and sink.record(event, detail=detail)

    log = RouteCounterLog(clock=clock)
    log.bind_sink(queue)
    log.observe_page(EPOCH, RESIDENT)
    assert not log.maybe_log()
    accepting["on"] = True
    assert not log.maybe_log()
    clock.now += 300.0
    assert log.maybe_log()
    assert sink.lines == [LOGGED]


def test_a_drain_without_a_transport_logs_the_counts_it_holds(tmp_path: Path) -> None:
    clock, sink = _Clock(), _Sink()
    host = _Host(tmp_path, _log(clock, sink))
    host.hook_counters.observe_page(EPOCH, RESIDENT)
    drain = ResidentEvidenceDrain(host, transport=lambda: None)

    assert drain.drain_once() is False
    assert sink.lines == [LOGGED]


def test_a_new_page_feeds_the_log_through_the_drain(tmp_path: Path) -> None:
    clock, sink = _Clock(), _Sink()
    host = _Host(tmp_path, _log(clock, sink))
    drain = ResidentEvidenceDrain(host, transport=lambda: (tmp_path, lambda **_: _page(counters=RESIDENT)))

    assert drain.drain_once() is False
    assert drain.failures == 0
    assert sink.lines == [LOGGED]


def test_a_new_daemon_drains_an_old_resident_page(tmp_path: Path) -> None:
    clock, sink = _Clock(), _Sink()
    host = _Host(tmp_path, _log(clock, sink))
    drain = ResidentEvidenceDrain(host, transport=lambda: (tmp_path, lambda **_: _page()))

    assert drain.drain_once() is False
    assert drain.failures == 0
    assert sink.lines == []


def test_the_page_counts_are_independent_of_optional_counters() -> None:
    assert _decode_batch(_page(counters=RESIDENT)) == _decode_batch(_page()) == (1, 0, False, False)
    log = RouteCounterLog()
    assert _decode_batch(_page(counters={"by_harness": "bad"}), log) == (1, 0, False, False)
    assert log.snapshot()["resident"] == {}


@pytest.mark.parametrize("diagnostics", [None, object()])
def test_a_counter_log_without_diagnostics_stays_silent(diagnostics: object) -> None:
    log = RouteCounterLog()
    bind_route_counter_sink(type("Worker", (), {"hook_counters": log})(), diagnostics)
    log.observe_page(EPOCH, RESIDENT)
    assert not log.maybe_log()


def test_a_counter_log_binds_the_daemon_diagnostics() -> None:
    clock, sink = _Clock(), _Sink()
    log = RouteCounterLog(clock=clock)
    bind_route_counter_sink(type("Worker", (), {"hook_counters": log})(), sink)
    log.observe_page(EPOCH, RESIDENT)
    assert log.maybe_log()
    assert sink.lines == [LOGGED]


def test_resident_snapshot_preserves_native_counters_for_route_readers() -> None:
    snapshot = ResidentRouteCounterSnapshot()
    snapshot.observe_page(EPOCH, RESIDENT)
    assert snapshot.snapshot() == {"epoch": EPOCH, "resident": RESIDENT["by_harness"]}
