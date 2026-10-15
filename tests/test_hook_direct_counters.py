from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import hook_direct_evidence_drain
from codex_plugin_scanner.guard.daemon.hook_direct_counters import (
    HARNESS_SLOTS,
    HookCounterLog,
    bind_hook_counter_sink,
    decode_resident_counters,
    harness_slot,
    note_hook_received,
)
from codex_plugin_scanner.guard.daemon.hook_direct_evidence_drain import DirectHookEvidenceDrain, _decode_page

EPOCH = "1f-2e-0"
RESIDENT = {"by_harness": {"codex": {"answer": 3, "direct_lane_workspace_unknown": 1}}}


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
    hook_counters: HookCounterLog
    store: object = field(default_factory=object)
    activity_writer: object = field(default_factory=object)
    policy_snapshot_publisher: object = field(default_factory=object)

    def _record_post_tool_activity(self, *, harness: str, payload: Mapping[str, object], succeeded: bool) -> None:
        raise AssertionError((harness, payload, succeeded))


def _page(*, counters: object | None = None) -> bytes:
    page: dict[str, object] = {
        "schema": "guard-hook-direct-evidence.v1",
        "epoch": EPOCH,
        "records": [],
        "remaining": 0,
        "through": None,
    }
    if counters is not None:
        page["counters"] = counters
    return json.dumps(page).encode()


def _log(clock: _Clock, sink: _Sink) -> HookCounterLog:
    log = HookCounterLog(interval_seconds=300.0, clock=clock)
    log.bind_sink(sink.record)
    return log


def test_harness_slots_match_the_direct_harnesses() -> None:
    direct = hook_direct_evidence_drain._DIRECT_HARNESSES  # pyright: ignore[reportPrivateUsage]
    assert frozenset(HARNESS_SLOTS[:-1]) == direct
    assert len(set(HARNESS_SLOTS)) == len(HARNESS_SLOTS)
    for name in HARNESS_SLOTS:
        assert harness_slot(name) == name
    for name in ("", "gemini", "Codex", "/usr/bin/codex", None, 7):
        assert harness_slot(name) == "other"


def test_the_daemon_counts_received_hooks_by_slot_only() -> None:
    log = HookCounterLog()
    worker = type("Worker", (), {"hook_counters": log})()
    for harness in ("codex", "codex", "/home/user/bin/tool --flag", "grok"):
        note_hook_received(worker, harness)
    note_hook_received(None, "codex")
    assert log.snapshot() == {"epoch": None, "resident": {}, "received": {"codex": 2, "grok": 1, "other": 1}}


def test_malformed_resident_counters_are_ignored() -> None:
    assert decode_resident_counters(RESIDENT) == RESIDENT["by_harness"]
    assert decode_resident_counters({"by_harness": {}}) == {}
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
        assert decode_resident_counters(malformed) is None, malformed


def test_the_log_is_change_only_and_rate_limited() -> None:
    clock, sink = _Clock(), _Sink()
    log = _log(clock, sink)
    assert not log.maybe_log()
    log.note_received("codex")
    assert log.maybe_log()
    assert sink.lines == [("hook_direct_counters", {"epoch": None, "resident": {}, "received": {"codex": 1}})]
    log.note_received("codex")
    clock.now += 299.0
    assert not log.maybe_log()
    clock.now += 1.0
    assert log.maybe_log()
    clock.now += 300.0
    assert not log.maybe_log()
    assert len(sink.lines) == 2
    assert sink.lines[-1][1]["received"] == {"codex": 2}


def test_a_failed_delivery_is_retried_after_the_interval() -> None:
    clock, sink = _Clock(), _Sink()
    failing = {"on": True}

    def flaky(event: str, *, detail: str) -> None:
        if failing["on"]:
            raise OSError("diagnostics unavailable")
        sink.record(event, detail=detail)

    log = HookCounterLog(clock=clock)
    log.bind_sink(flaky)
    log.note_received("codex")
    with pytest.raises(OSError):
        log.maybe_log()
    failing["on"] = False
    assert not log.maybe_log()
    clock.now += 300.0
    assert log.maybe_log()
    assert sink.lines == [("hook_direct_counters", {"epoch": None, "resident": {}, "received": {"codex": 1}})]


def test_a_dropped_line_is_retried_after_the_interval() -> None:
    clock, sink = _Clock(), _Sink()
    accepting = {"on": False}

    def queue(event: str, *, detail: str) -> bool:
        # `DaemonDiagnostics.record` returns False when its queue drops a line.
        return accepting["on"] and sink.record(event, detail=detail)

    log = HookCounterLog(clock=clock)
    log.bind_sink(queue)
    log.note_received("codex")
    assert not log.maybe_log()
    accepting["on"] = True
    assert not log.maybe_log()
    clock.now += 300.0
    assert log.maybe_log()
    assert sink.lines == [("hook_direct_counters", {"epoch": None, "resident": {}, "received": {"codex": 1}})]


def test_receipts_are_logged_without_a_drain_transport(tmp_path: Path) -> None:
    clock, sink = _Clock(), _Sink()
    host = _Host(tmp_path, _log(clock, sink))
    host.hook_counters.note_received("codex")
    drain = DirectHookEvidenceDrain(host, transport=lambda: None)

    assert drain.drain_once() is False
    assert sink.lines == [("hook_direct_counters", {"epoch": None, "resident": {}, "received": {"codex": 1}})]


def test_a_new_page_feeds_the_log_through_the_drain(tmp_path: Path) -> None:
    clock, sink = _Clock(), _Sink()
    host = _Host(tmp_path, _log(clock, sink))
    host.hook_counters.note_received("codex")
    drain = DirectHookEvidenceDrain(host, transport=lambda: (tmp_path, lambda **_: _page(counters=RESIDENT)))

    assert drain.drain_once() is False
    assert drain.failures == 0
    assert sink.lines == [
        (
            "hook_direct_counters",
            {"epoch": EPOCH, "resident": RESIDENT["by_harness"], "received": {"codex": 1}},
        )
    ]


def test_a_new_daemon_drains_an_old_resident_page(tmp_path: Path) -> None:
    clock, sink = _Clock(), _Sink()
    host = _Host(tmp_path, _log(clock, sink))
    host.hook_counters.note_received("cursor")
    drain = DirectHookEvidenceDrain(host, transport=lambda: (tmp_path, lambda **_: _page()))

    assert drain.drain_once() is False
    assert drain.failures == 0
    assert sink.lines == [("hook_direct_counters", {"epoch": None, "resident": {}, "received": {"cursor": 1}})]


def test_an_old_shaped_decoder_reads_a_new_page_unchanged() -> None:
    # The decoder before counters took only the page bytes and read five keys.
    assert _decode_page(_page(counters=RESIDENT)) == _decode_page(_page()) == ([], 0, None)
    log = HookCounterLog()
    assert _decode_page(_page(counters={"by_harness": "bad"}), log) == ([], 0, None)
    assert log.snapshot()["resident"] == {}


@pytest.mark.parametrize("diagnostics", [None, object()])
def test_a_counter_log_without_diagnostics_stays_silent(diagnostics: object) -> None:
    log = HookCounterLog()
    bind_hook_counter_sink(type("Worker", (), {"hook_counters": log})(), diagnostics)
    log.note_received("codex")
    assert not log.maybe_log()


def test_a_counter_log_binds_the_daemon_diagnostics() -> None:
    clock, sink = _Clock(), _Sink()
    log = HookCounterLog(clock=clock)
    bind_hook_counter_sink(type("Worker", (), {"hook_counters": log})(), sink)
    log.note_received("pi")
    assert log.maybe_log()
    assert sink.lines[0][1]["received"] == {"pi": 1}
