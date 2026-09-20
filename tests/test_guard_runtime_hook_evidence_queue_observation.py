"""Queue timing controls use the real writer and an explicitly paused consumer."""

from __future__ import annotations

import gc
import itertools
import json
import sqlite3
import sys
import threading
from pathlib import Path
from typing import cast
from unittest.mock import patch

import pytest

from codex_plugin_scanner.guard.daemon import runtime_hook_evidence_writer as writer_module
from codex_plugin_scanner.guard.daemon.runtime_hook_evidence_queue_observation import EvidenceQueueObservation
from codex_plugin_scanner.guard.daemon.runtime_hook_evidence_writer import RuntimeHookEvidenceWriter
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_native_decision_receipt import _receipt


class _Clock:
    def __init__(self, *values: int) -> None:
        self.values = iter(values)
        self.calls = 0

    def __call__(self) -> int:
        self.calls += 1
        return next(self.values)


def _paused_writer(
    tmp_path: Path,
    observation: EvidenceQueueObservation | None = None,
    *,
    max_records: int = 10,
) -> RuntimeHookEvidenceWriter:
    store = GuardStore(tmp_path / "guard-home")
    # Only consumer startup is paused; admission, dequeue, journal and retry
    # controls below invoke the actual writer methods and use actual records.
    with patch.object(threading.Thread, "start") as start:
        writer = RuntimeHookEvidenceWriter(
            store=store,
            max_records=max_records,
            max_batch=10,
            batch_wait_seconds=0,
            queue_observation=observation,
        )
    start.assert_called_once_with()
    return writer


def _command(writer: RuntimeHookEvidenceWriter) -> bool:
    return writer.submit_command_activity(
        harness="pi",
        event="PostToolUse",
        payload={"command": "queue-private-command", "tool_call_id": "call_g7M8q2L5n9R4s1T6"},
        succeeded=True,
    )


def _assert_test_owns_last_record_reference(record: object) -> None:
    """Bounded CPython control for the caller's actual slots-only queue record."""
    assert sys.implementation.name == "cpython"
    assert type(record) is writer_module._CommandActivityRecord
    # Caller local, this helper's argument, and getrefcount's temporary argument.
    assert sys.getrefcount(record) == 3
    retained = [record]
    assert sys.getrefcount(record) == 4
    retained.clear()
    assert sys.getrefcount(record) == 3


def _group(observation: EvidenceQueueObservation, kind: str, origin: str) -> dict[str, object]:
    groups = cast(dict[str, dict[str, dict[str, object]]], observation.report()["groups"])
    return groups[kind][origin]


def test_disabled_observation_never_dispatches_diagnostics(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("disabled diagnostic callback ran")

    monkeypatch.setattr(RuntimeHookEvidenceWriter, "_observe_queue", forbidden)
    writer = _paused_writer(tmp_path)
    assert writer.submit_native_decision_receipt(_receipt())
    assert _command(writer)
    assert len(writer._next_batch()) == 2
    assert writer.stats()["accepted"] == 2
    assert writer.stats()["queued"] == 0
    assert writer._queue_observation is None


def test_queue_ages_separate_native_and_command_without_payloads(tmp_path: Path) -> None:
    clock = _Clock(100, 200, 500, 700)
    observation = EvidenceQueueObservation(clock_ns=clock)
    writer = _paused_writer(tmp_path, observation)
    receipt = _receipt()
    assert writer.submit_native_decision_receipt(receipt)
    assert writer.submit_native_decision_receipt(receipt)
    assert _command(writer)
    assert writer.stats()["receipt_deduped"] == 1
    assert clock.calls == 2
    assert len(writer._next_batch()) == 2
    native = _group(observation, "native_receipt", "admission")
    command = _group(observation, "command_activity", "admission")
    for group, elapsed in ((native, 400), (command, 500)):
        assert group["queued"] == group["dequeued"] == group["measured"] == 1
        assert group["total_ns"] == group["minimum_ns"] == group["maximum_ns"] == elapsed
        assert group["missing_age"] == 0
        assert sum(cast(list[int], group["histogram_counts"])) == 1
    report = observation.detach(writer)
    assert clock.calls == 4
    assert report["age_coverage_complete"] is True
    serialized = json.dumps(report)
    for private in ("queue-private-command", "call_g7M8q2L5n9R4s1T6", str(receipt["decision_id"]), str(tmp_path)):
        assert private not in serialized


def test_attach_backlog_has_unknown_age_and_detach_stops_observation(tmp_path: Path) -> None:
    clock = _Clock(100, 300, 500)
    observation = EvidenceQueueObservation(clock_ns=clock)
    writer = _paused_writer(tmp_path)
    assert writer.submit_native_decision_receipt(_receipt())
    assert observation.attach(writer)
    assert observation.attach(writer)
    assert clock.calls == 0
    assert observation.report()["windows"] == 1
    assert _command(writer)
    assert len(writer._next_batch()) == 2
    backlog = _group(observation, "native_receipt", "preexisting")
    assert backlog["dequeued"] == backlog["missing_age"] == 1
    assert backlog["measured"] == 0
    assert _group(observation, "command_activity", "admission")["total_ns"] == 200
    assert _command(writer)
    report = observation.detach(writer)
    assert report["detached_pending"] == 1
    assert report["tracked_pending"] == report["queued"] == 0
    assert report["age_coverage_complete"] is False
    assert len(writer._next_batch()) == 1
    assert observation.report() == report
    assert clock.calls == 3
    assert _command(writer)
    assert observation.attach(writer)
    assert observation.report()["windows"] == 2
    assert observation.report()["pending_unknown_age"] == 1
    assert len(writer._next_batch()) == 1
    assert _group(observation, "command_activity", "preexisting")["missing_age"] == 1
    observation.detach(writer)


def test_observer_overflow_does_not_change_writer_admission_or_fifo(tmp_path: Path) -> None:
    observation = EvidenceQueueObservation(max_pending=1, clock_ns=_Clock(10, 20, 30, 40))
    writer = _paused_writer(tmp_path, observation, max_records=3)
    first, second = _receipt(), _receipt(request_id="second")
    assert writer.submit_native_decision_receipt(first)
    assert writer.submit_native_decision_receipt(second)
    assert _command(writer)
    expected_ids = [record.record_id for record in writer._records]
    assert not _command(writer)
    assert observation.report()["overflow"] == 2
    assert observation.report()["tracked_pending"] == 1
    assert observation.report()["untracked_pending"] == 2
    assert observation.report()["capacity_covers_admission_and_inflight"] is False
    assert [record.record_id for record in writer._next_batch()] == expected_ids
    assert writer.stats()["accepted"] == 3 and writer.stats()["dropped"] == 1
    assert _group(observation, "native_receipt", "admission")["measured"] == 1
    for kind in ("native_receipt", "command_activity"):
        assert _group(observation, kind, "untracked")["missing_age"] == 1
    report = observation.detach(writer)
    assert report["tracking_complete"] is False
    assert report["queued"] == report["tracked_pending"] == 0


@pytest.mark.parametrize("failure", [ValueError("private clock error"), KeyboardInterrupt(), -1, True, 1.5])
def test_clock_faults_preserve_accepted_records_and_report_missing_age(tmp_path: Path, failure: object) -> None:
    def broken_clock() -> int:
        if isinstance(failure, BaseException):
            raise failure
        return cast(int, failure)

    observation = EvidenceQueueObservation(clock_ns=broken_clock)
    writer = _paused_writer(tmp_path, observation)
    assert writer.submit_native_decision_receipt(_receipt())
    assert len(writer._next_batch()) == 1
    report = observation.detach(writer)
    assert writer.stats()["accepted"] == 1 and writer.stats()["dropped"] == 0
    assert report["diagnostic_errors"] == 1
    assert _group(observation, "native_receipt", "admission")["missing_age"] == 1
    assert report["age_coverage_complete"] is False
    assert "private clock error" not in json.dumps(report)


def test_backward_clock_is_not_a_negative_latency_sample(tmp_path: Path) -> None:
    observation = EvidenceQueueObservation(clock_ns=_Clock(200, 100))
    writer = _paused_writer(tmp_path, observation)
    assert _command(writer)
    assert len(writer._next_batch()) == 1
    group = _group(observation, "command_activity", "admission")
    assert group["measured"] == 0 and group["missing_age"] == 1
    assert observation.detach(writer)["diagnostic_errors"] == 1


def test_retry_age_restarts_at_actual_requeue(tmp_path: Path) -> None:
    observation = EvidenceQueueObservation(clock_ns=_Clock(100, 200, 300, 500))
    writer = _paused_writer(tmp_path, observation)
    assert writer.submit_native_decision_receipt(_receipt())
    batch = writer._next_batch()
    assert writer._record_persistence_failure(batch, phase="receipt_persistence", code="sqlite_busy") == 0.05
    assert writer._next_batch() == batch
    assert _group(observation, "native_receipt", "admission")["total_ns"] == 100
    assert _group(observation, "native_receipt", "retry")["total_ns"] == 200
    assert writer.stats()["failures"] == writer.stats()["receipt_failures"] == 1
    assert writer.stats()["accepted"] == writer.stats()["receipt_accepted"] == 1
    observation.detach(writer)


def test_constructor_observes_journal_recovery_from_current_enqueue(tmp_path: Path) -> None:
    first = _paused_writer(tmp_path)
    assert first.submit_native_decision_receipt(_receipt())
    assert _command(first)
    for record in first._records:
        first._append_journal(record)
    original_journal = first._journal_path.read_bytes()
    observation = EvidenceQueueObservation(clock_ns=_Clock(100, 200, 400, 700))
    recovered = _paused_writer(tmp_path, observation)
    assert recovered.stats()["recovered"] == 2
    assert recovered._journal_path.read_bytes() == original_journal
    assert len(recovered._next_batch()) == 2
    assert _group(observation, "native_receipt", "recovery")["total_ns"] == 300
    assert _group(observation, "command_activity", "recovery")["total_ns"] == 500
    assert _group(observation, "native_receipt", "admission")["queued"] == 0
    observation.detach(recovered)


def test_failed_writer_start_detaches_observer_and_releases_recovered_records(tmp_path: Path) -> None:
    first = _paused_writer(tmp_path)
    assert _command(first)
    first._append_journal(first._records[0])
    original_journal = first._journal_path.read_bytes()
    observation = EvidenceQueueObservation(clock_ns=_Clock(100))
    failure = RuntimeError("synthetic writer startup failure")

    with patch.object(threading.Thread, "start", side_effect=failure), pytest.raises(RuntimeError) as raised:
        RuntimeHookEvidenceWriter(
            store=GuardStore(tmp_path / "guard-home"),
            queue_observation=observation,
        )

    assert raised.value is failure
    assert first._journal_path.read_bytes() == original_journal
    assert _group(observation, "command_activity", "recovery")["queued"] == 1
    report = observation.report()
    assert report["attached"] is False
    assert report["detachments"] == report["detached_pending"] == 1
    assert report["tracked_pending"] == report["queued"] == 0


def test_observer_releases_record_references_on_dequeue_and_detach(tmp_path: Path) -> None:
    observation = EvidenceQueueObservation(clock_ns=itertools.count().__next__)
    writer = _paused_writer(tmp_path, observation)
    assert _command(writer)
    record = writer._records[0]
    assert observation._pending[id(record)].record is record
    batch = writer._next_batch()
    assert batch[0] is record
    del batch
    gc.collect()
    _assert_test_owns_last_record_reference(record)
    assert _command(writer)
    record = writer._records[0]
    assert observation._pending[id(record)].record is record
    observation.detach(writer)
    assert not observation._pending
    batch = writer._next_batch()
    assert batch[0] is record
    del batch
    gc.collect()
    _assert_test_owns_last_record_reference(record)


def test_callback_failure_cannot_escape_dequeue_or_retain_records(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    observation = EvidenceQueueObservation(clock_ns=_Clock(100))
    writer = _paused_writer(tmp_path, observation)
    assert _command(writer)
    record = writer._records[0]
    assert observation._pending[id(record)].record is record

    def broken_callback(*_args: object) -> None:
        raise RuntimeError("private diagnostic callback")

    monkeypatch.setattr(observation, "_dequeued", broken_callback)
    batch = writer._next_batch()
    assert len(batch) == 1 and batch[0] is record
    del batch
    gc.collect()
    _assert_test_owns_last_record_reference(record)
    report = observation.detach(writer)
    assert report["diagnostic_errors"] == report["tracking_invalidations"] == 1
    assert report["age_coverage_complete"] is False
    assert writer.stats()["queued"] == 0 and writer.stats()["accepted"] == 1


def test_observer_refuses_a_second_writer_without_replacing_its_owner(tmp_path: Path) -> None:
    observation = EvidenceQueueObservation(clock_ns=itertools.count().__next__)
    first = _paused_writer(tmp_path / "first", observation)
    second = _paused_writer(tmp_path / "second")
    assert not observation.attach(second)
    assert first._queue_observation is observation and second._queue_observation is None
    assert observation.report()["attachment_conflicts"] == 1
    observation.detach(first)


def test_live_writer_retry_keeps_real_persistence_and_queue_units_separate(tmp_path: Path) -> None:
    attempts: list[str] = []
    persisted = threading.Event()
    observation = EvidenceQueueObservation(clock_ns=itertools.count(100, 100).__next__)

    def persist(*, store: GuardStore, receipt: object) -> bool:
        assert store.guard_home == tmp_path / "guard-home"
        assert isinstance(receipt, dict)
        attempts.append(str(receipt["decision_id"]))
        if len(attempts) == 1:
            raise sqlite3.OperationalError("transient persistence fault")
        persisted.set()
        return True

    with patch.object(writer_module, "persist_native_decision_receipt", side_effect=persist):
        writer = RuntimeHookEvidenceWriter(
            store=GuardStore(tmp_path / "guard-home"),
            batch_wait_seconds=0,
            queue_observation=observation,
        )
        try:
            assert writer.submit_native_decision_receipt(_receipt())
            assert persisted.wait(timeout=2)
        finally:
            assert writer.stop(timeout_seconds=2)
            observation.detach(writer)
    assert len(attempts) == 2 and attempts[0] == attempts[1]
    assert writer.stats()["receipt_processed"] == 1
    assert writer.stats()["receipt_failures"] == 1
    assert writer.stats()["durable_pending"] == 0
    for origin in ("admission", "retry"):
        assert _group(observation, "native_receipt", origin)["measured"] == 1
        assert _group(observation, "native_receipt", origin)["total_ns"] == 100


@pytest.mark.parametrize("detach_at_call", [1, 2])
def test_clock_detachment_never_retains_or_invents_a_queue_age(tmp_path: Path, detach_at_call: int) -> None:
    calls = 0

    def clock() -> int:
        nonlocal calls
        calls += 1
        if calls == detach_at_call:
            observation.detach(writer)
        return calls * 100

    observation = EvidenceQueueObservation(clock_ns=clock)
    writer = _paused_writer(tmp_path, observation)
    assert _command(writer)
    record = writer._records[0]
    if detach_at_call == 2:
        assert observation._pending[id(record)].record is record
    else:
        assert not observation._pending
    batch = writer._next_batch()
    assert batch[0] is record
    del batch
    gc.collect()
    _assert_test_owns_last_record_reference(record)
    report = observation.report()
    assert report["attached"] is False
    assert report["tracked_pending"] == 0
    assert report["measured"] == 0
    assert report["age_coverage_complete"] is False
    assert writer.stats()["accepted"] == 1 and writer.stats()["queued"] == 0
