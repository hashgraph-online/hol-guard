"""Keep failed persistence attempts attributable without exporting private data."""

from __future__ import annotations

import errno
import json
import sqlite3
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import runtime_hook_evidence_writer as writer_module
from codex_plugin_scanner.guard.daemon.runtime_hook_evidence_diagnostics import (
    evidence_failure_code,
    evidence_failure_snapshot,
)
from codex_plugin_scanner.guard.daemon.runtime_hook_evidence_writer import RuntimeHookEvidenceWriter
from codex_plugin_scanner.guard.sqlite_tuning import sqlite_connect_timeout_seconds
from codex_plugin_scanner.guard.store import GuardStore
from scripts.native_probe_receipts import receipt_corpus_is_complete

from .test_native_decision_receipt import _receipt


def _wait_for(predicate: Callable[[], bool]) -> None:
    deadline = time.monotonic() + 3
    while not predicate() and time.monotonic() < deadline:
        time.sleep(0.005)
    assert predicate()


def _assert_reconciled(writer: RuntimeHookEvidenceWriter) -> None:
    stats = writer.stats()
    assert sum(stats["failure_diagnostics"].values()) == stats["failures"]
    assert sum(stats["receipt_failure_diagnostics"].values()) == stats["receipt_failures"]
    assert evidence_failure_snapshot(stats["failure_diagnostics"]) == stats["failure_diagnostics"]
    assert evidence_failure_snapshot(stats["receipt_failure_diagnostics"]) == stats["receipt_failure_diagnostics"]


def test_actual_sqlite_busy_retains_failure_after_idempotent_drain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = GuardStore(tmp_path)
    timeouts: list[float] = []
    persist = store.record_native_decision_receipt

    def observed_persist(receipt):
        timeouts.append(sqlite_connect_timeout_seconds())
        return persist(receipt)

    monkeypatch.setattr(store, "record_native_decision_receipt", observed_persist)
    writer = RuntimeHookEvidenceWriter(store=store, batch_wait_seconds=0)
    blocker = sqlite3.connect(store.path, timeout=0.01)
    try:
        blocker.execute("begin immediate")
        assert writer.submit_native_decision_receipt(_receipt())
        _wait_for(lambda: writer.stats()["receipt_failures"] >= 1)
        waiting = writer.stats()
        assert waiting["receipt_processed"] == waiting["receipt_dropped"] == 0
        assert waiting["receipt_durable_pending"] == 1
        code = "sqlite_busy" if sys.version_info >= (3, 11) else "sqlite_code_unavailable"
        assert waiting["receipt_failure_diagnostics"] == {f"receipt_persistence/{code}": waiting["receipt_failures"]}
        blocker.rollback()
        _wait_for(lambda: receipt_corpus_is_complete(writer.stats(), expected=1))
    finally:
        blocker.close()
        assert writer.stop(timeout_seconds=3)
    stats = writer.stats()
    assert stats["receipt_failures"] >= 1
    assert stats["receipt_processed"] == stats["receipt_transactions"] == 1
    assert stats["receipt_durable_pending"] == stats["receipt_dropped"] == 0
    assert store.native_decision_receipt_count() == 1
    assert len(timeouts) >= 2 and set(timeouts) == {0.05}
    _assert_reconciled(writer)


@pytest.mark.parametrize("failure", ["after_commit", "single_ack", "batch_ack"])
def test_committed_receipt_retry_keeps_failure_and_never_counts_a_second_processed_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    store = GuardStore(tmp_path)
    count = 2 if failure == "batch_ack" else 1
    method = "record_native_decision_receipts" if count == 2 else "record_native_decision_receipt"
    persist = getattr(store, method)
    attempts = 0

    def once_after_commit(receipts):
        nonlocal attempts
        result = persist(receipts)
        attempts += 1
        if attempts == 1:
            if failure == "after_commit":
                raise RuntimeError("private post-commit path /private/example must not escape")
            return () if count == 2 else False
        return result

    monkeypatch.setattr(store, method, once_after_commit)
    writer = RuntimeHookEvidenceWriter(store=store, batch_wait_seconds=0)
    try:
        with writer._condition:
            for index in range(count):
                assert writer.submit_native_decision_receipt(_receipt(request_id=f"committed-{index}"))
        _wait_for(lambda: receipt_corpus_is_complete(writer.stats(), expected=count))
    finally:
        assert writer.stop(timeout_seconds=3)
    stats = writer.stats()
    code = "runtime_error" if failure == "after_commit" else "unacknowledged"
    assert stats["receipt_failure_diagnostics"] == {f"receipt_persistence/{code}": count}
    assert stats["receipt_processed"] == stats["receipt_failures"] == count
    assert stats["receipt_dropped"] == stats["receipt_durable_pending"] == 0
    assert attempts == 2 and stats["receipt_transactions"] == 1
    assert store.native_decision_receipt_count() == count
    assert "private" not in json.dumps(stats)
    _assert_reconciled(writer)


def test_append_failure_is_dropped_receipt_evidence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path)
    writer = RuntimeHookEvidenceWriter(store=store, batch_wait_seconds=0)

    def fail_append(*args, **kwargs):
        raise OSError(errno.ENOSPC, "private journal command /private/example")

    monkeypatch.setattr(writer_module, "append_journal_batch", fail_append)
    try:
        assert writer.submit_native_decision_receipt(_receipt())
        _wait_for(lambda: writer.stats()["receipt_dropped"] == 1)
    finally:
        assert writer.stop(timeout_seconds=3)
    stats = writer.stats()
    assert stats["receipt_failure_diagnostics"] == {"journal_append/os_no_space": 1}
    assert stats["receipt_failures"] == stats["receipt_dropped"] == 1
    assert stats["receipt_processed"] == stats["receipt_durable_pending"] == 0
    assert store.native_decision_receipt_count() == 0
    _assert_reconciled(writer)


def test_checkpoint_retry_is_not_a_receipt_persistence_failure(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path)
    checkpoint = writer_module.checkpoint_journal
    attempts = 0

    def fail_once(*args, **kwargs):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise OSError(errno.EROFS, "private journal /private/example")
        return checkpoint(*args, **kwargs)

    monkeypatch.setattr(writer_module, "checkpoint_journal", fail_once)
    writer = RuntimeHookEvidenceWriter(store=store, batch_wait_seconds=0)
    try:
        assert writer.submit_native_decision_receipt(_receipt())
        _wait_for(lambda: receipt_corpus_is_complete(writer.stats(), expected=1))
    finally:
        assert writer.stop(timeout_seconds=3)
    stats = writer.stats()
    assert stats["failure_diagnostics"] == {"journal_checkpoint/os_read_only": 1}
    assert stats["receipt_failure_diagnostics"] == {}
    assert stats["receipt_failures"] == stats["receipt_dropped"] == 0
    assert stats["receipt_processed"] == stats["receipt_transactions"] == 1
    assert attempts == 2 and store.native_decision_receipt_count() == 1
    _assert_reconciled(writer)


@pytest.mark.parametrize("failure", ["invalid_record", "recovery_duplicate", "recovery_capacity"])
def test_recovery_diagnostics_do_not_invent_native_receipts_for_unknown_records(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    store = GuardStore(tmp_path)
    receipt = _receipt()
    second = _receipt(request_id="second") if failure == "recovery_capacity" else receipt
    suffix = "{truncated private record" if failure == "invalid_record" else json.dumps(second)
    (tmp_path / "runtime-hook-evidence.jsonl").write_text(json.dumps(receipt) + "\n" + suffix + "\n")
    release = threading.Event()
    run = RuntimeHookEvidenceWriter._run

    def paused_run(writer: RuntimeHookEvidenceWriter) -> None:
        assert release.wait(timeout=3)
        run(writer)

    monkeypatch.setattr(RuntimeHookEvidenceWriter, "_run", paused_run)
    writer = RuntimeHookEvidenceWriter(store=store, max_records=1 if failure == "recovery_capacity" else 2)
    try:
        stats = writer.stats()
        assert stats["failure_diagnostics"] == {f"journal_recovery/{failure}": 1}
        assert stats["receipt_failure_diagnostics"] == {}
        assert stats["receipt_failures"] == stats["receipt_dropped"] == 0
        assert stats["recovered"] == 1 and stats["receipt_durable_pending"] == 1
        _assert_reconciled(writer)
    finally:
        release.set()
        assert writer.stop(timeout_seconds=3)
    if failure == "invalid_record":
        assert writer.stats()["failure_diagnostics"]["journal_checkpoint/invalid_record"] == 1
    assert store.native_decision_receipt_count() == 1
    _assert_reconciled(writer)


def test_recovery_io_error_is_global_and_snapshots_are_detached(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = GuardStore(tmp_path)

    def fail_recovery(*args, **kwargs):
        raise OSError(errno.EACCES, "private journal /private/example")

    monkeypatch.setattr(writer_module, "recover_journal_records", fail_recovery)
    writer = RuntimeHookEvidenceWriter(store=store)
    assert writer.stop(timeout_seconds=3)
    stats = writer.stats()
    assert stats["failure_diagnostics"] == {"journal_recovery/os_permission": 1}
    assert stats["receipt_failure_diagnostics"] == {}
    stats["failure_diagnostics"]["journal_recovery/os_permission"] = 999
    stats["receipt_failure_diagnostics"]["receipt_persistence/sqlite_busy"] = 999
    assert writer.stats()["failure_diagnostics"] == {"journal_recovery/os_permission": 1}
    assert writer.stats()["receipt_failure_diagnostics"] == {}
    _assert_reconciled(writer)


def test_command_activity_failure_does_not_become_a_native_receipt_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = GuardStore(tmp_path)
    writer = RuntimeHookEvidenceWriter(store=store, batch_wait_seconds=0)
    attempts = 0

    def fail_once(record):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise ValueError("private command payload")

    monkeypatch.setattr(writer, "_persist_command_activity", fail_once)
    try:
        assert writer.submit_command_activity(
            harness="pi", event="PostToolUse", payload={"command": "echo synthetic"}, succeeded=True
        )
        _wait_for(lambda: writer.stats()["processed"] == 1)
    finally:
        assert writer.stop(timeout_seconds=3)
    assert writer.stats()["failure_diagnostics"] == {"command_activity_persistence/value_error": 1}
    assert writer.stats()["receipt_failure_diagnostics"] == {}
    assert attempts == 2
    _assert_reconciled(writer)


def test_compatibility_rewrite_invalid_records_keep_global_accounting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    writer = RuntimeHookEvidenceWriter(store=GuardStore(tmp_path))
    assert writer.stop(timeout_seconds=3)
    monkeypatch.setattr(writer_module, "rewrite_journal", lambda *args, **kwargs: 2)
    writer._rewrite_journal(remove_record_id="synthetic-completed")
    assert writer.stats()["failure_diagnostics"] == {"journal_rewrite/invalid_record": 2}
    assert writer.stats()["receipt_failure_diagnostics"] == {}
    _assert_reconciled(writer)


def test_invalid_receipt_admission_retains_drop_without_inventing_persistence_failure(tmp_path: Path) -> None:
    writer = RuntimeHookEvidenceWriter(store=GuardStore(tmp_path))
    try:
        assert not writer.submit_native_decision_receipt({"private-invalid-field": "private-payload"})
        assert writer.stats()["receipt_dropped"] == 1
        assert writer.stats()["receipt_accepted"] == writer.stats()["receipt_failures"] == 0
        assert writer.stats()["failure_diagnostics"] == writer.stats()["receipt_failure_diagnostics"] == {}
    finally:
        assert writer.stop(timeout_seconds=3)
    _assert_reconciled(writer)


def test_hostile_exception_callbacks_are_not_used_by_writer(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    callbacks: list[str] = []

    class HostileError(RuntimeError):
        def __getattribute__(self, name):
            callbacks.append("attribute")
            raise AssertionError("exception attributes are private")

        def __str__(self):
            callbacks.append("str")
            raise AssertionError("exception text is private")

        def __repr__(self):
            callbacks.append("repr")
            raise AssertionError("exception representation is private")

    error = HostileError("private payload /private/example")
    store = GuardStore(tmp_path)
    persist = store.record_native_decision_receipt
    attempts = 0

    def fail_once(receipt):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise error
        return persist(receipt)

    monkeypatch.setattr(store, "record_native_decision_receipt", fail_once)
    writer = RuntimeHookEvidenceWriter(store=store, batch_wait_seconds=0)
    try:
        assert writer.submit_native_decision_receipt(_receipt())
        _wait_for(lambda: receipt_corpus_is_complete(writer.stats(), expected=1))
    finally:
        assert writer.stop(timeout_seconds=3)
    assert callbacks == []
    assert writer.stats()["receipt_failure_diagnostics"] == {"receipt_persistence/other_exception": 1}
    assert "private" not in json.dumps(writer.stats())
    _assert_reconciled(writer)


def test_exact_type_classification_never_compares_hostile_metaclasses() -> None:
    class HostileMeta(type):
        def __eq__(cls, other):
            raise AssertionError("exception metaclass equality must not run")

        def __hash__(cls):
            raise AssertionError("exception metaclass hashing must not run")

    class HostileSqliteError(sqlite3.OperationalError, metaclass=HostileMeta):
        def __getattribute__(self, name):
            raise AssertionError("exception attributes must not run")

    assert evidence_failure_code(HostileSqliteError("private")) == "other_exception"


@pytest.mark.parametrize(
    ("primary_code", "label"),
    [
        (5, "sqlite_busy"),
        (6, "sqlite_locked"),
        (11, "sqlite_corrupt"),
        (26, "sqlite_not_a_database"),
        (8, "sqlite_read_only"),
        (13, "sqlite_full"),
        (10, "sqlite_io"),
        (14, "sqlite_cannot_open"),
        (19, "sqlite_constraint"),
    ],
)
def test_sqlite_extended_codes_are_reduced_to_bounded_primary_labels(primary_code: int, label: str) -> None:
    error = sqlite3.OperationalError("private text")
    error.sqlite_errorcode = primary_code | (27 << 8)
    assert evidence_failure_code(error) == label


def test_unknown_codes_and_varied_messages_cannot_grow_diagnostic_keys() -> None:
    labels: set[str] = set()
    for index in range(100):
        error = sqlite3.OperationalError(f"private message {index}")
        error.sqlite_errorcode = 255 | (index << 8)
        labels.add(evidence_failure_code(error))
    assert labels == {"sqlite_other"}
    missing = sqlite3.OperationalError("database locked text is not inspected")
    assert evidence_failure_code(missing) == "sqlite_code_unavailable"
    missing.sqlite_errorcode = "private-value"
    assert evidence_failure_code(missing) == "sqlite_code_unavailable"


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (OSError("private unavailable errno"), "os_code_unavailable"),
        (OSError(errno.EIO, "private I/O detail"), "os_other"),
        (ValueError("private value"), "value_error"),
        (TypeError("private type"), "type_error"),
        (RuntimeError("private runtime"), "runtime_error"),
        (Exception("private unknown exception"), "other_exception"),
    ],
)
def test_other_codes_are_fixed_without_reading_exception_text(error: Exception, expected: str) -> None:
    assert evidence_failure_code(error) == expected


@pytest.mark.parametrize(
    "value",
    [None, [], {"private path": 1}, {"receipt_persistence/sqlite_busy": True}, {"receipt_persistence/sqlite_busy": -1}],
)
def test_absent_or_invalid_diagnostics_are_unavailable(value: object) -> None:
    assert evidence_failure_snapshot(value) is None


def test_snapshot_rejects_custom_shapes_without_visiting_them() -> None:
    class HostileDict(dict):
        def items(self):
            raise AssertionError("custom mappings must not be visited")

    class HostileInt(int):
        def __lt__(self, other):
            raise AssertionError("custom integers must not be compared")

    assert evidence_failure_snapshot(HostileDict()) is None
    assert evidence_failure_snapshot({"receipt_persistence/sqlite_busy": HostileInt(1)}) is None
    observed_zero: dict[str, int] = {}
    assert evidence_failure_snapshot(observed_zero) == {}
    observed = {"receipt_persistence/sqlite_busy": 3}
    snapshot = evidence_failure_snapshot(observed)
    assert snapshot == observed and snapshot is not observed
