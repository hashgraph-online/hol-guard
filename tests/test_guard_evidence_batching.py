"""Batch commit, crash boundaries, and bounded foreground evidence contracts."""

from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import threading
import time
from collections.abc import Iterator, Mapping
from pathlib import Path
from unittest.mock import patch

import pytest

from codex_plugin_scanner.guard.daemon import runtime_hook_evidence_journal as journal
from codex_plugin_scanner.guard.daemon.runtime_hook_evidence_writer import RuntimeHookEvidenceWriter
from codex_plugin_scanner.guard.store import GuardStore

from .test_native_decision_receipt import _receipt


def _wait_for(predicate: object) -> None:
    assert callable(predicate)
    deadline = time.monotonic() + 3
    while not predicate() and time.monotonic() < deadline:
        time.sleep(0.005)
    assert predicate()


def test_receipt_batch_validates_before_atomic_commit_and_deduplicates(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    first, second = _receipt(request_id="first"), _receipt(request_id="second")
    with patch.object(store, "_connect", wraps=store._connect) as connections:
        assert store.record_native_decision_receipts((first, first, second)) == (
            first["decision_id"],
            first["decision_id"],
            second["decision_id"],
        )
        assert connections.call_count == 1
    assert store.native_decision_receipt_count() == 2
    invalid = {**_receipt(request_id="invalid"), "reason_code": "changed_without_new_identity"}
    with pytest.raises(ValueError):
        store.record_native_decision_receipts((_receipt(request_id="must-not-commit"), invalid))
    assert store.native_decision_receipt_count() == 2


def test_late_sqlite_batch_failure_rolls_back_every_insert(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    with store._connect() as connection:
        connection.execute(
            "create trigger fail_second_receipt before insert on native_hook_decision_receipts "
            "when NEW.request_id = 'second' begin select raise(ABORT, 'injected storage failure'); end"
        )
    with pytest.raises(sqlite3.IntegrityError):
        store.record_native_decision_receipts((_receipt(request_id="first"), _receipt(request_id="second")))
    assert store.native_decision_receipt_count() == 0


def test_writer_batches_receipts_and_checkpoints_once(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    writer = RuntimeHookEvidenceWriter(store=store, batch_wait_seconds=0.05)
    with writer._condition:
        for index in range(32):
            assert writer.submit_native_decision_receipt(_receipt(request_id=f"batch-{index}"))
    assert writer.stop(timeout_seconds=3)
    assert store.native_decision_receipt_count() == 32
    stats = writer.stats()
    assert stats["receipt_processed"] == stats["journal_durable"] == 32
    assert stats["receipt_transactions"] == stats["journal_checkpoints"] == 1
    assert stats["durable_pending"] == stats["checkpoint_pending"] == 0


@pytest.mark.parametrize("cut_point", ["append", "commit", "checkpoint"])
def test_process_death_recovers_only_journaled_receipts(tmp_path: Path, cut_point: str) -> None:
    script = """
import os, sys
from pathlib import Path
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.daemon.runtime_hook_evidence_journal import (
    _NativeDecisionReceiptRecord, append_journal_batch, checkpoint_journal,
)
from tests.test_native_decision_receipt import _receipt
home = Path(sys.argv[1])
store = GuardStore(home)
receipt = _receipt(request_id="crash-boundary")
path = home / "runtime-hook-evidence.jsonl"
append_journal_batch(path, (_NativeDecisionReceiptRecord(receipt=receipt, payload_bytes=0),))
if sys.argv[2] == "append":
    os._exit(0)
store.record_native_decision_receipts((receipt,))
if sys.argv[2] == "commit":
    os._exit(0)
checkpoint_journal(path, remove_record_ids={receipt["decision_id"]}, max_bytes=16*1024*1024)
os._exit(0)
"""
    completed = subprocess.run(
        [sys.executable, "-c", script, str(tmp_path), cut_point],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    store = GuardStore(tmp_path)
    recovered = RuntimeHookEvidenceWriter(store=store, batch_wait_seconds=0)
    assert recovered.stop(timeout_seconds=3)
    assert recovered.stats()["recovered"] == (0 if cut_point == "checkpoint" else 1)
    assert store.native_decision_receipt_count() == 1
    assert (tmp_path / "runtime-hook-evidence.jsonl").read_bytes() == b""


def test_checkpoint_retry_never_reinserts_or_redecides_receipts(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    writer = RuntimeHookEvidenceWriter(store=store, batch_wait_seconds=0)
    with patch(
        "codex_plugin_scanner.guard.daemon.runtime_hook_evidence_writer.checkpoint_journal",
        side_effect=OSError("read-only filesystem"),
    ):
        assert writer.submit_native_decision_receipt(_receipt())
        _wait_for(lambda: writer.stats()["checkpoint_pending"] == 1)
        assert writer.stats()["receipt_transactions"] == 1
        assert writer.stats()["durable_pending"] == 1
    _wait_for(lambda: writer.stats()["checkpoint_pending"] == 0)
    # A successful idle checkpoint must leave the worker available for new work.
    assert writer.submit_native_decision_receipt(_receipt(request_id="after-recovery"))
    assert writer.stop(timeout_seconds=3)
    assert writer.stats()["receipt_transactions"] == 2
    assert store.native_decision_receipt_count() == 2


def test_unpaired_command_recovery_preserves_attempt_identity(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    writer = RuntimeHookEvidenceWriter(store=store, batch_wait_seconds=0)
    with patch(
        "codex_plugin_scanner.guard.daemon.runtime_hook_evidence_writer.checkpoint_journal",
        side_effect=OSError("checkpoint unavailable"),
    ):
        assert writer.submit_command_activity(
            harness="pi", event="PostToolUse", payload={"command": "echo safe"}, succeeded=True
        )
        _wait_for(lambda: writer.stats()["processed"] == 1)
        assert writer.stop(timeout_seconds=3)
    assert store.count_command_activities() == 1
    recovered = RuntimeHookEvidenceWriter(store=store, batch_wait_seconds=0)
    assert recovered.stop(timeout_seconds=3)
    assert recovered.stats()["recovered"] == 1
    assert recovered.stats()["processed"] == 1
    assert store.count_command_activities() == 1


def test_truncated_journal_reports_degradation_and_replays_valid_prefix(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    (tmp_path / "runtime-hook-evidence.jsonl").write_text(
        json.dumps(_receipt()) + '\n{"schema":"truncated', encoding="utf-8"
    )
    writer = RuntimeHookEvidenceWriter(store=store, batch_wait_seconds=0)
    assert writer.stop(timeout_seconds=3)
    assert writer.stats()["recovered"] == 1
    assert writer.stats()["degraded"]
    assert store.native_decision_receipt_count() == 1


def test_compact_admission_does_not_visit_or_retain_unrelated_payload(tmp_path: Path) -> None:
    class UnrelatedPayload:
        def __deepcopy__(self, _memo: object) -> object:
            raise AssertionError("unrelated output must not be copied")

    release = threading.Event()
    with patch.object(RuntimeHookEvidenceWriter, "_run", lambda _self: release.wait(timeout=3)):
        writer = RuntimeHookEvidenceWriter(store=GuardStore(tmp_path), max_bytes=1_024)
        try:
            assert writer.submit_command_activity(
                harness="pi",
                event="PostToolUse",
                succeeded=True,
                payload={"command": "echo safe", "tool_output": UnrelatedPayload()},
            )
            assert writer.stats()["queued_bytes"] < 1_024
            queued = writer._records[0]
            assert queued.invocation_preview == "echo safe"
        finally:
            release.set()
            assert writer.stop(timeout_seconds=3)


def test_full_queue_rejects_before_payload_access(tmp_path: Path) -> None:
    class UnreadableMapping(Mapping[str, object]):
        def __getitem__(self, _key: str) -> object:
            raise AssertionError("saturated admission must not inspect the payload")

        def __iter__(self) -> Iterator[str]:
            raise AssertionError("saturated admission must not iterate the payload")

        def __len__(self) -> int:
            raise AssertionError("saturated admission must not count the payload")

    release = threading.Event()
    with patch.object(RuntimeHookEvidenceWriter, "_run", lambda _self: release.wait(timeout=3)):
        writer = RuntimeHookEvidenceWriter(store=GuardStore(tmp_path), max_records=1)
        try:
            assert writer.submit_command_activity(
                harness="pi", event="PostToolUse", succeeded=True, payload={"command": "echo safe"}
            )
            assert not writer.submit_command_activity(
                harness="pi", event="PostToolUse", succeeded=True, payload=UnreadableMapping()
            )
            assert writer.stats()["dropped"] == 1
            assert writer.stats()["degraded"]
        finally:
            release.set()
            assert writer.stop(timeout_seconds=3)


@pytest.mark.skipif(os.name == "nt", reason="unprivileged Windows runners cannot create symlinks")
def test_preview_sidecar_symlink_cannot_read_or_modify_another_file(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "home")
    target = tmp_path / "private.jsonl"
    target.write_text("private material", encoding="utf-8")
    (store.guard_home / "runtime-hook-evidence.preview.jsonl").symlink_to(target)
    writer = RuntimeHookEvidenceWriter(store=store, batch_wait_seconds=0)
    assert writer.submit_command_activity(
        harness="pi", event="PostToolUse", payload={"command": "echo safe"}, succeeded=True
    )
    assert writer.stop(timeout_seconds=3)
    assert writer.stats()["dropped"] == 1
    assert target.read_text(encoding="utf-8") == "private material"


def test_failed_aggregate_append_rolls_back_preview_batch(tmp_path: Path) -> None:
    path = tmp_path / "runtime-hook-evidence.jsonl"
    record = journal._CommandActivityRecord(
        record_id="attempt",
        harness="pi",
        event="PostToolUse",
        correlation=None,
        has_command=True,
        succeeded=True,
        payload_bytes=0,
        invocation_preview="echo safe",
    )
    write_all = journal._write_all

    def write(descriptor: int, payload: bytes) -> None:
        if b'"schema"' in payload:
            raise OSError("aggregate disk full after preview flush")
        write_all(descriptor, payload)

    with patch.object(journal, "_write_all", side_effect=write), pytest.raises(OSError):
        journal.append_journal_batch(path, (record,))
    assert path.read_bytes() == b""
    assert (tmp_path / "runtime-hook-evidence.preview.jsonl").read_bytes() == b""


def test_concurrent_recovery_deduplicates_the_same_command_attempt(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    path = tmp_path / "runtime-hook-evidence.jsonl"
    record = journal._CommandActivityRecord(
        record_id="shared-attempt",
        harness="pi",
        event="PostToolUse",
        correlation=None,
        has_command=True,
        succeeded=True,
        payload_bytes=0,
        occurred_at="2026-01-01T00:00:00+00:00",
        invocation_preview="echo safe",
    )
    journal.append_journal_batch(path, (record,))
    release = threading.Event()
    run = RuntimeHookEvidenceWriter._run

    def gated_run(writer: RuntimeHookEvidenceWriter) -> None:
        assert release.wait(timeout=3)
        run(writer)

    with patch.object(RuntimeHookEvidenceWriter, "_run", gated_run):
        first = RuntimeHookEvidenceWriter(store=store, batch_wait_seconds=0)
        second = RuntimeHookEvidenceWriter(store=store, batch_wait_seconds=0)
        assert first.stats()["recovered"] == second.stats()["recovered"] == 1
        release.set()
        assert first.stop(timeout_seconds=3)
        assert second.stop(timeout_seconds=3)
    assert store.count_command_activities() == 1
    assert path.read_bytes() == b""


def test_corrupt_database_keeps_native_receipt_journal_recoverable(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "home")
    backup_path = tmp_path / "healthy.db"
    backup = sqlite3.connect(backup_path)
    try:
        with store._connect() as connection:
            connection.backup(backup)
    finally:
        backup.close()
    writer = RuntimeHookEvidenceWriter(store=store, batch_wait_seconds=0)
    store.path.write_bytes(b"malformed sqlite database")
    # Exercise the journal's fallback when the existing automatic quarantine
    # repair cannot proceed, rather than replacing that repair contract.
    with patch.object(store, "_recover_fatal_sqlite_store", return_value=False):
        try:
            assert writer.submit_native_decision_receipt(_receipt())
            _wait_for(lambda: writer.stats()["receipt_failures"] >= 1)
        finally:
            assert writer.stop(timeout_seconds=3)
    assert writer.stats()["receipt_durable_pending"] == 1
    # The database is repaired outside the hook path; recovery consumes the
    # journaled receipt, never a second native decision.
    for suffix in ("-wal", "-shm", "-journal"):
        Path(str(store.path) + suffix).unlink(missing_ok=True)
    os.replace(backup_path, store.path)
    recovered = RuntimeHookEvidenceWriter(store=store, batch_wait_seconds=0)
    assert recovered.stop(timeout_seconds=3)
    assert recovered.stats()["receipt_processed"] == 1
    assert store.native_decision_receipt_count() == 1
