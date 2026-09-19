"""Real SQLite/journal checks for diagnostic witnesses, independent of SLO runs."""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.daemon import runtime_hook_evidence_journal as journal
from codex_plugin_scanner.guard.daemon.runtime_hook_evidence_writer import RuntimeHookEvidenceWriter
from codex_plugin_scanner.guard.store import GuardStore
from scripts.native_slo_mixed_server import MixedScenarioFixture
from scripts.native_slo_mixed_witness import ReceiptWitness, _JournalOS, writer_drained
from tests.test_native_command_observations import _observations
from tests.test_native_command_observations import _receipt as command_receipt
from tests.test_native_decision_receipt import _receipt


def _session(store: GuardStore, **fields: object) -> SimpleNamespace:
    return SimpleNamespace(store=store, guard_home=store.guard_home, workspace=store.guard_home, **fields)


def test_dequeued_batch_is_not_mistaken_for_drained_evidence() -> None:
    stats = {
        "queued": 0,
        "durable_pending": 0,
        "receipt_durable_pending": 0,
        "in_flight": False,
        "accepted": 2,
        "processed": 1,
    }
    assert writer_drained(stats) is False
    stats["processed"] = 2
    stats["in_flight"] = True
    assert writer_drained(stats) is False
    stats["in_flight"] = False
    assert writer_drained(stats) is True
    del stats["accepted"]
    assert writer_drained(stats) is False


def test_witness_requires_exact_committed_ids_and_full_command_binding(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    first, second = command_receipt(_observations()), _receipt(request_id="second")
    witness = ReceiptWitness(_session(store), maximum=3)
    witness.observe("mixed-load-0", {"receipt": first})
    witness.observe("mixed-load-1", {"receipt": second})
    witness.admitted(first, True)
    witness.admitted(second, True)
    store.record_native_decision_receipt(first)
    store.record_native_decision_receipt(_receipt(request_id="unrelated"))
    witness.reconcile()
    report = witness.report()
    assert report["committed"] == report["missing"] == 1
    assert report["committed_identity_digest"] == hashlib.sha256(first["decision_id"].encode()).hexdigest()
    assert witness.row("mixed-load-1")["committed"] is False

    # SQL row count and outer ID are unchanged; validated getter detects loss
    # of the authenticated native command binding in the persisted row.
    with store._connect() as connection:
        connection.execute(
            "update native_hook_decision_receipts set command_extensions_json = null where decision_id = ?",
            (first["decision_id"],),
        )
    witness.reconcile(verify_all=True)
    assert witness.report()["binding_mismatches"] == 1
    with store._connect() as connection:
        connection.execute("delete from native_hook_decision_receipts where decision_id = ?", (first["decision_id"],))
    witness.reconcile(verify_all=True)
    assert witness.report()["committed"] == 0
    assert witness.report()["missing"] == 2


def test_actual_writer_admission_journal_io_and_sql_are_observed_without_modifying_result(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    writer = RuntimeHookEvidenceWriter(store=store, batch_wait_seconds=0.05)
    receipt = _receipt(request_id="observed")
    edge = {"receipt": receipt}
    worker = SimpleNamespace(_review_raw_hook_native=lambda **_kwargs: edge)
    session = _session(
        store, daemon=SimpleNamespace(_server=SimpleNamespace(hook_worker=worker, runtime_hook_evidence_writer=writer))
    )
    witness = ReceiptWitness(session, maximum=1).__enter__()
    try:
        assert worker._review_raw_hook_native(payload={"tool_use_id": "mixed-load-0"}) is edge
        assert writer.submit_native_decision_receipt(receipt) is True
        assert writer.stop(timeout_seconds=3)
        witness.reconcile()
        result = witness.report()
        assert result["native_receipts"] == result["writer_admitted"] == result["committed"] == 1
        assert result["binding_mismatches"] == result["missing"] == 0
        assert result["journal_io"]["journal_written_bytes"] > 0
        assert result["journal_io"]["journal_file_fsync_calls"] > 0
        assert result["unavailable"]["sqlite_fsync_calls"] == "sqlite_vfs_not_instrumented"
        assert "sqlite_fsync_calls" not in result["journal_io"]
    finally:
        writer.stop(timeout_seconds=3)
        witness.close()
    assert journal.os is os


def test_real_short_writes_and_failed_sync_do_not_invent_completed_bytes(tmp_path: Path) -> None:
    witness = ReceiptWitness(_session(GuardStore(tmp_path)), maximum=1)

    def fail_sync(_descriptor: int) -> None:
        raise OSError("simulated fsync failure")

    instrumented = _JournalOS(SimpleNamespace(write=lambda _fd, _data: 2, fsync=fail_sync), witness)
    assert instrumented.write(1, b"abcdefgh") == 2
    with pytest.raises(OSError):
        instrumented.fsync(1)
    result = witness.report()["journal_io"]
    assert result["journal_written_bytes"] == 2
    assert result["journal_file_fsync_calls"] == 0
    assert result["journal_file_fsync_failures"] == 1


def test_witness_overflow_duplicate_and_invalid_receipts_are_explicit(tmp_path: Path) -> None:
    witness = ReceiptWitness(_session(GuardStore(tmp_path)), maximum=1)
    first = _receipt(request_id="first")
    witness.observe("mixed-load-0", {"receipt": first})
    witness.observe("mixed-load-0", {"receipt": first})
    witness.observe("mixed-load-1", {"receipt": _receipt(request_id="other")})
    witness.observe("mixed-load-2", {"receipt": {"decision_id": "invalid"}})
    witness.observe("untracked-private-id", {"receipt": first})
    assert witness.report()["observations"] == {
        "duplicate_observations": 1,
        "witness_overflow": 1,
        "invalid_receipt_identity": 1,
    }
    assert len(witness.page(0, 128)["rows"]) == 1
    with pytest.raises(ValueError):
        witness.page(0, 129)


def test_candidate_pre_hook_requires_program_binding_even_for_valid_legacy_identity(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    receipt = command_receipt(None)
    witness = ReceiptWitness(_session(store), maximum=1)
    witness.observe("mixed-load-0", {"receipt": receipt})
    store.record_native_decision_receipt(receipt)
    witness.reconcile()
    assert witness.report()["binding_mismatches"] == 0
    assert witness.report()["pre_receipts_without_program_binding"] == 1


def test_first_decision_filters_stale_generation_digest_action_and_acceptance_time(tmp_path: Path) -> None:
    witness = ReceiptWitness(_session(GuardStore(tmp_path)), maximum=4)
    binding = {"generation": 9, "policy_digest": "b" * 64}
    witness.observe(
        "mixed-load-0", {"receipt": _receipt(request_id="before", policy_generation=9, policy_digest="b" * 64)}
    )
    accepted = time.monotonic()
    witness.observe(
        "mixed-load-1", {"receipt": _receipt(request_id="stale", policy_generation=8, policy_digest="b" * 64)}
    )
    witness.observe(
        "mixed-load-2", {"receipt": _receipt(request_id="wrong", policy_generation=9, policy_digest="c" * 64)}
    )
    witness.observe(
        "mixed-load-3", {"receipt": _receipt(request_id="correct", policy_generation=9, policy_digest="b" * 64)}
    )
    assert witness.first_decision(binding, "allow", since=accepted)["attempt"] == "mixed-load-3"
    assert witness.first_decision(binding, "block", since=accepted) is None


def test_partial_inventory_failure_retains_real_commits(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = GuardStore(tmp_path)
    fixture = MixedScenarioFixture(_session(store))
    fixture.witness = ReceiptWitness(fixture.session, maximum=1)
    original = store.record_inventory_artifact
    calls = 0

    def fail_third(**kwargs: object) -> None:
        nonlocal calls
        calls += 1
        if calls == 3:
            raise OSError("disk unavailable")
        original(**kwargs)

    monkeypatch.setattr(store, "record_inventory_artifact", fail_third)
    result = fixture.dispatch("mixed_inventory", {"index": 0, "count": 5})
    assert result["status"] == "failed"
    assert result["offered"] == 5
    assert result["attempted"] == 3
    assert result["committed"] == 2
    with store._connect() as connection:
        assert connection.execute("select count(*) from artifact_inventory").fetchone()[0] == 2
    assert "disk unavailable" not in json.dumps(result)
