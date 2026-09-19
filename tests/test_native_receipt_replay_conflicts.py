"""A corrupt stored duplicate never acknowledges recoverable native evidence."""

from __future__ import annotations

import copy
import hashlib
import json
import threading
from dataclasses import replace
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon.runtime_hook_evidence_journal import _NativeDecisionReceiptRecord
from codex_plugin_scanner.guard.daemon.runtime_hook_evidence_writer import RuntimeHookEvidenceWriter
from codex_plugin_scanner.guard.native_decision_receipt import canonical_receipt_bytes
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_native_command_observations import _observations, _receipt
from tests.test_native_policy_decision_context import _captured


@pytest.mark.parametrize("command_binding", [False, True])
def test_corrupt_duplicate_rolls_back_every_new_receipt_in_the_batch(tmp_path: Path, command_binding: bool) -> None:
    store = GuardStore(tmp_path)
    existing = _receipt(_observations() if command_binding else None)
    fresh = _receipt(None if command_binding else _observations())
    assert existing["decision_id"] != fresh["decision_id"]
    assert store.record_native_decision_receipt(existing)
    column, corrupted = ("command_extensions_json", "{!") if command_binding else ("reason_code", "synthetic_changed")
    with store._connect() as connection:
        connection.execute(
            f"update native_hook_decision_receipts set {column} = ? where decision_id = ?",
            (corrupted, existing["decision_id"]),
        )
    with pytest.raises(ValueError, match="native decision receipt identity conflicts"):
        store.record_native_decision_receipts([fresh, existing])
    assert store.native_decision_receipt_count() == 1
    assert store.get_native_decision_receipt(existing["decision_id"]) is None
    assert store.get_native_decision_receipt(fresh["decision_id"]) is None
    with store._connect() as connection:
        assert connection.execute(f"select {column} from native_hook_decision_receipts").fetchone()[0] == corrupted


def test_exact_legacy_and_command_receipt_replays_remain_idempotent(tmp_path: Path) -> None:
    store = GuardStore(tmp_path)
    receipts = [_receipt(None), _receipt(_observations())]
    expected = tuple(receipt["decision_id"] for receipt in receipts)
    assert store.record_native_decision_receipts(receipts) == expected
    assert store.record_native_decision_receipts(copy.deepcopy(receipts)) == expected
    assert store.native_decision_receipt_count() == 2
    assert [store.get_native_decision_receipt(identity) for identity in expected] == receipts


@pytest.mark.parametrize("command_binding", [False, True])
def test_conflicting_stored_native_row_keeps_the_original_scoped_journal_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, command_binding: bool
) -> None:
    store = GuardStore(tmp_path)
    receipt, context = _captured()
    if command_binding:
        receipt["command_extensions"] = _receipt(_observations())["command_extensions"]
        receipt["decision_id"] = hashlib.sha256(canonical_receipt_bytes(receipt)).hexdigest()
        context = replace(context, native_decision_id=receipt["decision_id"])
    assert store.record_native_decision_receipt(receipt)
    with store._connect() as connection:
        connection.execute("update native_hook_decision_receipts set reason_code = 'synthetic_changed'")
    attempted = threading.Event()
    original_record = store.record_native_decision_receipt

    def record_and_observe(*args, **kwargs):
        try:
            return original_record(*args, **kwargs)
        finally:
            attempted.set()

    monkeypatch.setattr(store, "record_native_decision_receipt", record_and_observe)
    writer = RuntimeHookEvidenceWriter(store=store, batch_wait_seconds=0)
    monkeypatch.setattr(writer, "_drain_expired", attempted.is_set)
    assert writer.submit_native_decision_receipt(receipt, policy_context=context)
    assert attempted.wait(timeout=5)
    assert writer.stop(timeout_seconds=0.1)
    assert writer.stats()["receipt_processed"] == 0
    assert writer.stats()["receipt_durable_pending"] == 1
    saved = (tmp_path / "runtime-hook-evidence.jsonl").read_text().splitlines()
    assert len(saved) == 1
    record = _NativeDecisionReceiptRecord.from_json(json.loads(saved[0]))
    assert record is not None and record.receipt == receipt and record.policy_context == context
    assert store.get_native_decision_receipt(context.native_decision_id) is None
    assert store.get_receipt(context.native_decision_id) is None
