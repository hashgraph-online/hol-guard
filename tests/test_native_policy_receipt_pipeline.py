from __future__ import annotations

import copy
import hashlib
import json
import sqlite3
import threading
from dataclasses import replace
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.daemon.hook_native_policy_context import (
    native_process_result,
    submit_native_review_receipt,
)
from codex_plugin_scanner.guard.daemon.hook_process_worker import HookProcessReview
from codex_plugin_scanner.guard.daemon.runtime_hook_evidence_journal import _NativeDecisionReceiptRecord
from codex_plugin_scanner.guard.daemon.runtime_hook_evidence_writer import RuntimeHookEvidenceWriter
from codex_plugin_scanner.guard.native_decision_receipt import canonical_receipt_bytes, validate_native_decision_receipt
from codex_plugin_scanner.guard.policy_rule_identity import PolicyRuleIdentity
from codex_plugin_scanner.guard.runtime.runner import _cloud_sync_receipt_payload
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_native_command_observations import _observations
from tests.test_native_command_observations import _receipt as _command_receipt
from tests.test_native_decision_receipt import _receipt
from tests.test_native_policy_decision_context import _captured


def _counts(store):
    with store._connect() as db:
        return tuple(
            db.execute(f"select count(*) from {table}").fetchone()[0]
            for table in (
                "native_hook_decision_receipts",
                "runtime_receipts",
                "runtime_receipt_envelopes",
                "guard_cloud_events",
            )
        )


def _packet(receipt, context):
    worker = SimpleNamespace(last_native_decision_receipt=receipt, _last_native_policy_context=context)
    # The same JSON boundary used between the evaluator and parent process.
    return json.loads(json.dumps(native_process_result(worker, {"continue": True}, "native_resident")))


def test_command_binding_and_scoped_policy_attribution_survive_one_receipt_commit(tmp_path, monkeypatch):
    store = GuardStore(tmp_path / "guard")
    receipt, context = _captured()
    receipt["command_extensions"] = _command_receipt(_observations())["command_extensions"]
    receipt["decision_id"] = hashlib.sha256(canonical_receipt_bytes(receipt)).hexdigest()
    context = replace(context, native_decision_id=receipt["decision_id"])
    expected = copy.deepcopy(receipt)
    original_connect = store._connect

    def mutate_caller_then_connect():
        binding = receipt["command_extensions"]
        assert isinstance(binding, dict)
        binding["program_digest"] = "e" * 64
        return original_connect()

    monkeypatch.setattr(store, "_connect", mutate_caller_then_connect)
    assert store.record_native_decision_receipt(receipt, policy_context=context)
    monkeypatch.setattr(store, "_connect", original_connect)
    assert store.get_native_decision_receipt(context.native_decision_id) == expected
    ordinary = store.get_receipt(context.native_decision_id)
    assert ordinary is not None
    assert ordinary["timestamp"] == context.recorded_at
    envelope = ordinary["action_envelope_json"]
    assert isinstance(envelope, dict)
    assert envelope["nativePolicyDecision"] == context.to_dict()
    assert _counts(store) == (1, 1, 1, 1)
    assert store.record_native_decision_receipt(expected, policy_context=context)
    assert _counts(store) == (1, 1, 1, 1)


def test_mismatched_native_context_cannot_commit_either_receipt(tmp_path):
    store = GuardStore(tmp_path / "guard")
    receipt, context = _captured()
    context = replace(context, native_decision_id="f" * 64)
    with pytest.raises(ValueError, match="does not match"):
        store.record_native_decision_receipt(receipt, policy_context=context)
    assert _counts(store) == (0, 0, 0, 0)


@pytest.mark.parametrize("observe", [False, True])
def test_native_context_survives_process_parent_journal_store_and_real_upload_projection(tmp_path, observe):
    store = GuardStore(tmp_path / "guard")
    receipt, context = _captured(observe=observe)
    original = copy.deepcopy(receipt)
    review = HookProcessReview.from_result(_packet(receipt, context))
    assert review.policy_context == context and review.receipt == receipt
    writer = RuntimeHookEvidenceWriter(store=store, batch_wait_seconds=0)
    assert submit_native_review_receipt(writer, review)
    assert writer.stop(timeout_seconds=5)
    assert writer.stats()["receipt_processed"] == 1
    stored = store.get_receipt(context.native_decision_id)
    assert stored is not None
    payload = _cloud_sync_receipt_payload(stored, device_id="synthetic-device", device_name="Synthetic")
    assert payload["receiptId"] == receipt["decision_id"]
    assert payload["capturedAt"] == context.recorded_at
    assert payload["policyDecision"] == "allow"
    envelope = payload["envelopeRedacted"]
    assert isinstance(envelope, dict)
    assert envelope["nativePolicyDecision"] == context.to_dict()
    assert "policyExecutionOutcome" not in json.dumps(payload)
    assert "command" not in envelope
    assert _counts(store) == (1, 1, 1, 1)
    with store._connect() as db:
        assert db.execute("select recorded_at from native_hook_decision_receipts").fetchone()[0] == context.recorded_at
    assert receipt == original and validate_native_decision_receipt(receipt) == receipt
    assert store.record_native_decision_receipt(receipt, policy_context=context)
    assert _counts(store) == (1, 1, 1, 1)


@pytest.mark.parametrize("committed_projection", [False, True])
def test_native_journal_replays_original_context_after_native_insert_succeeds(
    tmp_path, monkeypatch, committed_projection
):
    home = tmp_path / "guard"
    store = GuardStore(home)
    receipt, context = _captured()
    failed = threading.Event()
    original_add = store.add_receipt

    def fail_projection(*args, **kwargs):
        if committed_projection:
            original_add(*args, **kwargs)
        failed.set()
        raise sqlite3.OperationalError("synthetic projection unavailable")

    monkeypatch.setattr(store, "add_receipt", fail_projection)
    writer = RuntimeHookEvidenceWriter(store=store, batch_wait_seconds=0)
    monkeypatch.setattr(writer, "_drain_expired", failed.is_set)
    assert writer.submit_native_decision_receipt(receipt, policy_context=context)
    assert failed.wait(timeout=5)
    assert writer.stop(timeout_seconds=0.1)
    assert _counts(store) == ((1, 1, 1, 1) if committed_projection else (1, 0, 0, 0))
    assert writer.stats()["receipt_durable_pending"] == 1
    lines = (home / "runtime-hook-evidence.jsonl").read_text().splitlines()
    record = _NativeDecisionReceiptRecord.from_json(json.loads(lines[0]))
    assert record is not None and record.policy_context == context and record.receipt == receipt
    monkeypatch.setattr(store, "add_receipt", original_add)
    recovered = RuntimeHookEvidenceWriter(store=store, batch_wait_seconds=0)
    assert recovered.stop(timeout_seconds=5)
    assert recovered.stats()["recovered"] == recovered.stats()["receipt_processed"] == 1
    assert recovered.stats()["receipt_durable_pending"] == 0
    assert _counts(store) == (1, 1, 1, 1)
    stored = store.get_receipt(context.native_decision_id)
    assert stored is not None
    assert stored["timestamp"] == context.recorded_at


def test_native_projection_receipt_envelope_and_outbox_rollback_together(tmp_path, monkeypatch):
    store = GuardStore(tmp_path / "guard")
    receipt, context = _captured()
    original = store._add_guard_event_v1

    def fail_outbox(*args, **kwargs):
        raise sqlite3.OperationalError("synthetic outbox failure")

    monkeypatch.setattr(store, "_add_guard_event_v1", fail_outbox)
    with pytest.raises(sqlite3.OperationalError):
        store.record_native_decision_receipt(receipt, policy_context=context)
    assert _counts(store) == (1, 0, 0, 0)
    monkeypatch.setattr(store, "_add_guard_event_v1", original)
    assert store.record_native_decision_receipt(receipt, policy_context=context)
    assert _counts(store) == (1, 1, 1, 1)


def test_native_context_conflict_cannot_replace_committed_identity(tmp_path):
    store = GuardStore(tmp_path / "guard")
    receipt, context = _captured()
    assert store.record_native_decision_receipt(receipt, policy_context=context)
    substituted = replace(context, identity=PolicyRuleIdentity("other-policy", "other-rule", "8"))
    with pytest.raises(ValueError, match="conflicts"):
        store.record_native_decision_receipt(receipt, policy_context=substituted)
    assert _counts(store) == (1, 1, 1, 1)
    stored = store.get_receipt(context.native_decision_id)
    assert stored is not None
    envelope = stored["action_envelope_json"]
    assert isinstance(envelope, dict)
    assert envelope["nativePolicyDecision"] == context.to_dict()


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value["policy_context"].update(command="synthetic-private-command"),
        lambda value: value.update(receipt=_receipt(event_name="PreToolUse", request_id="another-request")),
        lambda value: value["policy_context"].update(decision="deny", policyAction="block"),
        lambda value: value["policy_context"]["snapshot"].update(policy_generation=True),
    ],
)
def test_process_and_journal_reject_substituted_context(mutation):
    receipt, context = _captured()
    packet = _packet(receipt, context)
    mutation(packet)
    assert HookProcessReview.from_result(packet).payload is None
    assert (
        _NativeDecisionReceiptRecord.from_json(
            {
                "schema": "guard-native-policy-receipt-record.v1",
                "receipt": packet["receipt"],
                "policy_context": packet["policy_context"],
            }
        )
        is None
    )


def test_legacy_native_receipt_without_context_does_not_invent_cloud_attribution(tmp_path):
    store = GuardStore(tmp_path / "guard")
    receipt = _receipt()
    record = _NativeDecisionReceiptRecord(receipt=receipt, payload_bytes=0)
    assert json.loads(record.serialized()) == receipt
    assert store.record_native_decision_receipt(receipt)
    assert _counts(store) == (1, 0, 0, 0)


def test_writer_dedup_rejects_a_conflicting_context(tmp_path):
    receipt, context = _captured()
    writer = RuntimeHookEvidenceWriter(store=GuardStore(tmp_path / "guard"), batch_wait_seconds=0)
    try:
        assert writer.submit_native_decision_receipt(receipt, policy_context=context)
        assert writer.submit_native_decision_receipt(receipt, policy_context=context)
        assert not writer.submit_native_decision_receipt(
            receipt,
            policy_context=replace(
                context,
                identity=PolicyRuleIdentity("other-policy", "other-rule", "8"),
            ),
        )
    finally:
        assert writer.stop(timeout_seconds=5)
    assert writer.stats()["receipt_deduped"] == 1
    assert writer.stats()["receipt_dropped"] == 1


@pytest.mark.parametrize("redaction", ["full", "partial", "none"])
def test_content_free_native_context_survives_all_receipt_redaction_modes(tmp_path, redaction):
    from codex_plugin_scanner.guard.receipts.manager import _redacted_envelope_dict

    store = GuardStore(tmp_path / "guard")
    receipt, context = _captured()
    store.record_native_decision_receipt(receipt, policy_context=context)
    stored = store.get_receipt(context.native_decision_id)
    assert stored is not None
    envelope = stored["action_envelope_json"]
    assert isinstance(envelope, dict)
    stored["envelope_redacted_json"] = _redacted_envelope_dict(
        envelope,
        redaction_level=redaction,
    )
    payload = _cloud_sync_receipt_payload(
        stored,
        device_id="synthetic-device",
        device_name="Synthetic",
        redaction_level=redaction,
    )
    redacted = payload["envelopeRedacted"]
    assert isinstance(redacted, dict)
    assert redacted["nativePolicyDecision"] == context.to_dict()
    assert payload["capturedAt"] == context.recorded_at
    request_digest = receipt["request_digest"]
    assert isinstance(request_digest, str)
    assert payload["artifactId"] == "native-request:" + request_digest
    assert payload["artifactHash"] == request_digest


def test_concurrent_same_context_projects_one_atomic_receipt(tmp_path, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor

    store = GuardStore(tmp_path / "guard")
    receipt, context = _captured()
    original_read = store.get_receipt
    first_reads = threading.Barrier(2)
    lock = threading.Lock()
    remaining = 2

    def read_before_concurrent_insert(receipt_id):
        nonlocal remaining
        result = original_read(receipt_id)
        with lock:
            wait = remaining > 0
            remaining -= 1
        if wait:
            assert result is None
            first_reads.wait(timeout=5)
        return result

    monkeypatch.setattr(store, "get_receipt", read_before_concurrent_insert)
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(store.record_native_decision_receipt, receipt, policy_context=context) for _ in range(2)
        ]
        assert all(future.result(timeout=10) for future in futures)
    assert _counts(store) == (1, 1, 1, 1)
