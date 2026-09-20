"""Actual native-result provenance through production process and receipt codecs.

The process request/response functions execute in-process under the enclosing
explicit staged negotiation. This adds no separate process-isolation claim.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from codex_plugin_scanner.guard.daemon.hook_native_policy_context import submit_native_review_receipt
from codex_plugin_scanner.guard.daemon.hook_process_entrypoint import _run_resident_hook_request
from codex_plugin_scanner.guard.daemon.hook_process_worker import HookProcessReview
from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.daemon.runtime_hook_evidence_writer import RuntimeHookEvidenceWriter
from codex_plugin_scanner.guard.native_decision_receipt import validate_native_decision_receipt
from codex_plugin_scanner.guard.native_policy_snapshot_publisher import NativePolicySnapshotPublisher
from codex_plugin_scanner.guard.runtime.runner import _cloud_sync_receipt_payload
from codex_plugin_scanner.guard.store import GuardStore
from tests.native_scoped_resident_fixtures import HARNESS, raw_payload


def assert_actual_native_receipt_provenance(
    store: GuardStore, publisher: NativePolicySnapshotPublisher, home: Path, workspace: Path
) -> tuple[str, dict[str, object]]:
    worker = HookWorker(store=store, wait_for_native_policy=False, publish_native_policy=False)
    worker.policy_snapshot_publisher = publisher
    packet = _run_resident_hook_request(
        {
            "payload": {**raw_payload(), "hook_event_name": "PreToolUse"},
            "harness": HARNESS,
            "home_dir": str(home),
            "guard_home": str(store.guard_home),
            "workspace": str(workspace),
            "deadline": time.monotonic() + 5,
        },
        stores={str(store.guard_home): store},
        hook_workers={str(store.guard_home): worker},
        configured_guard_home=str(store.guard_home),
    )
    assert packet["reason_code"] is None
    # No native receipt or context fields are synthesized or changed here.
    review = HookProcessReview.from_result(json.loads(json.dumps(packet)))
    assert review.payload is not None and review.receipt is not None and review.policy_context is not None
    receipt = review.receipt
    original_bytes = json.dumps(receipt, sort_keys=True, separators=(",", ":"))
    assert validate_native_decision_receipt(receipt) == receipt
    context = review.policy_context
    assert context.matches_receipt(receipt)
    assert context.identity.to_dict() == {
        "policyId": "synthetic-policy",
        "ruleId": "synthetic-rule",
        "policyVersion": "8",
    }
    assert context.decision == context.policy_action == "allow"
    assert publisher.result_binding_is_current(context.binding())
    writer = RuntimeHookEvidenceWriter(store=store, batch_wait_seconds=0)
    assert submit_native_review_receipt(writer, review)
    assert writer.stop(timeout_seconds=5)
    assert writer.stats()["receipt_processed"] == 1
    stored = store.get_receipt(str(receipt["decision_id"]))
    assert stored is not None and stored["receipt_id"] == context.native_decision_id
    assert stored["timestamp"] == context.recorded_at
    assert stored["action_envelope_json"]["nativePolicyDecision"] == context.to_dict()
    payload = _cloud_sync_receipt_payload(stored, device_id="synthetic-device", device_name="Synthetic")
    assert payload["receiptId"] == receipt["decision_id"]
    assert payload["capturedAt"] == context.recorded_at and payload["policyDecision"] == "allow"
    assert payload["envelopeRedacted"]["nativePolicyDecision"] == context.to_dict()
    assert "policyExecutionOutcome" not in json.dumps(payload)
    with store._connect() as connection:
        event = connection.execute(
            "select payload_json from guard_cloud_events where idempotency_key = ?",
            (f"receipt.created:{context.native_decision_id}",),
        ).fetchone()
        assert event is not None
        assert json.loads(event["payload_json"])["payload"]["policyDecision"] == "allow"
    assert store.record_native_decision_receipt(receipt, policy_context=context)
    assert store.get_receipt(context.native_decision_id)["timestamp"] == context.recorded_at
    assert json.dumps(receipt, sort_keys=True, separators=(",", ":")) == original_bytes

    return context.native_decision_id, context.to_dict()
