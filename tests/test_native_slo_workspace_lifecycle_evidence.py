from __future__ import annotations

import copy
import hashlib
import json
import time
from contextlib import closing

import pytest

from codex_plugin_scanner.guard.native_decision_receipt import validate_native_decision_receipt
from scripts import native_slo_workspace_lifecycle_evidence as evidence
from scripts.native_slo_contract import assert_privacy_safe
from scripts.native_slo_failure import failure_evidence
from scripts.native_slo_mixed_load import PrivateLedger
from scripts.native_slo_mixed_witness import ReceiptWitness
from scripts.native_slo_workspace_observer import MAX_EVENTS, public_binding
from scripts.native_slo_workspace_request_observer import WorkspaceRequestObserver
from scripts.native_slo_workspace_trace import event_digest, phase_chain, validate_trace
from tests.native_workspace_request_fixtures import control


class Ledger:
    def __init__(self):
        self.rows = []

    def write(self, value):
        self.rows.append(value)


def restored(rows, summary):
    assert all(row["kind"] == "lifecycle_cell_terminal_part" for row in rows)
    assert [row["part"] for row in rows] == list(range(len(rows)))
    assert all(row["parts"] == len(rows) for row in rows)
    encoded = "".join(row["content"] for row in rows)
    digest = hashlib.sha256(encoded.encode("ascii")).hexdigest()
    assert all(row["result_sha256"] == digest for row in rows)
    assert summary["evidence"] == {
        "schema": evidence.EVIDENCE_SCHEMA,
        "sha256": digest,
        "bytes": len(encoded),
        "parts": len(rows),
        "record_kind": "lifecycle_cell_terminal_part",
    }
    return json.loads(encoded)


@pytest.fixture
def cell(tmp_path, monkeypatch):
    # Native/HTTP and authenticated readback are controls. The witness and
    # request observers, receipt validation and committed SQLite readback run.
    state = control(tmp_path, monkeypatch)
    state.action = "allow"
    state.response = {
        "hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow"},
        "policy_action": "allow",
        "decision": "allow",
        "continue": True,
    }
    with closing(ReceiptWitness(state.session, maximum=1).__enter__()) as witness:
        with WorkspaceRequestObserver(state.session, witness, state.workspaces[:1], maximum=1) as observer:
            accepted = time.monotonic()
            observer.probe(0, 0)
        witness.reconcile(verify_all=True)
        requests = observer.join(accepted=accepted, snapshot=state.snapshot, action="allow", declared_indexes=(0,))
    assert requests["passed"] is True
    binding = public_binding(state.snapshot)
    rows = []
    for index, (kind, fields) in enumerate(
        (
            (
                "compile",
                {
                    "succeeded": True,
                    "config_loads": 2,
                    "scope_loads": [1, 1],
                    "unregistered_loads": 0,
                    "config_load_failures": 0,
                    "scope_counts_overflow": False,
                    "config_load_wall_ms": 0.2,
                    "config_load_thread_cpu_ms": 0.1,
                    "cache_entries": 2,
                    "registered_workspaces": 1,
                },
            ),
            ("push", {"binding": binding, "returned": True}),
            ("transport_ack", {"binding": binding, "validated": True}),
            ("barrier", {"binding": binding, "ready": True}),
        )
    ):
        rows.append(
            {
                "kind": kind,
                "phase": 0,
                "publication": 1,
                "started_ms": index * 2.0 + 1,
                "finished_ms": index * 2.0 + 2,
                "thread_cpu_ms": 0.1,
                **fields,
            }
        )
    return {
        "status": "completed",
        "scenario": "lost_metadata_hint",
        "registered_workspaces": 1,
        "passed": True,
        "accepted_ms": 0.0,
        "binding": binding,
        "accept_to_ack_ms": 8.0,
        "headline_timing_eligible": False,
        "full_rsp_128_129_qualification": False,
        "requests": requests,
        "publication_rows": rows,
        "publication_observer": {
            "events": len(rows),
            "event_bound": MAX_EVENTS,
            "counts": {"compile": 1, "push": 1, "transport_ack": 1, "barrier": 1},
            "event_digest": event_digest(rows),
            "complete": True,
            "calls_in_flight_at_freeze": 0,
            "timing_scope": "instrumented_publisher_thread_including_forwarding_observer",
            "thread_cpu_scope": "calling_thread_only_excludes_native_resident_cpu",
            "headline_timing_eligible": False,
        },
        "publication_chain": phase_chain(rows, binding, accepted_ms=0.0),
        "scope_checks": dict.fromkeys(evidence._SCOPE_CHECKS, True),
        "fault": {
            "metadata_observations": 3,
            "changed_metadata_hints_dropped": 2,
            "actual_changed_hint_observed": True,
            "resident_identity_forwarded": True,
            "content_capture_replaced": False,
            "clock_replaced": False,
            "explicit_publish_hint_sent": False,
        },
    }


def test_private_ledger_roundtrip_preserves_complete_receipts_authority_and_ack(tmp_path, cell):
    original = copy.deepcopy(cell)
    path = tmp_path / "lifecycle.jsonl"
    ledger = PrivateLedger(path)
    try:
        summary = evidence.retain_cell(ledger, cell)
    finally:
        ledger.finish()
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    saved = restored(rows, summary)
    assert len(rows) > 1
    assert saved["schema"] == evidence.EVIDENCE_SCHEMA
    assert saved["proof"] == {key: value for key, value in cell.items() if key in evidence._PROOF_FIELDS}
    assert cell == original
    captured = saved["proof"]["requests"]["actual_request_rows"][0]
    for name in ("native_receipt", "committed_receipt"):
        assert validate_native_decision_receipt(captured[name]) == captured[name]
        expected = original["requests"]["actual_request_rows"][0][name]
        assert captured[name]["command_extensions"] == expected["command_extensions"]
        assert captured[name]["source_ref_external_allowed"] is False
        assert captured[name]["reviewed_output_sha256"] is None
    assert captured["authority_before"] == captured["authority_after"] == cell["requests"]["authority"]
    validate_trace(saved["proof"]["publication_rows"], saved["proof"]["publication_observer"])
    assert not (evidence._PROOF_FIELDS & set(summary))
    assert summary["request_checks"]["passed"] is True
    assert summary["headline_timing_eligible"] is summary["full_rsp_128_129_qualification"] is False
    assert assert_privacy_safe({"cells": [summary]})["cells"][0] == summary
    assert all(len(json.dumps(row)) < 8192 for row in rows)


def fault_request(passed=True):
    return {
        "passed": passed,
        "scope": "fault_request_separate_from_recovered_receipt_cohort",
        "offered_requests": 1,
        "returned_requests": 1,
        "native_receipts_expected": 0,
        "availability_semantics": "explicit_advisory_continuation_without_native_policy_decision",
        "elapsed_ms": 2.5,
        "delivered_decision": "allow",
        "route": "native_fail_safe",
        "reason": "native_command_control_fence_unavailable",
    }


def test_all_lifecycle_acceptance_and_failure_facts_survive_exactly(cell):
    cell.update(
        passed=False,
        service_replacement={
            "scope": "two_python_service_instances_same_process_same_owned_home",
            "service_instances": 2,
            "cold_observation_boundary": "before_real_constructor_start",
            **dict.fromkeys(evidence._SERVICE_FLAGS, True),
            "python_process_restarted": False,
            "same_owned_home_identity": False,
            "empty_command_authority_reloaded": False,
        },
        key_change={
            "key_domain": "generated_command_control_authority",
            **dict.fromkeys(evidence._KEY_FLAGS, True),
            "interactive_enrollment_exercised": False,
            "policy_integrity_key_migration_exercised": False,
            "old_authority_key_id": "a" * 64,
            "old_authority_epoch": 7,
            "fault_request": fault_request(),
        },
        expiry={**dict.fromkeys(evidence._EXPIRY_FLAGS, True), "control_binding_preserved": False},
        lifecycle_clocks={
            "origin": "lifecycle_cell_entry_monotonic",
            "scope": "instrumented_caller_boundaries",
            "acceptance_deadline_changed": False,
            "boundaries_ms": {"daemon_start_enter": 10.0},
        },
        fault={
            "scope": "one_real_accepted_reply_discarded_before_first_python_admission",
            "real_client_calls": 2,
            **dict.fromkeys(evidence._ACK_FLAGS, True),
            "successful_ack_fabricated": False,
        },
        fault_request=fault_request(False),
        failure=failure_evidence(ValueError("original failure")),
        fixture_cleanup_failure=failure_evidence(OSError("cleanup failure")),
        cleanup_failures=[{"stage": "publisher_close", "failure": failure_evidence(OSError("close failed"))}],
    )
    ledger = Ledger()
    summary = evidence.retain_cell(ledger, cell)
    proof = restored(ledger.rows, summary)["proof"]
    for key in evidence._FACT_FIELDS | evidence._FAILURE_FIELDS:
        assert proof[key] == cell[key]
    assert proof["service_replacement"]["same_owned_home_identity"] is False
    assert proof["service_replacement"]["empty_command_authority_reloaded"] is False
    assert summary["passed"] is False
    assert assert_privacy_safe({"cells": [summary]})["cells"][0] == summary


@pytest.mark.parametrize(
    "fault",
    [
        "invalid_receipt",
        "unknown_receipt_field",
        "unknown_row_field",
        "unknown_report_field",
        "too_many_requests",
        "unbounded_request_id",
        "unknown_authority_field",
        "wrong_event_digest",
        "unknown_publication_field",
        "unbounded_publication_rows",
        "nonfinite_time",
        "unknown_service_fact",
        "nonboolean_service_fact",
        "wrong_cold_observation_boundary",
    ],
)
def test_unknown_malformed_or_unbounded_proof_rejected_before_ledger_write(cell, fault):
    row = cell["requests"]["actual_request_rows"][0]
    if fault == "invalid_receipt":
        row["native_receipt"]["policy_generation"] += 1
    elif fault == "unknown_receipt_field":
        row["native_receipt"]["unknown"] = True
    elif fault == "unknown_row_field":
        row["raw_payload"] = "private-input"
    elif fault == "unknown_report_field":
        cell["requests"]["unknown"] = True
    elif fault == "too_many_requests":
        cell["requests"]["actual_request_rows"] *= 33
    elif fault == "unbounded_request_id":
        row["native_receipt"]["request_id"] = "x" * 257
    elif fault == "unknown_authority_field":
        cell["requests"]["authority"]["unknown"] = True
    elif fault == "wrong_event_digest":
        cell["publication_observer"]["event_digest"] = "f" * 64
    elif fault == "unknown_publication_field":
        cell["publication_rows"][0]["source_content"] = "private-input"
    elif fault == "unbounded_publication_rows":
        cell["publication_rows"] *= 65
    elif fault == "nonfinite_time":
        row["review_returned_ms"] = float("nan")
    else:
        cell["service_replacement"] = {
            "scope": "two_python_service_instances_same_process_same_owned_home",
            "service_instances": 2,
            "cold_observation_boundary": "before_real_constructor_start",
            **dict.fromkeys(evidence._SERVICE_FLAGS, True),
        }
        if fault == "unknown_service_fact":
            cell["service_replacement"]["private_home"] = "private-input"
        elif fault == "wrong_cold_observation_boundary":
            cell["service_replacement"]["cold_observation_boundary"] = "after_constructor_return"
        else:
            cell["service_replacement"]["same_owned_home_identity"] = 1
    ledger = Ledger()
    with pytest.raises(ValueError):
        evidence.retain_cell(ledger, cell)
    assert ledger.rows == []


def test_oversized_terminal_evidence_rejected_before_writing(cell, monkeypatch):
    monkeypatch.setattr(evidence, "MAX_CELL_BYTES", 100)
    ledger = Ledger()
    with pytest.raises(ValueError):
        evidence.retain_cell(ledger, cell)
    assert ledger.rows == []


def test_failed_cell_without_requests_keeps_original_failure_without_promoting_it():
    cell = {
        "scenario": "service_restart",
        "registered_workspaces": 100,
        "passed": False,
        "status": "failed",
        "failure": failure_evidence(TimeoutError("never ready")),
        "headline_timing_eligible": False,
    }
    ledger = Ledger()
    summary = evidence.retain_cell(ledger, cell)
    proof = restored(ledger.rows, summary)["proof"]
    assert proof == {"failure": cell["failure"]}
    assert summary["passed"] is False and "request_checks" not in summary


def test_publication_offsets_before_acceptance_are_preserved(cell):
    cell["accepted_ms"] = 6.0
    cell["publication_chain"] = phase_chain(cell["publication_rows"], cell["binding"], accepted_ms=6.0)
    ledger = Ledger()
    summary = evidence.retain_cell(ledger, cell)
    proof = restored(ledger.rows, summary)["proof"]
    assert proof["publication_chain"]["accepted_to_compile_started_ms"] == -5.0


def test_request_check_tampering_cannot_enter_retained_proof(cell):
    cell["requests"]["rows"][0]["checks"]["authenticated_readbacks_match"] = False
    ledger = Ledger()
    with pytest.raises(ValueError):
        evidence.retain_cell(ledger, cell)
    assert ledger.rows == []
