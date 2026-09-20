from __future__ import annotations

import copy
import json

import pytest

from scripts.native_slo_daemon_fixture import _CONTROL_LIMIT, _emit
from scripts.native_slo_failure import FixtureFailureError, failure_evidence
from scripts.native_slo_workspace_observer import MAX_EVENTS
from scripts.native_slo_workspace_trace import event_digest, phase_chain, startup_rows, validate_trace

BINDING = {"generation": 17, "policy_digest": "a" * 64, "runtime_identity": "b" * 64}


def trace():
    base = {"publication": 4, "phase": 2, "thread_cpu_ms": 0.5}
    return [
        {**base, "kind": "compile", "started_ms": 1.0, "finished_ms": 2.0, "succeeded": True},
        {**base, "kind": "push", "started_ms": 3.0, "finished_ms": 4.0, "returned": True, "binding": BINDING},
        {**base, "kind": "transport_ack", "started_ms": 2.5, "finished_ms": 5.0, "validated": True, "binding": BINDING},
        {**base, "kind": "barrier", "started_ms": 0.5, "finished_ms": 6.0, "ready": True, "binding": BINDING},
    ]


def test_chain_requires_same_publish_call_and_exact_binding():
    rows = trace()
    value = phase_chain(rows, BINDING, accepted_ms=0)
    assert value["matched"] and value["publication"] == 4
    assert value["compile_ms"] == value["push_ms"] == 1
    assert value["accepted_to_validated_transport_ack_ms"] == 5
    assert value["accepted_to_committed_barrier_ms"] == 6


@pytest.mark.parametrize(
    "index,field,value",
    [
        (0, "publication", 5),
        (0, "succeeded", False),
        (1, "returned", False),
        (1, "binding", {**BINDING, "generation": 18}),
        (2, "validated", False),
        (3, "ready", False),
        (3, "binding", None),
        (0, "finished_ms", 3.5),
        (3, "finished_ms", 4.5),
    ],
)
def test_reordered_missing_failed_or_other_generation_spans_cannot_supply_chain(index, field, value):
    rows = copy.deepcopy(trace())
    rows[index][field] = value
    assert phase_chain(rows, BINDING, accepted_ms=0) == {"matched": False}


def test_burst_requires_compilation_started_after_last_accepted_write():
    assert phase_chain(trace(), BINDING, accepted_ms=1.5)["matched"]
    assert not phase_chain(trace(), BINDING, accepted_ms=1.5, require_final_compile=True)["matched"]


def test_full_bounded_startup_trace_survives_private_failure_protocol_without_truncation(capsysbinary):
    rows = []
    for index in range(MAX_EVENTS):
        rows.append(
            {
                "kind": "transport_ack",
                "phase": 0,
                "publication": index + 1,
                "started_ms": 1.7976931348623157e100,
                "finished_ms": 1.7976931348623157e101,
                "thread_cpu_ms": 1.7976931348623157e99,
                "validated": False,
                "binding": {**BINDING, "generation": 2**64 - 1},
                "scope_loads": [255] * 101,
                "config_loads": 25755,
                "cache_entries": 101,
                "registered_workspaces": 100,
                "scope_counts_overflow": True,
                "config_load_wall_ms": 1.7976931348623157e100,
                "config_load_thread_cpu_ms": 1.7976931348623157e100,
            }
        )
    report = {"events": len(rows), "event_bound": MAX_EVENTS, "event_digest": event_digest(rows)}
    detail = {
        "reason": "workspace_startup_failed",
        "workspace_observation": {
            "observer": report,
            "retained_initial_pages": {
                f"page_{index // 32}": rows[index : index + 32] for index in range(0, MAX_EVENTS, 32)
            },
        },
    }
    _emit({"error": "fixture_failed", "detail": failure_evidence(FixtureFailureError(detail))})
    wire = capsysbinary.readouterr().out.decode()
    assert len(wire.encode()) < _CONTROL_LIMIT
    received = failure_evidence(FixtureFailureError(json.loads(wire)["detail"]))
    retained, decoded = startup_rows(received)
    assert decoded == rows
    assert "retained_initial_pages" not in retained["workspace_observation"]
    assert "truncated" not in wire and "redacted" not in wire


@pytest.mark.parametrize(
    "field,value", [("events", True), ("events", 2), ("event_bound", 1024), ("event_digest", "0" * 64)]
)
def test_event_manifest_rejects_tampering(field, value):
    rows = trace()
    report = {"events": len(rows), "event_bound": MAX_EVENTS, "event_digest": event_digest(rows), field: value}
    with pytest.raises(ValueError):
        validate_trace(rows, report)
