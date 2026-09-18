from __future__ import annotations

import hashlib
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_hook_edge
from scripts import native_slo_capacity as capacity
from scripts import native_slo_capacity_diagnostic as diagnostic
from scripts.native_slo_adapter import Observation
from scripts.native_slo_contract import assert_privacy_safe


def _observation(*, allowed=True, overloaded=False):
    return Observation("claude-code", "PreToolUse", "1k", 17.0, "pending_batch_validation", allowed, overloaded)


def test_actual_native_call_arguments_result_and_deadline_are_unchanged(monkeypatch):
    edge = {"result": {"decision": "allow"}}
    received = []

    def original(**kwargs):
        received.append(kwargs)
        return edge

    worker = SimpleNamespace(_review_raw_hook_native=original)
    captured = diagnostic.CapacityDiagnostics(worker, 1)
    kwargs = {"deadline": 123.0, "policy_snapshot": {"generation": 7}, "payload": {"private": "unexported"}}
    with captured.capture_native():
        assert worker._review_raw_hook_native(**kwargs) is edge
    assert worker._review_raw_hook_native is original
    assert received == [kwargs]
    assert captured.report()["native_call_count"] == 1
    assert captured.report()["native_missing_count"] == 0
    assert "unexported" not in json.dumps(captured.report())


def test_native_exception_and_wrapper_retirement_are_preserved():
    failure = OSError("private failure")

    def original(**_kwargs):
        raise failure

    worker = SimpleNamespace(_review_raw_hook_native=original)
    captured = diagnostic.CapacityDiagnostics(worker, 1)
    with pytest.raises(OSError) as raised, captured.capture_native():
        worker._review_raw_hook_native(deadline=1.0)
    assert raised.value is failure
    assert worker._review_raw_hook_native is original
    report = captured.report()
    assert report["native_wrapper"] == "capture_window_closed"
    assert report["native_missing_count"] == 0
    assert "private failure" not in json.dumps(report)


def test_missing_native_details_and_total_observations_are_bounded():
    calls = []

    def original(**_kwargs):
        calls.append(True)
        return None

    worker = SimpleNamespace(_review_raw_hook_native=original)
    captured = diagnostic.CapacityDiagnostics(worker, 10)
    with captured.capture_native():
        for _ in range(13):
            assert worker._review_raw_hook_native() is None
    report = assert_privacy_safe(captured.report())
    assert len(calls) == 13
    assert report["native_call_count"] == report["native_missing_count"] == 10
    assert report["native_count_is_lower_bound"] is True
    assert len(report["native_missing_details"]) == 8
    assert report["native_details_truncated"] is True
    assert report["native_missing_details"][0]["capture_context"] == "native_worker_wrapper"


def test_delivered_semantics_retain_closed_labels_and_bounded_unknown_digests():
    captured = diagnostic.CapacityDiagnostics(SimpleNamespace(), 3)
    private = "private_secret_response_" * 10000

    def operation():
        diagnostic.retain_capacity_delivery(
            {
                "decision": "allow",
                "model_output_action": "allow_original",
                "policy_action": "allow",
                "reason_code": private,
                "error": {"private": private},
                "raw_payload": private,
            }
        )
        return _observation()

    expected = operation()
    assert captured.report()["delivery_count"] == 0  # Unselected calls are ignored.
    assert captured.observe(operation) == expected
    captured.observe(operation)
    report = assert_privacy_safe(captured.report())
    assert report["delivery_count"] == 2
    assert report["delivered_semantics"][0]["count"] == 2
    verdict = report["delivered_semantics"][0]["verdict"]
    assert verdict["decision"] == verdict["policy_action"] == "allow"
    assert verdict["model_action"] == "allow_original"
    assert verdict["reason_code_digest"] == hashlib.sha256(private[:128].encode()).hexdigest()
    assert verdict["reason_code_digest_complete"] is False
    assert verdict["error_state"] == "invalid_type"
    assert "private_secret" not in json.dumps(report)
    assert "raw_payload" not in json.dumps(report)


def test_concurrent_deliveries_are_counted_without_associating_worker_order():
    captured = diagnostic.CapacityDiagnostics(SimpleNamespace(), 64)

    def run(index):
        allowed = index % 2 == 0

        def operation():
            diagnostic.retain_capacity_delivery(
                {"decision": "allow" if allowed else "deny", "reason_code": "daemon_capacity"}
            )
            return _observation(allowed=allowed, overloaded=not allowed)

        return captured.observe(operation)

    with ThreadPoolExecutor(max_workers=8) as executor:
        observations = list(executor.map(run, range(64)))
    report = captured.report()
    assert len(observations) == report["delivery_count"] == 64
    assert sorted(row["count"] for row in report["delivered_semantics"]) == [32, 32]
    assert report["individual_route_attribution"] is False
    assert report["request_repeated"] is False
    assert report["deadline_changed"] is False


def test_raised_attempt_is_not_counted_as_delivered_and_context_is_reset():
    captured = diagnostic.CapacityDiagnostics(SimpleNamespace(), 1)

    def operation():
        diagnostic.retain_capacity_delivery({"decision": "allow"})
        raise TimeoutError("original")

    with pytest.raises(TimeoutError, match="original"):
        captured.observe(operation)
    diagnostic.retain_capacity_delivery({"decision": "deny"})
    captured.observe(_observation)
    report = captured.report()
    assert report["delivery_count"] == 1
    assert report["delivered_semantics"][0]["verdict"]["available"] is False


def test_extra_delivery_cannot_grow_counts_past_wave_limit():
    captured = diagnostic.CapacityDiagnostics(SimpleNamespace(), 1)
    captured.observe(_observation)
    captured.observe(_observation)
    assert captured.report()["delivery_count"] == 1
    assert captured.report()["delivery_count_is_lower_bound"] is True


@pytest.mark.parametrize("limit", [True, 0, -1, 65, 1.0])
def test_invalid_limit_is_rejected(limit):
    with pytest.raises(ValueError, match="limit"):
        diagnostic.CapacityDiagnostics(SimpleNamespace(), limit)


def test_unknown_surrogate_reason_does_not_replace_the_real_result():
    captured = diagnostic.CapacityDiagnostics(SimpleNamespace(), 1)
    expected = _observation()

    def operation():
        diagnostic.retain_capacity_delivery({"reason_code": "private\ud800"})
        return expected

    assert captured.observe(operation) is expected
    assert captured.report()["delivered_semantics"][0]["verdict"]["reason_code_digest_complete"] is True


def test_observed_linux_failure_stays_failed_with_actual_wave_semantic_counts(monkeypatch):
    snapshots = iter(
        ({"routes": {"native_resident": 114}}, {"routes": {"native_resident": 136, "native_fail_safe": 14}})
    )
    worker = SimpleNamespace(metrics=SimpleNamespace(snapshot=lambda: next(snapshots)))
    calls = []

    def native(**kwargs):
        calls.append(kwargs["case"])
        return {"result": {"decision": "allow"}} if kwargs["case"] < 22 else None

    worker._review_raw_hook_native = native
    sequence = iter(range(64))
    lock = threading.Lock()

    def observe(*_args):
        with lock:
            case = next(sequence)
        allowed = case < 36
        if allowed:
            worker._review_raw_hook_native(case=case)
        diagnostic.retain_capacity_delivery(
            {
                "policy_action": "allow" if allowed else "deny",
                "reason_code": "native_post_tool_unavailable" if 22 <= case < 36 else "daemon_capacity",
            }
        )
        return _observation(allowed=allowed, overloaded=not allowed)

    health_calls = []

    def overloads():
        health_calls.append(True)
        return 0

    session = SimpleNamespace(
        daemon=SimpleNamespace(_server=SimpleNamespace(hook_worker=worker)),
        observe=observe,
        native_overload_count=overloads,
    )
    monkeypatch.setattr(capacity, "wait_for_route_corpus", lambda metrics, **_kwargs: metrics.snapshot())
    with ThreadPoolExecutor(max_workers=8) as executor, pytest.raises(RuntimeError) as raised:
        capacity._run_capacity_wave(session, (("claude-code", "PreToolUse"),), 64, executor)
    assert "does not match delivered decisions" in str(raised.value)
    detail = assert_privacy_safe({"failure": raised.value.detail})["failure"]
    assert detail["delivered_allowed"] == 36
    assert detail["delivered_overloaded"] == 28
    assert detail["transport_errors"] == 0
    retained = detail["capacity_diagnostic"]
    assert retained["delivery_count"] == 64
    assert retained["native_call_count"] == len(calls) == 36
    assert retained["native_missing_count"] == 14
    assert len(retained["native_missing_details"]) == 8
    assert sorted(row["count"] for row in retained["delivered_semantics"]) == [14, 22, 28]
    assert all(isinstance(row["verdict"]["allowed"], bool) for row in retained["delivered_semantics"])
    assert len(health_calls) == 2  # Only the existing before/after overload snapshots.


def test_actual_edge_decoder_facts_survive_deepest_capacity_export(monkeypatch):
    payload = {"schema": "guard-hook-edge-result.v2", "error": "native_hook_edge_unavailable"}
    decoded = []

    def decode(actual):
        assert actual is payload
        decoded.append(True)
        return None

    monkeypatch.setattr(native_hook_edge, "_decode_edge", decode)
    worker = SimpleNamespace(_review_raw_hook_native=lambda **_kwargs: native_hook_edge._decode_edge(payload))
    captured = diagnostic.CapacityDiagnostics(worker, 1)
    with captured.capture_native():
        assert worker._review_raw_hook_native() is None
    exported = assert_privacy_safe({"failure": {"capacity_diagnostic": captured.report()}})
    detail = exported["failure"]["capacity_diagnostic"]["native_missing_details"][0]
    assert detail["edge_decoder_calls"] == 1
    assert detail["edge_decoder_accepted"] is False
    assert detail["edge_decoder_error_present"] is True
    assert detail["edge_decoder_error_state"] == "known"
    assert detail["edge_decoder_error_value"] == "native_hook_edge_unavailable"
    assert detail["edge_decoder_error_digest"] == hashlib.sha256(payload["error"].encode()).hexdigest()
    assert len(decoded) == 1
    assert native_hook_edge._decode_edge is decode
    assert "truncated" not in json.dumps(detail)
