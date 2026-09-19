"""Retain exact refusal evidence without replacing the production edge."""

from __future__ import annotations

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextvars import Context
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_hook_edge as edge
from codex_plugin_scanner.guard.native_resident_client import native_resident_client_failure_code
from scripts import native_slo_edge_diagnostic as stages
from scripts.native_slo_contract import assert_privacy_safe
from scripts.native_slo_failure import FixtureFailureError, failure_evidence
from scripts.native_slo_native_diagnostic import observe_native_call
from scripts.native_slo_source_witness import source_review_witness
from tests.test_native_hook_edge import _edge_result


@pytest.fixture
def real_edge(monkeypatch, tmp_path):
    calls = []
    response = {"value": _edge_result()}
    status = SimpleNamespace(
        mode="auto",
        available=True,
        compatible=True,
        identity=SimpleNamespace(path=tmp_path / "runtime", sha256="a" * 64),
        capabilities=SimpleNamespace(
            features=("hook-envelope-v2", "native-resident-client-v1", "pre-tool-generic-authority-v1")
        ),
        reason="ready",
    )
    monkeypatch.setattr(edge, "native_runtime_status", lambda: calls.append("status") or status)
    monkeypatch.setattr(edge, "_isolated_environment", lambda: {})

    def client(**kwargs):
        calls.append(("client", kwargs["deadline_monotonic"]))
        return json.dumps(response["value"]).encode()

    monkeypatch.setattr(edge, "native_resident_client_request", client)
    monkeypatch.setattr(edge, "native_record_resident_success", lambda *_args: calls.append("success"))
    monkeypatch.setattr(edge, "native_record_resident_failure", lambda *_args, **kwargs: calls.append(kwargs["reason"]))
    deadline = time.monotonic() + 10

    def run():
        return observe_native_call(
            lambda: edge.review_raw_hook_native(
                payload={"private_marker": "do-not-export", "hook_event_name": "PreToolUse"},
                harness="claude-code",
                event="PreToolUse",
                guard_home=tmp_path,
                home_dir=tmp_path,
                cwd=tmp_path,
                source_ref_external_allowed=False,
                observe_mode=False,
                deadline=deadline,
                policy_snapshot={"generation": 1},
            ),
            worker=object(),
            deadline=deadline,
            policy_snapshot={"generation": 1},
        )

    return run, response, status, calls, deadline


def test_stages_observe_real_success_once_without_response_or_request_bytes(real_edge):
    run, response, _status, calls, deadline = real_edge
    original = edge._decode_edge
    with stages.capture_native_edge_stages():
        returned, detail = Context().run(run)
    assert returned == response["value"]
    assert edge._decode_edge is original
    assert calls == ["status", ("client", deadline), "success"]
    assert detail["edge_runtime_status_available"] is True
    assert detail["edge_envelope_returned_bytes"] is True
    assert detail["edge_decoder_accepted"] is True
    assert detail["edge_receipt_matched"] is True
    assert all(value == 1 for key, value in detail.items() if key.startswith("edge_") and key.endswith("_calls"))
    safe = assert_privacy_safe({"failure": {"native_call_diagnostic": detail}})
    encoded = json.dumps(safe)
    assert "do-not-export" not in encoded and "private_marker" not in encoded
    assert "bounded command allowed by Rust" not in encoded


def test_error_response_is_visible_even_when_client_failure_context_is_absent(real_edge):
    run, response, _status, calls, _deadline = real_edge
    response["value"] = {"error": "native_policy_snapshot_not_current", "private": "do-not-export"}
    with stages.capture_native_edge_stages():
        result, detail = Context().run(run)
    assert result is None
    assert detail["client_before_state"] == detail["client_after_state"] == "absent"
    assert detail["edge_client_returned_bytes"] is True
    assert detail["edge_decoder_error_value"] == "native_policy_snapshot_not_current"
    assert detail["edge_decoder_accepted"] is False
    assert detail["edge_resident_failure_reason_value"] == "native_hook_edge_invalid_response"
    assert "edge_receipt_matched" not in detail
    assert calls.count("native_hook_edge_invalid_response") == 1
    assert "do-not-export" not in json.dumps(detail)


def test_receipt_failure_is_observed_without_revalidating_it(real_edge, monkeypatch):
    run, _response, _status, _calls, _deadline = real_edge
    receipts = []
    monkeypatch.setattr(edge, "receipt_matches_edge", lambda *args: receipts.append(args) or False)
    with stages.capture_native_edge_stages():
        result, detail = run()
    assert result is None and len(receipts) == 1
    assert detail["edge_receipt_calls"] == 1 and detail["edge_receipt_matched"] is False


def test_runtime_refusal_does_not_launch_a_client_or_refresh_health(real_edge):
    run, _response, status, calls, _deadline = real_edge
    status.available = False
    status.reason = "unlisted /private/workspace"
    with stages.capture_native_edge_stages():
        result, detail = run()
    assert result is None and calls == ["status"]
    assert not any(key.startswith("edge_client_") or key.startswith("edge_envelope_") for key in detail)
    assert detail["edge_runtime_status_reason_state"] == "unlisted"
    assert "/private/workspace" not in json.dumps(detail)


def test_nested_installation_and_concurrent_contexts_keep_errors_separate(monkeypatch):
    barrier = threading.Barrier(2)
    original = edge._decode_edge

    def run(code):
        def operation():
            barrier.wait(timeout=2)
            return edge._decode_edge({"error": code})

        result, detail = observe_native_call(operation, worker=object())
        assert result is None and native_resident_client_failure_code() is None
        return detail["edge_decoder_error_value"]

    with stages.capture_native_edge_stages():
        wrapper = edge._decode_edge
        with stages.capture_native_edge_stages(), ThreadPoolExecutor(max_workers=2) as pool:
            futures = [
                pool.submit(run, code) for code in ("native_policy_snapshot_invalid", "native_request_invalid_json")
            ]
            assert [future.result(timeout=3) for future in futures] == [
                "native_policy_snapshot_invalid",
                "native_request_invalid_json",
            ]
        assert edge._decode_edge is wrapper
    assert edge._decode_edge is original


def test_diagnostic_failure_preserves_original_return_and_exception(monkeypatch):
    value = object()
    original_error = RuntimeError("private synthetic failure")

    def broken_summary(*_args):
        raise ValueError("diagnostic failed")

    wrapped = stages._wrapper(lambda: value, "client", broken_summary)
    with stages.collect_native_edge_stages() as trace:
        assert wrapped() is value
    assert trace["collection_failed"] is True

    def failed():
        raise original_error

    wrapped = stages._wrapper(failed, "client", broken_summary)
    with stages.collect_native_edge_stages() as trace, pytest.raises(RuntimeError) as caught:
        wrapped()
    assert caught.value is original_error and "collection_failed" not in trace
    assert stages._TRACE.get() is None


def test_stage_count_bound_retains_last_bounded_observation_without_more_work():
    summaries = []
    wrapped = stages._wrapper(lambda: b"response", "client", lambda *_args: summaries.append(1) or {"known": True})
    with stages.collect_native_edge_stages() as trace:
        for _ in range(10):
            assert wrapped() == b"response"
    assert trace["client"]["calls"] == 4
    assert trace["stage_count_limit_reached"] is True and len(summaries) == 4


def test_source_witness_failure_keeps_stage_values_inside_existing_privacy_depth():
    worker = SimpleNamespace(
        _review_raw_hook_native=lambda **_kwargs: edge._decode_edge({"error": "native_policy_snapshot_not_current"})
    )
    request = {"guard_source_ref": {"output_sha256": "a" * 64}}
    with pytest.raises(FixtureFailureError) as caught, source_review_witness(worker, request):
        worker._review_raw_hook_native()
    exported = json.loads(json.dumps(assert_privacy_safe({"failure": failure_evidence(caught.value)})))
    diagnostic = exported["failure"]["native_observations"][0]["call_diagnostic"]
    assert diagnostic["edge_decoder_error_value"] == "native_policy_snapshot_not_current"
    assert diagnostic["edge_decoder_accepted"] is False
    assert diagnostic["edge_decoder_calls"] == 1
    assert "truncated" not in json.dumps(diagnostic)
