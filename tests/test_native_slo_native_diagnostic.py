"""Worker-context diagnostics cannot change native outcomes or control state."""

from __future__ import annotations

import hashlib
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from contextvars import Context
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.native_resident_client import (
    native_resident_client_failure_code,
    record_native_resident_client_failure_code,
)
from scripts import native_slo_native_diagnostic as diagnostic
from scripts.native_slo_contract import assert_privacy_safe
from scripts.native_slo_failure import FixtureFailureError, failure_evidence
from scripts.native_slo_source_witness import source_review_witness


def test_source_failure_captures_real_worker_context_not_collector_context() -> None:
    def run():
        record_native_resident_client_failure_code("native_client_endpoint_invalid")

        def native(**_kwargs):
            record_native_resident_client_failure_code("native_client_timed_out")
            return None

        worker = SimpleNamespace(_review_raw_hook_native=native)
        with (
            ThreadPoolExecutor(max_workers=1) as pool,
            pytest.raises(FixtureFailureError) as caught,
            source_review_witness(worker, {"guard_source_ref": {"output_sha256": "a" * 64}}),
        ):
            assert pool.submit(worker._review_raw_hook_native).result(timeout=1) is None
        detail = assert_privacy_safe({"failure": failure_evidence(caught.value)})["failure"]
        observed = detail["native_observations"][0]["call_diagnostic"]
        assert observed["client_before_state"] == "absent"
        assert observed["client_after_value"] == "native_client_timed_out"
        assert observed["client_code_attribution"] == "context_transition"
        assert observed["capture_context"] == "native_worker_wrapper"
        assert detail["full_review_qualified"] is False
        assert native_resident_client_failure_code() == "native_client_endpoint_invalid"
        assert worker._review_raw_hook_native is native

    Context().run(run)


def test_unchanged_context_code_is_not_claimed_as_current_request_cause() -> None:
    def run():
        record_native_resident_client_failure_code("native_client_deadline_exceeded")
        returned, detail = diagnostic.observe_native_call(lambda: None, worker=object())
        assert returned is None
        assert detail["client_before_value"] == detail["client_after_value"] == "native_client_deadline_exceeded"
        assert detail["client_code_changed"] is False
        assert detail["client_code_attribution"] == "unchanged_or_stale"
        assert native_resident_client_failure_code() == "native_client_deadline_exceeded"

    Context().run(run)


def test_readonly_metadata_preserves_result_binding_deadline_and_publisher(monkeypatch) -> None:
    calls = []
    clock = iter((100.0, 100.25))
    monkeypatch.setattr(diagnostic, "time", SimpleNamespace(monotonic=lambda: next(clock)))
    binding = {"generation": 3, "mode": "observe", "private_marker": "never exported"}
    edge = {"result": {"decision": "allow"}}
    publisher = SimpleNamespace(
        _condition=threading.Condition(),
        _acked=True,
        _closed=False,
        _started=True,
        _snapshot={"private_marker": "never exported"},
        _last_error=None,
        _failure_count=2,
        is_ready=lambda: pytest.fail("must not refresh readiness or expiry"),
        current_snapshot=lambda: pytest.fail("must not refresh or copy policy"),
        wait_until_ready=lambda *_args: pytest.fail("must not wait for or change readiness"),
    )
    before = dict(vars(publisher))

    def native():
        calls.append(binding)
        record_native_resident_client_failure_code("native_client_frame_write_failed")
        return edge

    returned, detail = Context().run(
        diagnostic.observe_native_call,
        native,
        worker=SimpleNamespace(policy_snapshot_publisher=publisher),
        deadline=100.2,
        policy_snapshot=binding,
    )
    assert returned is edge and calls == [binding]
    assert binding == {"generation": 3, "mode": "observe", "private_marker": "never exported"}
    assert vars(publisher) == before
    assert detail["caller_remaining_ms_before"] == 200.0
    assert detail["caller_remaining_ms_after"] == -50.0
    assert detail["caller_expired_before"] is False and detail["caller_expired_after"] is True
    assert detail["elapsed_ms"] == 250.0
    assert detail["policy_binding_supplied"] is True and detail["policy_generation_valid"] is True
    assert detail["policy_mode"] == "observe"
    assert detail["publisher_cache"] == "captured" and detail["publisher_acked"] is True
    assert detail["publisher_failure_count"] == 2
    assert "private_marker" not in json.dumps(detail)


def test_busy_publisher_diagnostics_never_wait_for_control_lock() -> None:
    publisher = SimpleNamespace(_condition=threading.Condition())
    with ThreadPoolExecutor(max_workers=1) as pool, publisher._condition:
        future = pool.submit(
            diagnostic.observe_native_call,
            lambda: None,
            worker=SimpleNamespace(policy_snapshot_publisher=publisher),
        )
        _edge, detail = future.result(timeout=1)
    assert detail["publisher_cache"] == "busy"


@pytest.mark.parametrize("value", ["private_key /home/test/request text", "x" * 100_000])
def test_unknown_client_values_are_bounded_digest_only_through_real_export(value) -> None:
    def native():
        record_native_resident_client_failure_code(value)
        return None

    _edge, detail = Context().run(diagnostic.observe_native_call, native, worker=object())
    original = FixtureFailureError(
        {
            "reason": "reference_review_unproven",
            "native_observations": [{"call_diagnostic": detail}],
        }
    )
    report = assert_privacy_safe({"failure": failure_evidence(original)})
    exported = report["failure"]["native_observations"][0]["call_diagnostic"]
    assert exported["client_after_state"] == "unlisted"
    assert exported["client_after_digest"] == hashlib.sha256(value[:128].encode()).hexdigest()
    assert exported["client_after_digest_complete"] is (len(value) <= 128)
    assert "client_after_value" not in exported
    encoded = json.dumps(report)
    assert value not in encoded and len(encoded) < 4000


@pytest.mark.parametrize("deadline", [True, float("nan"), float("inf"), "private-clock", None])
def test_invalid_deadline_metadata_is_not_reinterpreted_or_exported(deadline) -> None:
    returned = object()
    actual, detail = Context().run(
        diagnostic.observe_native_call,
        lambda: returned,
        worker=object(),
        deadline=deadline,
        policy_snapshot={"generation": True, "mode": "private-marker"},
    )
    assert actual is returned
    assert detail["caller_deadline_valid"] is False
    assert "caller_remaining_ms_after" not in detail
    assert detail["policy_generation_valid"] is False
    assert detail["policy_mode"] == "unclassified"
    assert "private" not in json.dumps(detail)


def test_native_exception_is_preserved_without_publisher_diagnostic_calls() -> None:
    error = OSError("original private failure")

    def native():
        raise error

    class UnreadablePublisher:
        @property
        def policy_snapshot_publisher(self):
            pytest.fail("native exception must propagate immediately")

    with pytest.raises(OSError) as caught:
        diagnostic.observe_native_call(native, worker=UnreadablePublisher())
    assert caught.value is error


def test_optional_publisher_metadata_failure_cannot_replace_native_result() -> None:
    class UnreadablePublisher:
        @property
        def policy_snapshot_publisher(self):
            raise RuntimeError("private metadata failure")

    edge = object()
    returned, detail = diagnostic.observe_native_call(lambda: edge, worker=UnreadablePublisher())
    assert returned is edge
    assert detail["publisher_cache"] == "collection_failed"
    assert "private" not in json.dumps(detail)


def test_valid_source_edge_is_not_reinterpreted_from_a_stale_client_code() -> None:
    def run():
        record_native_resident_client_failure_code("native_client_timed_out")
        edge = {
            "authority": "rust",
            "result": {
                "decision": "allow",
                "model_output_action": "allow_original",
                "reviewed_output_sha256": "a" * 64,
                "reason_code": "source_full_scan_allow",
            },
        }

        def original(**_kwargs):
            return edge

        worker = SimpleNamespace(_review_raw_hook_native=original)
        with source_review_witness(worker, {"guard_source_ref": {"output_sha256": "a" * 64}}):
            assert worker._review_raw_hook_native() is edge
        assert worker._review_raw_hook_native is original
        assert native_resident_client_failure_code() == "native_client_timed_out"

    Context().run(run)
