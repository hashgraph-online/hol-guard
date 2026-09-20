from __future__ import annotations

import hashlib
import io
import json
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from email.message import Message
from pathlib import Path
from queue import Queue
from types import SimpleNamespace
from typing import Any

import pytest

from scripts import native_slo_phases as phases
from scripts.native_slo_phases import PhaseProfiler


def routed(profiler: PhaseProfiler, function: Any, *, harness: str = "claude-code", event: str = "PostToolUse") -> Any:
    def hook(_self: object, _payload: object, **_kwargs: object) -> Any:
        return function()

    return profiler._wrap(hook, "daemon_hook_inclusive", root=True)(
        None, {"hook_event_name": event}, default_harness=harness
    )


def spans(profiler: PhaseProfiler, route: str = "claude-code.PostToolUse") -> dict[str, Any]:
    return profiler.report()["by_route"][route]


def test_hash_bytes_are_actual_update_work_and_json_units_are_not_conflated(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard import native_hook_edge, native_runtime

    body = b"synthetic-private-bytes" * 150_000
    binary = tmp_path / "synthetic-runtime"
    binary.write_bytes(body)
    original_hash_module = native_runtime.hashlib
    original_json_module = native_hook_edge.json
    with PhaseProfiler() as profiler:
        identity = routed(profiler, lambda: native_runtime._validate_binary(binary))
        assert identity.sha256 == hashlib.sha256(body).hexdigest()
        encoded = routed(profiler, lambda: native_hook_edge.json.dumps({"value": "\u00e9"}, ensure_ascii=False))
        assert encoded == json.dumps({"value": "\u00e9"}, ensure_ascii=False)
        assert routed(profiler, lambda: native_hook_edge.json.loads(encoded.encode())) == {"value": "\u00e9"}
        with pytest.raises(json.JSONDecodeError):
            routed(profiler, lambda: native_hook_edge.json.loads(b"{private-invalid-json"))
    data = spans(profiler)
    assert data["runtime_sha256_update"]["work"]["hashed_bytes"] == len(body)
    assert data["runtime_sha256_update"]["outcomes"]["returned_none"] == 4
    assert data["edge_json_dumps"]["work"] == {"returned_characters": len(encoded)}
    assert data["edge_json_loads"]["work"]["attempted_input_bytes"] == len(encoded.encode()) + 21
    assert data["edge_json_loads"]["outcomes"] == {"returned_value": 1, "raised": 1}
    assert "private" not in json.dumps(profiler.report())
    assert native_runtime.hashlib is original_hash_module
    assert native_hook_edge.json is original_json_module


def test_hash_proxy_copy_and_initial_data_preserve_digest() -> None:
    from codex_plugin_scanner.guard import native_runtime

    with PhaseProfiler() as profiler:

        def exercise() -> None:
            digest = native_runtime.hashlib.sha256(b"a")
            clone = digest.copy()
            digest.update(memoryview(b"b"))
            clone.update(b"c")
            assert digest.digest() == hashlib.sha256(b"ab").digest()
            assert clone.hexdigest() == hashlib.sha256(b"ac").hexdigest()

        routed(profiler, exercise)
    data = spans(profiler)
    assert data["runtime_sha256_init"]["work"]["hashed_bytes"] == 1
    assert data["runtime_sha256_update"]["work"]["hashed_bytes"] == 2
    assert data["runtime_sha256_finalize"]["count"] == 2


def test_small_exact_maximum_and_over_limit_envelopes_use_real_encoder(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard import native_hook_edge as edge

    options = dict(
        harness="claude-code",
        event="PostToolUse",
        guard_home=tmp_path,
        home_dir=tmp_path,
        cwd=tmp_path,
        source_ref_external_allowed=False,
        deadline_budget_ms=500,
        snapshot={"generation": 1},
    )
    empty = edge._encode_hook_envelope(payload={"output": ""}, **options)
    assert empty is not None
    maximum = edge._MAX_REQUEST_BYTES
    sizes = [1024, maximum - len(empty), maximum - len(empty) + 1]
    expected = [edge._encode_hook_envelope(payload={"output": "x" * size}, **options) for size in sizes]
    with PhaseProfiler() as profiler:
        actual = [
            routed(profiler, lambda size=size: edge._encode_hook_envelope(payload={"output": "x" * size}, **options))
            for size in sizes
        ]
    assert actual == expected
    assert len(actual[1]) == maximum
    assert actual[2] is None
    data = spans(profiler)
    assert data["envelope_encode"]["outcomes"] == {"returned_value": 2, "returned_none": 1}
    assert data["envelope_encode"]["work"]["returned_bytes"] == sum(
        len(value) for value in expected if value is not None
    )
    assert data["edge_json_dumps"]["count"] == 3
    # Over-limit work was serialized before rejection; its work must survive.
    assert data["edge_json_dumps"]["work"]["returned_characters"] > maximum * 2


def _handler(raw: bytes) -> Any:
    from codex_plugin_scanner.guard.daemon.server import _GuardDaemonHandler

    handler = object.__new__(_GuardDaemonHandler)
    handler.headers = Message()
    handler.headers["Content-Length"] = str(len(raw))
    handler.headers["Content-Type"] = "application/json"
    handler.rfile = io.BytesIO(raw)
    handler.connection = SimpleNamespace(settimeout=lambda _timeout: None)
    handler.path = "/v1/hooks/claude-code?private-path-not-retained"
    return handler


@pytest.mark.parametrize(
    "raw,error",
    [(b'{"value":"ok"}', None), (b"{bad-private", "invalid_request_body"), (b"\xff", "invalid_request_body")],
)
def test_inbound_http_json_keeps_transport_bucket_and_invalid_attempts(raw: bytes, error: str | None) -> None:
    handler = _handler(raw)
    original = handler.rfile
    with PhaseProfiler() as profiler:
        result = profiler._http_root(lambda current: current._load_request_body())(handler)
    assert result[1] == error
    assert handler.rfile is original
    data = spans(profiler, "claude-code.transport_unclassified")
    assert data["http_body_read"]["work"]["returned_bytes"] == len(raw)
    if raw == b"\xff":
        assert "daemon_json_loads" not in data
    else:
        assert data["daemon_json_loads"]["work"]["attempted_input_characters"] == len(raw)
        assert data["daemon_json_loads"]["outcomes"] == ({"returned_value": 1} if error is None else {"raised": 1})
    assert "private" not in json.dumps(profiler.report())


def test_partial_http_read_counts_observed_bytes_before_error() -> None:
    handler = _handler(b"abcdef")
    handler.rfile = io.BytesIO(b"abc")
    with PhaseProfiler() as profiler:
        assert profiler._http_root(lambda current: current._load_request_body())(handler) == (
            {},
            "incomplete_request_body",
        )
    data = spans(profiler, "claude-code.transport_unclassified")
    assert data["http_body_read"]["count"] == 2
    assert data["http_body_read"]["work"]["returned_bytes"] == 3
    assert "daemon_json_loads" not in data


def test_actual_scheduler_wait_is_attributed_to_waiter_across_release_thread() -> None:
    from codex_plugin_scanner.guard.daemon.runtime_hook_scheduler import RuntimeHookScheduler

    queued = threading.Event()
    scheduler = RuntimeHookScheduler(active_limit=1, queue_listener=queued.set)
    arguments = dict(harness="claude-code", client_key="one", lane="decision", payload_bytes=10)
    first = scheduler.acquire(**arguments, deadline=time.monotonic() + 5)
    assert first.permit is not None
    with PhaseProfiler() as profiler, ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(
            routed, profiler, lambda: scheduler.acquire(**arguments, deadline=time.monotonic() + 5)
        )
        assert queued.wait(2)
        first.permit.release()
        second = future.result(timeout=2)
        assert second.permit is not None
        second.permit.release()
    data = spans(profiler)
    assert data["scheduler_condition_wait"]["count"] >= 1
    assert data["scheduler_queue_admitted"]["count"] == 1
    assert data["admission_and_queue"]["work"] == {"attempted_payload_bytes": 10, "enqueued_attempts": 1, "admitted": 1}
    assert scheduler.stats()["completed"] == 2


def test_scheduler_expiry_and_admission_rejection_are_both_retained() -> None:
    from codex_plugin_scanner.guard.daemon.runtime_hook_scheduler import RuntimeHookScheduler

    scheduler = RuntimeHookScheduler(active_limit=0)
    arguments = dict(harness="claude-code", client_key="one", lane="decision", payload_bytes=10)
    with PhaseProfiler() as profiler:
        expired = routed(profiler, lambda: scheduler.acquire(**arguments, deadline=time.monotonic() + 0.02))
        rejected = routed(profiler, lambda: scheduler.acquire(**arguments, deadline=time.monotonic() - 1))
    assert expired.permit is rejected.permit is None
    data = spans(profiler)
    assert data["scheduler_queue_unadmitted_until_return"]["count"] == 1
    assert data["admission_and_queue"]["work"]["rejected"] == 2
    assert data["admission_and_queue"]["work"]["never_enqueued_attempts"] == 1
    assert "scheduler_queue_admitted" not in data


def test_real_pool_wait_timeout_retains_none_and_restores_condition(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from codex_plugin_scanner.guard import native_resident_client as client_module

    pool = client_module._PersistentNativeClientPool(executable=tmp_path / "unused", state_dir=tmp_path, environment={})
    monkeypatch.setattr(client_module, "_MAX_PERSISTENT_CLIENTS", 1)
    pool._clients.add(object())
    original = threading.Condition.wait
    with PhaseProfiler() as profiler:
        assert routed(profiler, lambda: pool._lease(deadline_monotonic=time.monotonic() + 0.02)) is None
        unrelated = threading.Condition()
        with unrelated:
            routed(profiler, lambda: unrelated.wait(timeout=0.001))
    assert threading.Condition.wait is original
    data = spans(profiler)
    assert data["client_pool_condition_wait"]["count"] == 1
    assert data["client_pool_lease_inclusive"]["outcomes"] == {"returned_none": 1}
    assert "scheduler_condition_wait" not in data


def _stream(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    from codex_plugin_scanner.guard.native_resident_stream import _PersistentNativeClient

    client = _PersistentNativeClient(executable=tmp_path / "unused", state_dir=tmp_path, environment={})
    client._process = SimpleNamespace(stdin=io.BytesIO(), poll=lambda: None)
    monkeypatch.setattr(client, "_start", lambda: True)
    monkeypatch.setattr(client, "close", lambda: None)
    return client


@pytest.mark.parametrize("mode", ["response", "timeout", "stream_failure", "write_failure"])
def test_real_stream_request_boundaries_keep_transport_failures(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str
) -> None:
    from codex_plugin_scanner.guard import native_resident_stream as stream_module

    client = _stream(tmp_path, monkeypatch)
    if mode == "response":
        client._responses.put_nowait(b"private-response")
    if mode == "stream_failure":
        client._responses.put_nowait(stream_module._StreamFailure())
    if mode == "write_failure":
        monkeypatch.setattr(stream_module, "write_frame", lambda *_args, **_kwargs: False)
    payload = b"private-payload"
    with PhaseProfiler() as profiler:
        result = routed(profiler, lambda: client.request(payload, deadline_monotonic=time.monotonic() + 0.05))
    data = spans(profiler)
    assert data["client_frame_header_pack"]["work"] == {"returned_bytes": 4}
    assert data["client_frame_write"]["work"]["attempted_frame_bytes"] == len(payload) + 4
    assert data["client_stream_exchange_inclusive"]["outcomes"] == (
        {"returned_value": 1} if mode == "response" else {"returned_none": 1}
    )
    if mode == "write_failure":
        assert "completed_frame_bytes" not in data["client_frame_write"]["work"]
        assert data["client_frame_write"]["work"]["partial_or_unwritten_attempts"] == 1
        assert "client_response_wait_inclusive" not in data
    else:
        assert client._process.stdin.getvalue() == struct.pack(">I", len(payload)) + payload
        assert data["client_frame_write"]["work"]["completed_frame_bytes"] == len(payload) + 4
        wait = data["client_response_wait_inclusive"]
        if mode == "response":
            assert result == b"private-response"
            assert wait["work"]["delivered_payload_bytes"] == len(result)
        elif mode == "timeout":
            assert wait["outcomes"] == {"raised": 1}
        else:
            assert wait["work"]["stream_failure_sentinels"] == 1
    assert "private" not in json.dumps(profiler.report())


def test_background_reader_framing_is_not_misattributed_to_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _stream(tmp_path, monkeypatch)
    raw = b"reader-payload"
    process = SimpleNamespace(stdout=io.BytesIO(struct.pack(">I", len(raw)) + raw))
    responses = Queue(maxsize=2)
    original = Queue.get
    with PhaseProfiler() as profiler:
        client._read_responses(process, responses)
        assert responses.get_nowait() == raw
    assert Queue.get is original
    assert set(profiler.report()["by_route"]) == {"unattributed.native_stream_reader"}
    assert spans(profiler, "unattributed.native_stream_reader")["client_frame_header_unpack"]["work"] == {
        "attempted_header_bytes": 4
    }


def test_profiler_global_install_is_exclusive_and_restores_after_setup_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard import native_runtime

    original = native_runtime._validate_binary
    with PhaseProfiler(), pytest.raises(RuntimeError, match="already active"):
        PhaseProfiler().__enter__()
    with monkeypatch.context() as patches:
        patches.setattr(
            phases, "install_io_probes", lambda *_args: (_ for _ in ()).throw(ValueError("synthetic setup failure"))
        )
        with pytest.raises(ValueError, match="synthetic setup"):
            PhaseProfiler().__enter__()
    assert native_runtime._validate_binary is original
    with PhaseProfiler():
        pass


def test_dropped_timing_samples_do_not_drop_failure_counts_or_grow_without_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(phases, "_MAX_TOTAL_SAMPLES", 2)
    monkeypatch.setattr(phases, "_MAX_SERIES", 3)
    profiler = PhaseProfiler()

    def fail() -> None:
        raise ValueError("unrecorded")

    for _ in range(5):
        with pytest.raises(ValueError):
            routed(profiler, lambda: profiler.call(fail, "failure"))
    for number in range(5):
        routed(profiler, lambda number=number: profiler.call(lambda: None, f"extra_{number}"))
    report = profiler.report()
    assert len(profiler._samples) == 3
    assert sum(len(values) for values in profiler._samples.values()) == 2
    assert report["discarded_samples"] > 0
    assert report["discarded_series_updates"] > 0
    assert spans(profiler)["failure"]["outcomes"] == {"raised": 5}
    assert report["all_span_outcomes_including_discarded_series"]["raised"] == 10
    assert spans(profiler)["extra_0"]["timing"] == "not_retained"
    assert "p50_ms" not in spans(profiler)["extra_0"]
    assert report["headline_timing_eligible"] is False


@pytest.mark.parametrize("payload", [None, b""])
def test_rejected_empty_stream_input_preserves_result_without_new_counting_exception(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, payload: object
) -> None:
    client = _stream(tmp_path, monkeypatch)
    assert client.request(payload, deadline_monotonic=time.monotonic() + 1) is None
    with PhaseProfiler() as profiler:
        assert routed(profiler, lambda: client.request(payload, deadline_monotonic=time.monotonic() + 1)) is None
    assert spans(profiler)["client_stream_exchange_inclusive"]["outcomes"] == {"returned_none": 1}
    assert "client_frame_write" not in spans(profiler)


def test_byte_reservation_rejection_keeps_work_without_fake_queue_span() -> None:
    from codex_plugin_scanner.guard.daemon.runtime_hook_scheduler import RuntimeHookScheduler

    scheduler = RuntimeHookScheduler(retained_bytes_limit=3)
    with PhaseProfiler() as profiler:
        reservation, reason = routed(
            profiler, lambda: scheduler.reserve_bytes(payload_bytes=4, deadline=time.monotonic() + 1)
        )
    assert reservation is None
    assert reason == "daemon_hook_queue_bytes"
    data = spans(profiler)
    assert data["byte_admission"]["work"] == {"attempted_payload_bytes": 4, "rejected": 1}
    assert "scheduler_queue_admitted" not in data


def test_actual_http_response_preserves_wire_and_counts_caught_disconnect(monkeypatch: pytest.MonkeyPatch) -> None:
    from codex_plugin_scanner.guard.daemon.server import _GuardDaemonHandler

    handler = object.__new__(_GuardDaemonHandler)
    handler.request_version = "HTTP/1.1"
    handler.requestline = "POST /v1/hooks/claude-code HTTP/1.1"
    handler.wfile = io.BytesIO()
    handler.close_connection = False
    monkeypatch.setattr(handler, "_cors_headers_for_request", lambda **_kwargs: None)
    # Deterministic Date, so complete HTTP wire comparison is meaningful.
    monkeypatch.setattr(handler, "date_time_string", lambda: "Thu, 01 Jan 1970 00:00:00 GMT")
    payload = {"synthetic": "\u00e9"}
    handler._write_json(payload)
    expected = handler.wfile.getvalue()
    handler.wfile = io.BytesIO()
    original = handler.wfile
    with PhaseProfiler() as profiler:
        routed(profiler, lambda: handler._write_json(payload))
    assert handler.wfile is original
    assert handler.wfile.getvalue() == expected
    assert spans(profiler)["http_response_write"]["work"]["written_bytes"] == len(expected)
    assert spans(profiler)["daemon_json_dumps"]["count"] == 1

    class Disconnected:
        def write(self, _data: bytes) -> int:
            raise BrokenPipeError("private peer error")

    handler.wfile = Disconnected()
    with PhaseProfiler() as failed:
        routed(failed, lambda: handler._write_json(payload))
    assert handler.close_connection
    assert spans(failed)["http_response_write"]["outcomes"] == {"raised": 1}
    assert "written_bytes" not in spans(failed)["http_response_write"]["work"]
    assert "private" not in json.dumps(failed.report())


def test_receipt_submission_keeps_dedupe_saturation_and_invalid_attempts(tmp_path: Path) -> None:
    from codex_plugin_scanner.guard.daemon.runtime_hook_evidence_writer import RuntimeHookEvidenceWriter
    from codex_plugin_scanner.guard.store import GuardStore
    from tests.test_native_decision_receipt import _receipt

    writer = RuntimeHookEvidenceWriter(store=GuardStore(tmp_path / "guard-home"), max_records=1)
    try:
        # Hold the real writer queue lock to prevent the background consumer
        # racing the deterministic saturation fixture, not its submit method.
        with writer._condition, PhaseProfiler() as profiler:
            receipt = _receipt()
            assert routed(profiler, lambda: writer.submit_native_decision_receipt(receipt)) is True
            assert routed(profiler, lambda: writer.submit_native_decision_receipt(receipt)) is True
            assert (
                routed(profiler, lambda: writer.submit_native_decision_receipt(_receipt(request_id="request-2")))
                is False
            )
            assert routed(profiler, lambda: writer.submit_native_decision_receipt({})) is False
        data = spans(profiler)
        assert data["receipt_submission"]["outcomes"] == {"returned_true": 2, "returned_false": 2}
        assert data["receipt_record_serialization"]["count"] == 3
        assert data["receipt_record_serialization"]["work"]["returned_bytes"] > 0
        assert data["evidence_json_dumps"]["count"] == 3
        assert "request-2" not in json.dumps(profiler.report())
    finally:
        assert writer.stop(timeout_seconds=2)
