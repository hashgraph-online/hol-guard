"""Native Codex binding capture client: marker gate, transport and writer queue."""

from __future__ import annotations

import hashlib
import json
import threading
import time
from collections.abc import Callable
from contextlib import contextmanager
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import native_codex_binding_capture as capture
from codex_plugin_scanner.guard.daemon import hook_worker_native_review
from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.native_codex_binding_capture import CodexBindingCaptureWriter
from codex_plugin_scanner.guard.native_decision_receipt import canonical_receipt_bytes
from codex_plugin_scanner.guard.store import GuardStore


def _enable(guard_home: Path) -> None:
    directory = guard_home / "diagnostics"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "codex-binding-capture.v2.json").write_text("{}", encoding="utf-8")


def _valid_native_receipt() -> dict[str, object]:
    receipt: dict[str, object] = {
        "schema": "guard-native-hook-decision-receipt.v1",
        "version": 1,
        "authority": "rust",
        "decision_id": "0" * 64,
        "request_id": "sha256:request-1",
        "request_digest": "a" * 64,
        "harness": "codex",
        "event_name": "PreToolUse",
        "payload_kind": "inline",
        "policy_generation": 1,
        "policy_digest": None,
        "rule_digest": None,
        "runtime_identity": None,
        "decision": "allow",
        "model_output_action": "not_applicable",
        "policy_action": "allow",
        "observed_policy_action": None,
        "reason_code": "native_allow",
        "workspace_bound": False,
        "source_ref_external_allowed": False,
        "reviewed_output_sha256": None,
        "observe_mode": False,
        "deadline_budget_ms": 100,
    }
    receipt["decision_id"] = hashlib.sha256(canonical_receipt_bytes(receipt)).hexdigest()
    return receipt


def _finish(writer: CodexBindingCaptureWriter, release: threading.Event) -> None:
    writer.stop_capture()
    release.set()
    writer._thread.join(timeout=2.0)
    assert not writer._thread.is_alive()


def _patch_exchange(monkeypatch: pytest.MonkeyPatch, handler: Callable[[Path, dict[str, object]], object]) -> None:
    monkeypatch.setattr(capture, "_exchange", handler)


def test_without_marker_no_runtime_traffic(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[object] = []
    _patch_exchange(monkeypatch, lambda *args: calls.append(args))
    assert not capture.record_bridge_ingress(guard_home=tmp_path, raw_payload="{}", event_name="PreToolUse")
    assert not capture.record_native_worker(
        guard_home=tmp_path, payload={}, harness="codex", event_name="PreToolUse", receipt={}
    )
    assert calls == []


def test_bridge_forwards_bounded_text_and_reports_runtime_answer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _enable(tmp_path)
    monkeypatch.setattr(capture, "_bridge_resident_status", lambda _home: object())
    seen: list[dict[str, object]] = []

    def answer(_home: Path, command: dict[str, object], **_kwargs: object) -> object:
        seen.append(command)
        return {"recorded": True}

    _patch_exchange(monkeypatch, answer)
    assert capture.record_bridge_ingress(
        guard_home=tmp_path, raw_payload=b'{"a":1}', forwarded_payload='{"a":2}', event_name="PreToolUse"
    )
    assert seen == [
        {
            "kind": "bridge",
            "raw_payload": '{"a":1}',
            "forwarded_payload": '{"a":2}',
            "event_name": "PreToolUse",
            "harness": "codex",
        }
    ]
    assert not capture.record_bridge_ingress(guard_home=tmp_path, raw_payload=b"\xff", event_name="PreToolUse")
    assert not capture.record_bridge_ingress(guard_home=tmp_path, raw_payload="\ud800", event_name="PreToolUse")
    assert not capture.record_bridge_ingress(guard_home=tmp_path, raw_payload="x" * 65537, event_name="PreToolUse")
    assert not capture.record_bridge_ingress(
        guard_home=tmp_path, raw_payload="{}", event_name="PreToolUse", harness="claude"
    )
    assert len(seen) == 1
    _patch_exchange(monkeypatch, lambda *_args, **_kwargs: {"recorded": False})
    assert not capture.record_bridge_ingress(guard_home=tmp_path, raw_payload="{}", event_name="PreToolUse")
    _patch_exchange(monkeypatch, lambda *_args, **_kwargs: None)
    assert not capture.record_bridge_ingress(guard_home=tmp_path, raw_payload="{}", event_name="PreToolUse")


def test_exchange_rejects_unbound_or_failed_runtime_replies(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(capture, "ensure_resident_prerequisite", lambda _home: True)
    replies: list[dict[str, object] | None] = []

    def resident(**kwargs: object) -> dict[str, object] | None:
        request = kwargs["request"]
        assert isinstance(request, dict)
        assert kwargs["operation"] == "codex_binding_capture"
        assert kwargs["required_feature"] == capture.BINDING_CAPTURE_FEATURE
        assert kwargs["record_resilience"] is False
        reply = replies.pop(0)
        if reply is not None and reply.get("request_id") == "echo":
            reply = {**reply, "request_id": request["request_id"]}
        if reply is not None and reply.get("request_sha256") == "echo":
            reply = {**reply, "request_sha256": "sha256:" + capture._canonical_request_sha256(request)}
        return reply

    monkeypatch.setattr(capture, "_resident_request", resident)
    good = {
        "schema": "guard-codex-binding-capture-result.v1",
        "request_id": "echo",
        "request_sha256": "echo",
        "status": "ok",
        "code": "ok",
        "payload": {"recorded": True},
    }
    replies.extend([good, {**good, "request_sha256": "sha256:" + "0" * 64}, {**good, "status": "error"}, None])
    command: dict[str, object] = {"kind": "bridge"}
    assert capture._exchange(tmp_path, command) == {"recorded": True}
    assert capture._exchange(tmp_path, command) is None
    assert capture._exchange(tmp_path, command) is None
    assert capture._exchange(tmp_path, command) is None


def test_init_and_join_keep_the_key_in_the_runtime(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[dict[str, object]] = []

    def answer(_home: Path, command: dict[str, object]) -> object:
        seen.append(command)
        if command["kind"] == "init_marker":
            return {"session": {"run_id": "run-1", "key_id": "k" * 32}}
        return {"result": {"status": "bound"}}

    _patch_exchange(monkeypatch, answer)
    assert capture.initialize_capture_marker(tmp_path, run_id="run-1", expires_at=1) == {
        "run_id": "run-1",
        "key_id": "k" * 32,
    }
    assert capture.join_binding_records(tmp_path, [{"a": 1}, "x"]) == {"status": "bound"}
    assert seen[1] == {"kind": "join", "records": ['{"a":1}', '"x"']}
    assert capture.join_binding_records(tmp_path, [float("nan")]) is None


def test_optional_capture_start_failure_does_not_prevent_daemon_start(monkeypatch: pytest.MonkeyPatch) -> None:
    def failed_start(_self: threading.Thread) -> None:
        raise RuntimeError("thread unavailable")

    monkeypatch.setattr(threading.Thread, "start", failed_start)
    assert capture.start_codex_binding_capture_writer() is None


@pytest.mark.parametrize("failure", [OSError, TypeError])
def test_capture_keeps_expected_io_failures_optional_and_surfaces_programming_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: type[Exception]
) -> None:
    _enable(tmp_path)
    attempted = threading.Event()
    completed = threading.Event()
    unexpected = []
    calls = []

    def exchange(home: Path, command: dict[str, object]) -> object:
        calls.append((home, command))
        if len(calls) == 1:
            attempted.set()
            raise failure("synthetic capture failure")
        completed.set()
        return {"recorded": True}

    def capture_thread_error(args: threading.ExceptHookArgs) -> None:
        unexpected.append(args.exc_type)
        completed.set()

    _patch_exchange(monkeypatch, exchange)
    monkeypatch.setattr(threading, "excepthook", capture_thread_error)
    writer = CodexBindingCaptureWriter()
    kwargs = {"guard_home": tmp_path, "payload": {}, "receipt": _valid_native_receipt()}
    try:
        assert writer.submit_native_capture(**kwargs)
        assert attempted.wait(2.0)
        if failure is OSError:
            assert writer.submit_native_capture(**kwargs)
        assert completed.wait(2.0)
    finally:
        _finish(writer, completed)
    assert unexpected == ([] if failure is OSError else [TypeError])
    assert len(calls) == (2 if failure is OSError else 1)


@pytest.mark.parametrize("valid_receipt", [True, False])
def test_native_allow_does_not_wait_for_optional_capture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, valid_receipt: bool
) -> None:
    _enable(tmp_path / "guard")
    entered = threading.Event()
    release = threading.Event()
    inside_fence = [False]
    capture_fences = []

    def blocked(_home: Path, _command: dict[str, object]) -> object:
        capture_fences.append(inside_fence[0])
        entered.set()
        assert release.wait(30.0)
        return {"recorded": True}

    @contextmanager
    def fence(**_kwargs: object):
        inside_fence[0] = True
        try:
            yield True
        finally:
            inside_fence[0] = False

    _patch_exchange(monkeypatch, blocked)
    monkeypatch.setattr(hook_worker_native_review, "native_review_fence", fence)
    writer = CodexBindingCaptureWriter()
    worker = HookWorker(
        store=GuardStore(tmp_path / "guard"),
        capture_writer=writer,
        wait_for_native_policy=False,
        publish_native_policy=False,
    )
    monkeypatch.setattr(worker, "_native_policy_snapshot", lambda *_args, **_kwargs: {"mode": "enforce"})
    receipt = _valid_native_receipt() if valid_receipt else {"authority": "python"}
    monkeypatch.setattr(
        worker,
        "_review_raw_hook_native",
        lambda **_kwargs: {
            "harness": "codex",
            "event_name": "PreToolUse",
            "receipt": receipt,
            "result": {
                "authority": "rust",
                "decision": "allow",
                "minimum_action": "allow",
                "policy_action": "allow",
                "reason_code": "native_exact_safe_command",
                "reason": "Bounded command.",
                "explicitly_benign": True,
                "command_model": {"normalized_text": "pwd"},
            },
            "harness_response": {
                "policy_action": "allow",
                "hookSpecificOutput": {"permissionDecision": "allow"},
            },
        },
    )
    try:
        response = worker._review_native_edge(
            payload={"hook_event_name": "PreToolUse", "tool_input": {"command": "pwd"}},
            harness="codex",
            event_name="PreToolUse",
            default_harness="codex",
            home_dir=tmp_path / "home",
            guard_home=tmp_path / "guard",
            workspace=None,
            deadline=time.monotonic() + 5.0,
        )
        assert response["policy_action"] == "allow"
        assert response["hookSpecificOutput"]["permissionDecision"] == "allow"
        assert not release.is_set()
        if valid_receipt:
            assert entered.wait(2.0)
            assert capture_fences == [False]
        else:
            assert not writer._pending
            assert not entered.is_set()
    finally:
        _finish(writer, release)
        worker.close()


@pytest.mark.parametrize("stop_contended", [False, True])
def test_capture_queue_drops_when_full_or_contended_and_stops_without_drain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stop_contended: bool
) -> None:
    _enable(tmp_path)
    entered = threading.Event()
    release = threading.Event()
    recorded = []

    def blocked(_home: Path, command: dict[str, object]) -> object:
        recorded.append(command)
        entered.set()
        assert release.wait(30.0)
        return {"recorded": True}

    _patch_exchange(monkeypatch, blocked)
    writer = CodexBindingCaptureWriter()
    kwargs = {"guard_home": tmp_path, "payload": {"hook_event_name": "PreToolUse"}, "receipt": _valid_native_receipt()}
    try:
        assert writer.submit_native_capture(**kwargs)
        assert entered.wait(2.0)
        for _ in range(capture._QUEUE_LIMIT):
            assert writer.submit_native_capture(**kwargs)
        assert not writer.submit_native_capture(**kwargs)
        with writer._lock:
            assert not writer.submit_native_capture(**kwargs)
        if stop_contended:
            with writer._lock:
                writer.stop_capture()
            assert len(writer._pending) == capture._QUEUE_LIMIT
        else:
            writer.stop_capture()
            assert not writer._pending
        assert not writer.submit_native_capture(**kwargs)
        assert writer._thread.is_alive()
    finally:
        _finish(writer, release)
    assert len(recorded) == 1


def test_capture_queue_keeps_bounded_immutable_snapshots(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _enable(tmp_path)
    entered = threading.Event()
    release = threading.Event()
    finished = threading.Event()
    recorded = []

    def exchange(_home: Path, command: dict[str, object]) -> object:
        recorded.append(command)
        if len(recorded) == 1:
            entered.set()
            assert release.wait(30.0)
        else:
            finished.set()
        return {"recorded": True}

    _patch_exchange(monkeypatch, exchange)
    writer = CodexBindingCaptureWriter()
    try:
        assert writer.submit_native_capture(guard_home=tmp_path, payload={}, receipt=_valid_native_receipt())
        assert entered.wait(2.0)
        payload = {"tool_input": {"command": "pwd"}}
        receipt = _valid_native_receipt()
        assert writer.submit_native_capture(guard_home=tmp_path, payload=payload, receipt=receipt)
        payload["tool_input"]["command"] = "changed"
        receipt["reason_code"] = "changed"
        assert not writer.submit_native_capture(
            guard_home=tmp_path, payload={"oversized": "x" * 65537}, receipt=receipt
        )
        release.set()
        assert finished.wait(2.0)
        assert json.loads(str(recorded[1]["payload"])) == {"tool_input": {"command": "pwd"}}
        assert json.loads(str(recorded[1]["receipt"]))["reason_code"] == "native_allow"
    finally:
        _finish(writer, release)


def test_bridge_skips_when_no_idle_resident(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _enable(tmp_path)
    calls: list[object] = []
    _patch_exchange(monkeypatch, lambda *args, **kwargs: calls.append((args, kwargs)))
    monkeypatch.setattr(capture, "_bridge_resident_status", lambda _home: None)
    assert not capture.record_bridge_ingress(guard_home=tmp_path, raw_payload="{}", event_name="PreToolUse")
    assert calls == []


def test_unicode_payload_is_bounded_by_utf8_bytes(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _enable(tmp_path)
    seen: list[dict[str, object]] = []

    def answer(_home: Path, command: dict[str, object]) -> object:
        seen.append(command)
        return {"recorded": True}

    _patch_exchange(monkeypatch, answer)
    assert capture.record_native_worker(
        guard_home=tmp_path,
        payload={"text": "é" * 10922},
        harness="codex",
        event_name="PreToolUse",
        receipt={"ok": True},
    )
    payload = str(seen[0]["payload"])
    assert "\\u00e9" not in payload
    assert len(payload.encode("utf-8")) <= capture._MAX_TEXT_BYTES


def test_join_serializes_only_enough_records_to_show_the_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[dict[str, object]] = []

    def answer(_home: Path, command: dict[str, object]) -> object:
        seen.append(command)
        return {"result": {"status": "ambiguous"}}

    _patch_exchange(monkeypatch, answer)
    records: list[object] = [{"n": index} for index in range(400)]
    assert capture.join_binding_records(tmp_path, records) == {"status": "ambiguous"}
    encoded = seen[0]["records"]
    assert isinstance(encoded, list)
    assert len(encoded) == capture._JOIN_PROBE_RECORDS


def test_join_forwards_a_record_over_the_capture_ceiling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[dict[str, object]] = []

    def answer(_home: Path, command: dict[str, object]) -> object:
        seen.append(command)
        return {"result": {"status": "invalid"}}

    _patch_exchange(monkeypatch, answer)
    bulky = {"text": "a" * (capture._MAX_TEXT_BYTES + 1)}
    assert capture.join_binding_records(tmp_path, [bulky, {"n": 1}]) == {"status": "invalid"}
    encoded = seen[0]["records"]
    assert isinstance(encoded, list)
    assert len(encoded) == 1
    assert len(encoded[0].encode("utf-8")) > capture._MAX_TEXT_BYTES


def test_join_rejects_a_record_that_cannot_fit_the_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[object] = []
    _patch_exchange(monkeypatch, lambda *args: calls.append(args))
    huge = {"text": "b" * capture._JOIN_RECORD_BYTES}
    assert capture.join_binding_records(tmp_path, [huge]) is None
    assert calls == []


def test_capture_timeouts_do_not_touch_enforcement_resilience(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from types import SimpleNamespace

    from codex_plugin_scanner.guard import native_execution

    recorded: list[str] = []
    monkeypatch.setattr(
        native_execution,
        "native_record_resident_failure",
        lambda *_args, **_kwargs: recorded.append("failure"),
    )
    monkeypatch.setattr(
        native_execution,
        "native_record_resident_success",
        lambda *_args, **_kwargs: recorded.append("success"),
    )
    monkeypatch.setattr(native_execution, "native_resident_client_request", lambda **_kwargs: None)
    status = SimpleNamespace(
        available=True,
        compatible=True,
        identity=SimpleNamespace(sha256="ab", path=tmp_path / "runtime"),
        capabilities=SimpleNamespace(features={"resident-protocol-v2", capture.BINDING_CAPTURE_FEATURE}),
    )
    for _ in range(3):
        assert (
            native_execution._resident_request(
                operation="codex_binding_capture",
                request={},
                guard_home=tmp_path,
                timeout_seconds=0.2,
                required_feature=capture.BINDING_CAPTURE_FEATURE,
                record_resilience=False,
                status=status,
            )
            is None
        )
    assert recorded == []
    assert (
        native_execution._resident_request(
            operation="codex_binding_capture",
            request={},
            guard_home=tmp_path,
            timeout_seconds=0.2,
            required_feature=capture.BINDING_CAPTURE_FEATURE,
            status=status,
        )
        is None
    )
    assert recorded == ["failure"]


def test_writer_skips_queue_without_marker(tmp_path: Path) -> None:
    writer = CodexBindingCaptureWriter()
    try:
        assert not writer.submit_native_capture(guard_home=tmp_path, payload={}, receipt=_valid_native_receipt())
    finally:
        writer.stop_capture()
