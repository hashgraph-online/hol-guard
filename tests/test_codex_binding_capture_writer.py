"""Optional persistence cannot hold a native review or borrow its deadline."""

from __future__ import annotations

import json
import threading
import time
from contextlib import contextmanager
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import codex_binding_capture_writer as writer_module
from codex_plugin_scanner.guard.codex_binding_capture import join_binding_records, record_bridge_ingress
from codex_plugin_scanner.guard.codex_binding_capture_writer import CodexBindingCaptureWriter
from codex_plugin_scanner.guard.daemon import hook_worker_native
from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker
from codex_plugin_scanner.guard.store import GuardStore
from tests.codex_binding_capture_support import _enable_capture, _rows, _session, _valid_native_receipt


def _finish(writer: CodexBindingCaptureWriter, release: threading.Event) -> None:
    writer.stop_capture()
    release.set()
    writer._thread.join(timeout=2.0)
    assert not writer._thread.is_alive()


def test_optional_capture_start_failure_does_not_prevent_daemon_start(monkeypatch: pytest.MonkeyPatch) -> None:
    def failed_start(_self: threading.Thread) -> None:
        raise RuntimeError("thread unavailable")

    monkeypatch.setattr(threading.Thread, "start", failed_start)
    assert writer_module.start_codex_binding_capture_writer() is None


@pytest.mark.parametrize("failure", [OSError, TypeError])
def test_capture_keeps_expected_io_failures_optional_and_surfaces_programming_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: type[Exception]
) -> None:
    attempted = threading.Event()
    completed = threading.Event()
    unexpected = []
    calls = []

    def record(**_kwargs: object) -> bool:
        calls.append(_kwargs)
        if len(calls) == 1:
            attempted.set()
            raise failure("synthetic capture failure")
        completed.set()
        return True

    def capture_thread_error(args: threading.ExceptHookArgs) -> None:
        unexpected.append(args.exc_type)
        completed.set()

    monkeypatch.setattr(writer_module, "record_native_worker", record)
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
    entered = threading.Event()
    release = threading.Event()
    inside_fence = [False]
    capture_fences = []

    def blocked_record(**_kwargs: object) -> bool:
        capture_fences.append(inside_fence[0])
        entered.set()
        assert release.wait(30.0)
        return True

    @contextmanager
    def fence(**_kwargs: object):
        inside_fence[0] = True
        try:
            yield True
        finally:
            inside_fence[0] = False

    monkeypatch.setattr(writer_module, "record_native_worker", blocked_record)
    monkeypatch.setattr(hook_worker_native, "native_review_fence", fence)
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
    entered = threading.Event()
    release = threading.Event()
    recorded = []

    def blocked_record(**_kwargs: object) -> bool:
        recorded.append(_kwargs)
        entered.set()
        assert release.wait(30.0)
        return True

    monkeypatch.setattr(writer_module, "record_native_worker", blocked_record)
    writer = CodexBindingCaptureWriter()
    kwargs = {"guard_home": tmp_path, "payload": {"hook_event_name": "PreToolUse"}, "receipt": _valid_native_receipt()}
    try:
        assert writer.submit_native_capture(**kwargs)
        assert entered.wait(2.0)
        for _ in range(writer_module._QUEUE_LIMIT):
            assert writer.submit_native_capture(**kwargs)
        assert not writer.submit_native_capture(**kwargs)
        with writer._lock:
            assert not writer.submit_native_capture(**kwargs)
        if stop_contended:
            with writer._lock:
                writer.stop_capture()
            assert len(writer._pending) == writer_module._QUEUE_LIMIT
        else:
            writer.stop_capture()
            assert not writer._pending
        assert not writer.submit_native_capture(**kwargs)
        assert writer._thread.is_alive()
    finally:
        _finish(writer, release)
    assert len(recorded) == 1


def test_capture_queue_keeps_bounded_immutable_snapshots(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    entered = threading.Event()
    release = threading.Event()
    finished = threading.Event()
    recorded = []

    def record(**kwargs: object) -> bool:
        recorded.append(kwargs)
        if len(recorded) == 1:
            entered.set()
            assert release.wait(30.0)
        else:
            finished.set()
        return True

    monkeypatch.setattr(writer_module, "record_native_worker", record)
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
        assert recorded[1]["payload"] == {"tool_input": {"command": "pwd"}}
        assert recorded[1]["receipt"]["reason_code"] == "native_allow"
    finally:
        _finish(writer, release)


@pytest.mark.parametrize("enabled", [True, False])
def test_queued_capture_keeps_private_marker_and_sealed_join_contract(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, enabled: bool
) -> None:
    guard_home = tmp_path / "guard-home"
    directory = _enable_capture(guard_home) if enabled else guard_home / "diagnostics"
    payload = {"hook_event_name": "PreToolUse", "tool_use_id": "queued-call"}
    if enabled:
        assert record_bridge_ingress(guard_home=guard_home, raw_payload=json.dumps(payload), event_name="PreToolUse")
    finished = threading.Event()
    results = []
    record_native = writer_module.record_native_worker

    def record(**kwargs: object) -> bool:
        result = record_native(**kwargs)
        results.append(result)
        finished.set()
        return result

    monkeypatch.setattr(writer_module, "record_native_worker", record)
    writer = CodexBindingCaptureWriter()
    try:
        assert writer.submit_native_capture(guard_home=guard_home, payload=payload, receipt=_valid_native_receipt())
        assert finished.wait(2.0)
        assert results == [enabled]
        if enabled:
            rows = _rows(directory)
            assert len(rows) == 2
            assert "receipt" not in rows[1]
            assert "decision_id" not in rows[1]
            assert join_binding_records(rows, capture_session=_session(guard_home))["status"] == "bound"
        else:
            assert not directory.exists()
    finally:
        _finish(writer, finished)
