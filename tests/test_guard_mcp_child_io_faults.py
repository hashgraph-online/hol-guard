"""Fault-injection tests for the native MCP child-I/O adapter (RTM-023).

`_NativeMcpChildIo`/`_NativeChildProcess` marshal frames over the resident's
`mcp_stdio_session_*` ops; the resident owns the subprocess, framing, and
teardown. These tests monkeypatch the session seam to inject the failure
modes the relay must fail closed on — transport loss, malformed frames,
timeout, child death — without needing a real spawned child.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.proxy import runtime_mcp
from codex_plugin_scanner.guard.store import GuardStore


@pytest.fixture
def guard_home(tmp_path: Path) -> Path:
    return tmp_path / "guard-home"


@pytest.fixture
def child_io(guard_home):
    return runtime_mcp._NativeMcpChildIo("sess-test", guard_home)


def _recv(result):
    """Return a `mcp_stdio_session_recv_native` stub that yields `result`."""

    def stub(session_id, *, guard_home, timeout_seconds=30.0, **kwargs):
        return result

    return stub


def _send(result):
    def stub(session_id, message, *, guard_home, timeout_seconds=10.0):
        return result

    return stub


# write/send faults -------------------------------------------------------


def test_write_rejects_non_json_frame(child_io, monkeypatch):
    with pytest.raises(RuntimeError, match="non-JSON frame"):
        child_io.write("this is not json\n")


def test_write_raises_on_send_transport_loss(child_io, monkeypatch):
    monkeypatch.setattr(
        runtime_mcp, "mcp_stdio_session_send_native", _send(None)
    )
    with pytest.raises(RuntimeError):
        child_io.write(json.dumps({"jsonrpc": "2.0", "method": "x"}) + "\n")


def test_write_raises_on_send_not_sent_status(child_io, monkeypatch):
    monkeypatch.setattr(
        runtime_mcp,
        "mcp_stdio_session_send_native",
        _send({"status": "rejected"}),
    )
    with pytest.raises(RuntimeError):
        child_io.write(json.dumps({"jsonrpc": "2.0"}) + "\n")


# next_frame/recv faults ---------------------------------------------------


def test_next_frame_transport_loss_surfaces_error(child_io, monkeypatch):
    monkeypatch.setattr(
        runtime_mcp, "mcp_stdio_session_recv_native", _recv(None)
    )
    frame = child_io.next_frame(timeout_seconds=1.0, required=True)
    assert frame is not None
    assert frame.error is not None
    assert frame.line is None


def test_next_frame_event_payload_becomes_line(child_io, monkeypatch):
    payload = {"jsonrpc": "2.0", "result": {"tools": []}}
    monkeypatch.setattr(
        runtime_mcp,
        "mcp_stdio_session_recv_native",
        _recv({"status": "event", "payload": payload}),
    )
    frame = child_io.next_frame(timeout_seconds=1.0, required=True)
    assert frame.error is None
    assert frame.line is not None
    assert json.loads(frame.line) == payload


def test_next_frame_child_exit_records_code_and_eof(child_io, monkeypatch):
    monkeypatch.setattr(
        runtime_mcp,
        "mcp_stdio_session_recv_native",
        _recv({"status": "exited", "exit_code": 7}),
    )
    frame = child_io.next_frame(timeout_seconds=1.0, required=True)
    assert frame.error is None
    assert frame.line is None  # EOF frame
    assert child_io.exit_code == 7


def test_next_frame_eof_status(child_io, monkeypatch):
    monkeypatch.setattr(
        runtime_mcp,
        "mcp_stdio_session_recv_native",
        _recv({"status": "eof"}),
    )
    frame = child_io.next_frame(timeout_seconds=1.0, required=False)
    assert frame is not None
    assert frame.line is None
    assert frame.error is None


def test_next_frame_timeout_required_raises_io_timeout(child_io, monkeypatch):
    monkeypatch.setattr(
        runtime_mcp,
        "mcp_stdio_session_recv_native",
        _recv({"status": "timeout"}),
    )
    frame = child_io.next_frame(timeout_seconds=2.0, required=True)
    assert isinstance(frame.error, runtime_mcp.ProxyIoTimeoutError)


def test_next_frame_timeout_not_required_returns_none(child_io, monkeypatch):
    monkeypatch.setattr(
        runtime_mcp,
        "mcp_stdio_session_recv_native",
        _recv({"status": "timeout"}),
    )
    frame = child_io.next_frame(timeout_seconds=2.0, required=False)
    assert frame is None


def test_next_frame_error_status_fails_closed(child_io, monkeypatch):
    monkeypatch.setattr(
        runtime_mcp,
        "mcp_stdio_session_recv_native",
        _recv({"status": "error", "payload": "frame-too-large"}),
    )
    frame = child_io.next_frame(timeout_seconds=1.0, required=False)
    assert frame is not None
    assert frame.error is not None
    assert "frame-too-large" in str(frame.error)


def test_pending_injection_seam_delivered_first(child_io, monkeypatch):
    """The `_pending` queue is the sanctioned injection seam — locally queued
    frames are delivered before any resident recv."""
    child_io._pending.append(json.dumps({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"}) + "\n")
    monkeypatch.setattr(
        runtime_mcp,
        "mcp_stdio_session_recv_native",
        _recv({"status": "timeout"}),  # would block if reached
    )
    frame = child_io.next_frame(timeout_seconds=0.0, required=False)
    assert frame is not None
    assert "list_changed" in frame.line


# malformed / out-of-order frames -------------------------------------------


def test_malformed_event_payload_not_dict_still_frames(child_io, monkeypatch):
    """A non-dict event payload is serialized verbatim — the downstream JSON
    parser owns malformed-frame rejection, not the transport."""
    monkeypatch.setattr(
        runtime_mcp,
        "mcp_stdio_session_recv_native",
        _recv({"status": "event", "payload": [1, 2, 3]}),
    )
    frame = child_io.next_frame(timeout_seconds=1.0, required=False)
    assert frame is not None
    assert json.loads(frame.line) == [1, 2, 3]


def test_exit_code_bool_not_treated_as_int(child_io, monkeypatch):
    """`True` is a bool, not an int — must not set exit_code."""
    monkeypatch.setattr(
        runtime_mcp,
        "mcp_stdio_session_recv_native",
        _recv({"status": "exited", "exit_code": True}),
    )
    frame = child_io.next_frame(timeout_seconds=1.0, required=False)
    assert child_io.exit_code is None  # bool rejected
    assert frame.line is None


# _NativeChildProcess lifecycle ---------------------------------------------


def _open_result(status="opened"):
    return {"status": status}


def test_native_process_open_not_opened_is_terminal(guard_home, monkeypatch):
    """`status != "opened"` never falls back to a Python subprocess."""
    monkeypatch.setattr(
        runtime_mcp,
        "mcp_stdio_session_open_native",
        lambda *a, **k: _open_result("rejected"),
    )
    monkeypatch.setattr(
        runtime_mcp, "mcp_stdio_session_close_native", lambda *a, **k: None
    )
    monkeypatch.setattr(
        runtime_mcp,
        "resolved_runtime_launch_executable",
        lambda _identity: "/bin/echo",
    )

    proxy = runtime_mcp.CodexMcpGuardProxy(
        server_name="test-server",
        command=["/bin/echo", "hello"],
        context=runtime_mcp.HarnessContext(
            home_dir=guard_home,
            workspace_dir=guard_home,
            guard_home=guard_home,
        ),
        store=GuardStore(guard_home),
        config=runtime_mcp.GuardConfig(guard_home=guard_home, workspace=guard_home),
        source_scope="test",
        config_path="codex.json",
    )
    # The identity check reads this attribute; `_prepare_launch` normally sets
    # it, so stubbing `_prepare_launch` requires seeding it directly.
    proxy._active_runtime_launch_identity = {"executable": "/bin/echo"}
    monkeypatch.setattr(proxy, "_prepare_launch", lambda: ({}, {}, {}))

    def fail_on_subprocess_fallback(*args, **kwargs):
        raise AssertionError("Python subprocess fallback")

    monkeypatch.setattr(
        subprocess, "Popen", fail_on_subprocess_fallback
    )

    with pytest.raises(RuntimeError, match="native MCP session open failed"):
        proxy._start_process()
