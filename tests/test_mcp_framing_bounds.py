"""Real pipe and multiplexing regressions for bounded MCP transport."""

from __future__ import annotations

import io
import json
import os
import queue
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from types import SimpleNamespace
from typing import cast

import pytest

from codex_plugin_scanner.guard.config import GuardConfig
from codex_plugin_scanner.guard.proxy import framing, runtime_mcp
from codex_plugin_scanner.guard.proxy.runtime_mcp import RuntimeMcpGuardProxy, _ChildOutputFrame
from codex_plugin_scanner.guard.proxy.stdio import StdioGuardProxy, _readline_with_timeout
from codex_plugin_scanner.guard.proxy.tool_catalog import ToolCatalog


@contextmanager
def pipe():
    reader_fd, writer_fd = os.pipe()
    reader = os.fdopen(reader_fd, "r", encoding="utf-8")
    writer = os.fdopen(writer_fd, "w", encoding="utf-8")
    try:
        yield reader, writer
    finally:
        framing.retire_reader(reader)
        writer.close()
        reader.close()


def proxy(timeout=0.2):
    instance = RuntimeMcpGuardProxy.__new__(RuntimeMcpGuardProxy)
    instance.config = cast(GuardConfig, cast(object, SimpleNamespace(approval_wait_timeout_seconds=timeout)))
    instance.harness = "fixture"
    instance.server_name = "fixture"
    instance._buffered_child_responses = {}
    instance._buffered_client_responses = {}
    instance._child_output_queue = None
    instance._active_child_stdout = None
    instance._active_process = None
    instance._child_output_stop = threading.Event()
    instance._io_lifecycle_lock = threading.RLock()
    instance._io_failure = None
    instance._tool_catalog = ToolCatalog()
    instance._tool_catalog_generation = 0
    instance._tool_catalog_state = "unobserved"
    instance._tool_catalog_pending = None
    instance._tool_catalog_expected_cursor = None
    instance._tool_catalog_inflight = False
    instance._tool_catalog_inflight_cursor = None
    return instance


def test_partial_ready_pipe_never_enters_a_blocking_readline():
    with pipe() as (reader, writer):
        os.write(writer.fileno(), b'{"id":1')
        started = time.monotonic()
        with pytest.raises(framing.ProxyIoTimeoutError):
            _readline_with_timeout(reader, 0.03, source="approval", allow_background_wait=False)
        assert time.monotonic() - started < 0.5
        os.write(writer.fileno(), b'}\n{"id":2}\n')
        assert _readline_with_timeout(reader, 0.1, source="approval") == '{"id":1}\n'
        # A prefetched next line is visible even when the pipe is now empty.
        assert _readline_with_timeout(reader, 0, source="approval") == '{"id":2}\n'


def test_utf8_codepoint_split_across_quiet_polls_is_preserved():
    with pipe() as (reader, writer):
        os.write(writer.fileno(), b'{"value":"\xc3')
        with pytest.raises(framing.ProxyIoTimeoutError):
            _readline_with_timeout(reader, 0.02, source="child")
        os.write(writer.fileno(), b'\xa9"}\n')
        assert json.loads(_readline_with_timeout(reader, 0.1, source="child")) == {"value": "é"}


@pytest.mark.parametrize("windows_worker", [False, True])
def test_partial_frame_has_a_deadline_even_without_an_idle_deadline(monkeypatch, windows_worker):
    monkeypatch.setattr(framing, "FRAME_ASSEMBLY_SECONDS", 0.03)
    if windows_worker:
        monkeypatch.setattr(
            framing,
            "os",
            SimpleNamespace(name="nt", read=os.read, dup=os.dup, close=os.close, set_blocking=os.set_blocking),
        )
    with pipe() as (reader, writer):
        os.write(writer.fileno(), b'{"partial":')
        started = time.monotonic()
        with pytest.raises(framing.ProxyIoLimitError, match="frame_assembly_deadline"):
            _readline_with_timeout(reader, None, source="client_input")
        assert time.monotonic() - started < 0.5


@pytest.mark.parametrize("content,reason", [(b"x" * 129, "line_bytes_limit"), (b'"\xff"\n', "invalid_utf8")])
def test_invalid_pipe_frame_is_terminal(monkeypatch, content, reason):
    monkeypatch.setattr(framing, "MAX_LINE_BYTES", 128)
    with pipe() as (reader, writer):
        os.write(writer.fileno(), content)
        with pytest.raises(framing.ProxyIoLimitError, match=reason):
            _readline_with_timeout(reader, 0.1, source="child")
        with pytest.raises(framing.ProxyIoLimitError, match=reason):
            _readline_with_timeout(reader, 0.1, source="child")


def test_exact_byte_limit_accepts_complete_line(monkeypatch):
    monkeypatch.setattr(framing, "MAX_LINE_BYTES", 128)
    with pipe() as (reader, writer):
        os.write(writer.fileno(), b"x" * 127 + b"\n")
        assert len(_readline_with_timeout(reader, 0.1, source="child")) == 128


def test_eof_midframe_is_never_a_successful_message():
    with pipe() as (reader, writer):
        os.write(writer.fileno(), b'{"id":1}')
        writer.close()
        with pytest.raises(framing.ProxyIoLimitError, match="unterminated_frame"):
            _readline_with_timeout(reader, 0.1, source="child")


@pytest.mark.skipif(os.name == "nt", reason="POSIX pipe saturation; Windows worker is tested separately")
def test_full_pipe_write_deadline_poisoning_prevents_replay():
    with pipe() as (reader, writer):
        os.set_blocking(writer.fileno(), False)
        while True:
            try:
                os.write(writer.fileno(), b"x" * 4096)
            except BlockingIOError:
                break
        os.set_blocking(writer.fileno(), True)
        started = time.monotonic()
        with pytest.raises(framing.ProxyIoTimeoutError):
            framing.write_message(writer, {"method": "tools/call", "id": 1}, timeout_seconds=0.03, source="child_write")
        assert time.monotonic() - started < 0.5
        os.read(reader.fileno(), 65536)
        with pytest.raises(framing.ProxyIoLimitError, match="stream_retired"):
            framing.write_message(writer, {"method": "tools/call", "id": 1}, timeout_seconds=1, source="child_write")


def test_stalled_generic_writer_has_one_worker_and_no_retry():
    entered = threading.Event()
    release = threading.Event()

    class SlowWriter:
        calls = 0

        def write(self, _text):
            self.calls += 1
            entered.set()
            release.wait(1)

        def flush(self):
            pass

    writer = SlowWriter()
    try:
        with pytest.raises(framing.ProxyIoTimeoutError):
            framing.write_message(writer, {"id": 1}, timeout_seconds=0.02, source="child_write")
        assert entered.is_set()
        with pytest.raises(framing.ProxyIoLimitError, match="stream_retired"):
            framing.write_message(writer, {"id": 1}, timeout_seconds=0.02, source="child_write")
        assert writer.calls == 1
    finally:
        release.set()


def test_generic_reader_timeout_reuses_one_outstanding_read():
    release = threading.Event()

    class SlowReader:
        calls = 0

        def readline(self, size):
            assert size == framing.MAX_LINE_BYTES + 1
            self.calls += 1
            release.wait(1)
            return '{"id":1}\n'

    reader = SlowReader()
    try:
        for _ in range(3):
            with pytest.raises(framing.ProxyIoTimeoutError):
                _readline_with_timeout(reader, 0.01, source="child")
        assert reader.calls == 1
        release.set()
        assert _readline_with_timeout(reader, 0.2, source="child") == '{"id":1}\n'
    finally:
        release.set()
        framing.retire_reader(reader)


def test_queue_capacity_and_bytes_are_both_enforced(monkeypatch):
    monkeypatch.setattr(framing, "MAX_QUEUED_FRAMES", 2)
    monkeypatch.setattr(framing, "MAX_QUEUED_BYTES", 5)
    messages = framing.ByteBoundedQueue(len)
    messages.put("aaa")
    with pytest.raises(framing.ProxyIoLimitError, match="queue_bytes_limit"):
        messages.put("bbb")
    assert messages.bytes_queued == 3
    assert messages.get() == "aaa"
    assert messages.bytes_queued == 0
    messages.put("a")
    messages.put("b")
    with pytest.raises(queue.Full):
        messages.put("c")


def test_actual_child_overflow_is_bounded_and_quarantined(monkeypatch):
    monkeypatch.setattr(framing, "MAX_QUEUED_FRAMES", 2)
    instance = proxy()
    process = subprocess.Popen(
        [sys.executable, "-c", "import sys,time; sys.stdout.write('{}\\n'*100); sys.stdout.flush(); time.sleep(5)"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )
    assert process.stdout is not None
    try:
        instance._activate_child_output_pump(process.stdout, process=process)
        assert instance._child_output_stop.wait(1)
        process.wait(timeout=1)
        assert isinstance(instance._io_failure, framing.ProxyIoLimitError)
        assert instance._io_failure.reason == "queue_frame_limit"
        assert instance._child_output_queue is not None and instance._child_output_queue.qsize() <= 2
        sink = io.StringIO()
        with pytest.raises(framing.ProxyIoLimitError):
            instance._forward_notification({"id": 1, "method": "tools/call"}, sink)
        assert sink.getvalue() == ""
    finally:
        instance._deactivate_child_process_io()
        if process.poll() is None:
            process.kill()
        process.wait(timeout=1)
        if process.stdin is not None:
            process.stdin.close()
        process.stdout.close()


def test_idle_client_wait_observes_background_terminal_failure():
    instance = proxy()
    failed = framing.ProxyIoLimitError(source="child_output", reason="queue_frame_limit")
    with pipe() as (reader, _writer):
        alarm = threading.Timer(0.02, lambda: instance._abort_transport(failed))
        alarm.start()
        started = time.monotonic()
        try:
            with pytest.raises(framing.ProxyIoLimitError, match="queue_frame_limit"):
                instance._read_idle_client(reader)
            assert time.monotonic() - started < 0.5
        finally:
            alarm.cancel()
            alarm.join(timeout=1)


def test_idle_client_receives_child_catalog_notification_before_sending_another_request():
    instance = proxy(timeout=2)
    instance._tool_catalog_state = "complete"
    notification = {"jsonrpc": "2.0", "method": "notifications/tools/list_changed", "params": {}}
    received: list[str] = []
    errors: list[BaseException] = []
    with (
        pipe() as (client_input, client_writer),
        pipe() as (child_stdout, child_writer),
        pipe() as (client_reader, server_output),
    ):
        instance._activate_child_output_pump(child_stdout)

        def wait_for_client():
            try:
                received.append(
                    instance._read_idle_client(
                        client_input, child_stdin=io.StringIO(), child_stdout=child_stdout, server_output=server_output
                    )
                )
            except BaseException as error:
                errors.append(error)

        waiter = threading.Thread(target=wait_for_client, daemon=True)
        waiter.start()
        try:
            child_writer.write(json.dumps(notification) + "\n")
            child_writer.flush()
            # No client input has been written. The server notification must
            # reach the client and invalidate authority on its own.
            line = _readline_with_timeout(client_reader, 2, source="idle_notification")
            assert json.loads(line) == notification
            assert instance._tool_catalog_state == "invalidated"
            assert instance._tool_catalog_generation == 1
            assert received == []
            client_writer.write('{"id":"next","method":"tools/list"}\n')
            client_writer.flush()
            waiter.join(timeout=2)
            assert not waiter.is_alive()
            assert errors == []
            assert json.loads(received[0])["id"] == "next"
        finally:
            client_writer.close()
            waiter.join(timeout=2)
            instance._deactivate_child_process_io()


@pytest.mark.parametrize("kind", ["runtime", "generic"])
def test_failed_notification_write_ends_stream_without_waiting_for_more_input(monkeypatch, kind):
    class BrokenWriter:
        def write(self, _text):
            raise OSError("fixture pipe failure")

        def flush(self):
            pass

    process = cast(
        subprocess.Popen[str],
        cast(
            object,
            SimpleNamespace(
                stdin=BrokenWriter(), stdout=io.StringIO(), returncode=0, poll=lambda: 0, wait=lambda **_: 0
            ),
        ),
    )
    instance = proxy() if kind == "runtime" else StdioGuardProxy(command=["fixture"])
    monkeypatch.setattr(instance, "_start_process", lambda: process)
    if isinstance(instance, RuntimeMcpGuardProxy):

        def forward(**arguments):
            instance._forward_notification(arguments["message"], arguments["child_stdin"])
            return None, {}

        monkeypatch.setattr(instance, "_handle_message_checked", forward)
    with pipe() as (reader, writer):
        os.write(writer.fileno(), b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n')
        started = time.monotonic()
        if isinstance(instance, RuntimeMcpGuardProxy):
            result = instance.serve(stdin=reader, stdout=io.StringIO())
        else:
            result = instance.run_stream(input_stream=reader, output_stream=io.StringIO(), error_stream=io.StringIO())
        assert result == 2
        assert instance._io_failure is not None
        assert time.monotonic() - started < 0.5


def test_pump_failure_during_handler_cannot_emit_a_normal_response(monkeypatch):
    instance = proxy()

    def finish_with_failure(**_arguments):
        instance._abort_transport(framing.ProxyIoLimitError(source="child_output", reason="queue_frame_limit"))
        return {"id": 1, "result": {"value": "would-be-success"}}, {"decision": "forward"}

    monkeypatch.setattr(instance, "_handle_message_checked", finish_with_failure)
    response, event = instance._handle_message(
        message={"id": 1, "method": "ping"},
        child_stdin=io.StringIO(),
        child_stdout=io.StringIO(),
        client_input=None,
        server_output=None,
        approval_callback=None,
    )
    assert response is not None and "result" not in response
    assert response["error"]["data"]["session_terminal"] is True
    assert event["decision"] == "transport-failed"


def test_retired_pump_cannot_abort_a_replacement_session(monkeypatch):
    monkeypatch.setattr(framing, "MAX_QUEUED_FRAMES", 2)
    instance = proxy()
    entered = threading.Event()
    release = threading.Event()
    finished = threading.Event()
    quarantined = []
    monkeypatch.setattr(runtime_mcp, "_quarantine_process", quarantined.append)
    original = instance._abort_transport

    def delayed_abort(error, *, expected_queue=None):
        entered.set()
        try:
            assert release.wait(1)
            original(error, expected_queue=expected_queue)
        finally:
            finished.set()

    monkeypatch.setattr(instance, "_abort_transport", delayed_abort)
    instance._activate_child_output_pump(io.StringIO("{}\n" * 3))
    try:
        assert entered.wait(1)
        instance._deactivate_child_process_io()
        replacement = cast(subprocess.Popen[str], cast(object, SimpleNamespace(generation="replacement")))
        instance._activate_child_output_pump(io.StringIO(), process=replacement)
        replacement_stop = instance._child_output_stop
        release.set()
        assert finished.wait(1)
        assert instance._io_failure is None
        assert not replacement_stop.is_set()
        assert instance._active_process is replacement
        assert not quarantined
    finally:
        release.set()
        instance._deactivate_child_process_io()


@pytest.mark.parametrize("direction", ["child", "client"])
def test_unmatched_response_count_is_bounded_and_terminal(monkeypatch, direction):
    monkeypatch.setattr(framing, "MAX_BUFFERED_RESPONSES", 2)
    instance = proxy()
    buffer = getattr(instance, f"_buffer_{direction}_response")
    buffer({"id": 1, "result": {}})
    buffer({"id": 2, "result": {}})
    with pytest.raises(framing.ProxyIoLimitError, match="response_count_limit"):
        buffer({"id": 3, "result": {}})
    sink = io.StringIO()
    with pytest.raises(framing.ProxyIoLimitError):
        instance._forward_notification({"method": "tools/call", "id": 4}, sink)
    assert sink.getvalue() == ""


def test_unmatched_response_bytes_are_bounded(monkeypatch):
    monkeypatch.setattr(framing, "MAX_BUFFERED_RESPONSE_BYTES", 100)
    instance = proxy()
    instance._buffer_child_response({"id": 1, "result": "x" * 60})
    with pytest.raises(framing.ProxyIoLimitError, match="response_bytes_limit"):
        instance._buffer_child_response({"id": 2, "result": "x" * 60})


def test_direct_legacy_buffer_fixture_remains_compatible():
    instance = proxy()
    response = {"id": 2, "result": {"fixture": True}}
    instance._buffered_client_responses["2"] = [response]
    assert instance._pop_buffered_client_response(2) is response
    assert instance._buffered_client_responses == {}


def test_notification_flood_cannot_extend_response_budget(monkeypatch):
    instance = proxy(0.04)
    child = io.StringIO()
    sentinel = io.StringIO()

    def notification(*_args, **_kwargs):
        time.sleep(0.005)
        framing.remaining_timeout(0.04, source="child_response")
        return _ChildOutputFrame(line='{"jsonrpc":"2.0","method":"notifications/progress"}\n')

    monkeypatch.setattr(instance, "_next_child_output_frame", notification)
    started = time.monotonic()
    response = instance._forward_message(
        {"jsonrpc": "2.0", "id": 1, "method": "ping"}, child, sentinel, client_input=None, server_output=None
    )
    assert response["error"]["data"]["guard_timeout"] is True
    assert time.monotonic() - started < 0.5
    assert len(child.getvalue().splitlines()) == 1


def test_infinite_quiet_drain_is_bounded_without_removing_quiet_barrier(monkeypatch):
    monkeypatch.setattr(framing, "MAX_OPERATION_FRAMES", 4)
    instance = proxy()
    quiet = []

    def notification(_stream, *, timeout_seconds, required):
        quiet.append(timeout_seconds)
        return _ChildOutputFrame(line='{"method":"notifications/progress"}\n')

    monkeypatch.setattr(instance, "_next_child_output_frame", notification)
    with pytest.raises(framing.ProxyIoLimitError, match="operation_frame_limit"):
        instance._drain_child_messages(
            child_stdin=io.StringIO(),
            child_stdout=io.StringIO(),
            client_input=None,
            server_output=None,
            quiet_seconds=0.005,
        )
    assert quiet and set(quiet) == {0.005}


def test_pending_approval_drains_child_catalog_change_and_keeps_response():
    instance = proxy()
    child_stdout = io.StringIO()
    instance._active_child_stdout = child_stdout
    instance._child_output_queue = framing.ByteBoundedQueue(lambda frame: len(frame.line.encode()) if frame.line else 0)
    instance._child_output_queue.put(_ChildOutputFrame(line='{"method":"notifications/tools/list_changed"}\n'))
    generation = instance._tool_catalog_generation
    output = io.StringIO()
    result = instance._request_inline_approval(
        {"jsonrpc": "2.0", "id": "approval", "method": "elicitation/create"},
        input_stream=io.StringIO('{"jsonrpc":"2.0","id":"approval","result":{"action":"accept"}}\n'),
        output_stream=output,
        child_stdin=io.StringIO(),
        child_stdout=child_stdout,
    )
    assert result == {"action": "accept"}
    assert instance._tool_catalog_generation > generation
    assert "notifications/tools/list_changed" in output.getvalue()
    assert instance._child_output_queue.empty()


def test_timeout_control_reply_cannot_be_used_to_reset_a_request_budget():
    output = io.StringIO()
    with framing.operation_budget(0.01, source="fixture"):
        time.sleep(0.02)
        with pytest.raises(framing.ProxyIoLimitError, match="invalid_control_reply"):
            framing.write_timeout_reply(output, {"id": 1, "method": "tools/call"})
        with pytest.raises(framing.ProxyIoTimeoutError):
            framing.write_message(output, {"id": 1}, timeout_seconds=1, source="fixture")
    assert output.getvalue() == ""


def test_generic_stdio_notification_stream_does_not_reset_response_deadline(monkeypatch):
    instance = StdioGuardProxy(command=["fixture"])
    monkeypatch.setattr(instance, "_response_timeout_seconds", lambda: 0.03)

    class SlowNotifications(io.StringIO):
        def readline(self, size=-1):
            time.sleep(0.005)
            return '{"method":"notifications/progress"}\n'

    process = cast(subprocess.Popen[str], cast(object, SimpleNamespace(stdout=SlowNotifications(), poll=lambda: 0)))
    started = time.monotonic()
    # The response reader itself uses a single absolute deadline, including
    # when directly called without the surrounding operation decorator.
    response = instance._read_response(process=process, message_id=1)
    assert response is not None and response["error"]["data"]["guard_timeout"] is True
    assert time.monotonic() - started < 0.5
