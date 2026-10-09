"""Exercise terminal stream handling with a local transport fixture, not live inference."""

import json
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from ci.gauntlet.provider import InferenceRelay


@pytest.mark.parametrize("terminal", [True, False])
def test_terminal_event_completes_without_waiting_for_upstream_close(terminal):
    """A real DONE event ends the stream; EOF without DONE stays incomplete."""
    release = threading.Event()
    payload = b'data: {"model":"unit-transport-only","choices":[]}\n\n'
    if terminal:
        payload += b"data: [DONE]\n\n"

    class Upstream(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args):
            pass

        def do_POST(self):
            self.rfile.read(int(self.headers["Content-Length"]))
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            self.wfile.write(payload)
            self.wfile.flush()
            if terminal:
                release.wait(timeout=5)
            self.close_connection = True

    server = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with InferenceRelay(
            base_url=f"http://127.0.0.1:{server.server_port}/v1",
            model="unit-transport-only",
            api_key="test-only-key",
            canary="synthetic-test-canary",
            identity="unit-transport-only",
            allow_loopback=True,
        ) as relay:
            request = urllib.request.Request(
                relay.base_url + "/chat/completions",
                data=json.dumps({"messages": []}).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=1.5) as response:
                assert response.read() == payload
            evidence = relay.evidence()["live_rounds"]
            assert len(evidence) == 1
            assert evidence[0]["status"] == ("completed" if terminal else "incomplete-stream")
            assert evidence[0]["response_bytes"] == len(payload)
            assert evidence[0]["delivered_bytes"] == len(payload)
            assert evidence[0]["response_models"] == ["unit-transport-only"]
    finally:
        release.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_evidence_waits_for_terminal_event_without_qualifying_pending_stream():
    """Observe pending metadata, then wait for the upstream's real terminal event."""
    release = threading.Event()
    started = threading.Event()
    prefix = b'data: {"model":"unit-transport-only","choices":[]}\n\n'

    class Upstream(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            self.rfile.read(int(self.headers["Content-Length"]))
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            self.wfile.write(prefix)
            self.wfile.flush()
            started.set()
            if release.wait(timeout=5):
                self.wfile.write(b"data: [DONE]\n\n")
                self.wfile.flush()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    timer = None
    try:
        with InferenceRelay(
            base_url=f"http://127.0.0.1:{server.server_port}/v1",
            model="unit-transport-only",
            api_key="test-only-key",
            canary="synthetic-test-canary",
            identity="unit-transport-only",
            allow_loopback=True,
        ) as relay:
            request = urllib.request.Request(
                relay.base_url + "/chat/completions",
                data=json.dumps({"messages": []}).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=3) as response:
                assert started.wait(timeout=1)
                pending = relay.evidence(wait_seconds=0.05)["live_rounds"]
                assert pending[0]["status"] == "started"
                timer = threading.Timer(0.1, release.set)
                timer.start()
                settled = relay.evidence(wait_seconds=1)["live_rounds"]
                assert settled[0]["status"] == "completed"
                assert response.read() == prefix + b"data: [DONE]\n\n"
    finally:
        release.set()
        if timer is not None:
            timer.join(timeout=1)
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.parametrize("delivered", [True, False])
def test_agent_close_is_excused_only_after_the_finish_event_was_delivered(delivered):
    """A close after the whole finish event waits for DONE; an earlier close is an error."""
    import socket
    import struct
    import time

    gates = [threading.Event(), threading.Event()]
    first = b'data: {"model":"unit-transport-only","choices":[{"delta":{"content":"a"}}]}\n\n'
    finish = b'data: {"model":"unit-transport-only","choices":[{"finish_reason":"stop"}]}\n\n'
    tail = [b'data: {"model":"unit-transport-only","choices":[],"usage":{}}\n\n', b"data: [DONE]\n\n"]

    class Upstream(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            self.rfile.read(int(self.headers["Content-Length"]))
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            for chunk, gate in [(first, gates[0]), (finish, gates[1])]:
                self.wfile.write(chunk)
                self.wfile.flush()
                gate.wait(timeout=5)
            for chunk in tail:
                time.sleep(0.05)
                self.wfile.write(chunk)
                self.wfile.flush()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with InferenceRelay(
            base_url=f"http://127.0.0.1:{server.server_port}/v1",
            model="unit-transport-only",
            api_key="test-only-key",
            canary="synthetic-test-canary",
            identity="unit-transport-only",
            allow_loopback=True,
        ) as relay:
            body = json.dumps({"messages": []}).encode()
            agent = socket.create_connection(("127.0.0.1", relay.server.server_port), timeout=3)
            agent.sendall(
                b"POST /v1/chat/completions HTTP/1.1\r\nHost: relay\r\nContent-Type: application/json\r\n"
                + f"Content-Length: {len(body)}\r\n\r\n".encode()
                + body
            )
            received = b""
            if delivered:
                gates[0].set()
            target = finish if delivered else first
            while not received.endswith(target):
                data = agent.recv(4096)
                assert data
                received += data
            # Reset rather than close, so the relay's next write fails at once.
            agent.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            agent.close()
            time.sleep(0.2)
            for gate in gates:
                gate.set()
            row = relay.evidence(wait_seconds=3)["live_rounds"][0]
            if delivered:
                assert row["status"] == "completed"
                assert row["agent_closed_after_finish"] is True
            else:
                assert row["status"] == "provider-error"
                assert row["error_phase"] == "agent-write"
    finally:
        for gate in gates:
            gate.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
