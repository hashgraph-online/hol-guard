"""Resident-client-pool priming sends a bounded concurrent burst and retries transients."""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from tests.guard_daemon_acceptance_fixtures import _prime_resident_client_pool


class _StubState:
    def __init__(self, transient_answers: int, delay_seconds: float = 0.05) -> None:
        self.transient_answers = transient_answers
        self.delay_seconds = delay_seconds
        self.requests = 0
        self.in_flight = 0
        self.max_in_flight = 0
        self.lock = threading.Lock()


def _handler_for(state: _StubState) -> type[BaseHTTPRequestHandler]:
    class _Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            self.rfile.read(int(self.headers["Content-Length"]))
            with state.lock:
                state.requests += 1
                state.in_flight += 1
                state.max_in_flight = max(state.max_in_flight, state.in_flight)
            try:
                time.sleep(state.delay_seconds)
                with state.lock:
                    transient = state.transient_answers > 0
                    if transient:
                        state.transient_answers -= 1
                body = {"reason_code": "native_policy_not_ready"} if transient else {"decision": "allow"}
                payload = json.dumps(body).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            finally:
                with state.lock:
                    state.in_flight -= 1

        def log_message(self, *args: object) -> None:
            pass

    return _Handler


@contextmanager
def _stub_server(state: _StubState) -> Iterator[ThreadingHTTPServer]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _handler_for(state))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _prime(server: ThreadingHTTPServer, concurrency: int, deadline_seconds: float = 30) -> None:
    _prime_resident_client_pool(
        port=server.server_address[1],
        auth_token="stub",
        query="guard-home=x&home=y&workspace=z",
        concurrency=concurrency,
        deadline_monotonic=time.monotonic() + deadline_seconds,
    )


def test_prime_sends_concurrent_overlapping_requests() -> None:
    state = _StubState(transient_answers=0)
    with _stub_server(state) as server:
        _prime(server, concurrency=6)
    assert state.requests == 6
    assert state.max_in_flight > 1


def test_prime_retries_transient_reason_codes() -> None:
    state = _StubState(transient_answers=3)
    with _stub_server(state) as server:
        _prime(server, concurrency=3)
    assert state.requests > 3


def test_prime_raises_when_only_transient_answers_arrive() -> None:
    state = _StubState(transient_answers=10_000, delay_seconds=0)
    with _stub_server(state) as server, pytest.raises(RuntimeError, match="resident client pool did not warm"):
        _prime(server, concurrency=2, deadline_seconds=0.4)


def test_prime_rejects_a_nontransient_answer_that_arrives_after_the_deadline() -> None:
    state = _StubState(transient_answers=0, delay_seconds=0.4)
    with _stub_server(state) as server, pytest.raises(RuntimeError, match="resident client pool did not warm"):
        _prime(server, concurrency=2, deadline_seconds=0.3)
