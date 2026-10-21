"""A kept-alive follow-up request is timed from its own arrival, not the socket accept."""

from __future__ import annotations

import threading
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.daemon import server as daemon_server


def _capacity_server() -> daemon_server._GuardDaemonHTTPServer:
    server = object.__new__(daemon_server._GuardDaemonHTTPServer)
    server.request_capacity_lock = threading.Lock()
    server.request_capacity_kinds = {}
    server.request_accepted_at = {}
    server.rejected_requests = 0
    server.request_capacity = threading.BoundedSemaphore(4)
    server.critical_request_capacity = threading.BoundedSemaphore(4)
    server.control_request_capacity = threading.BoundedSemaphore(4)
    return server


def test_hook_after_identity_challenge_gets_its_own_admission_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    server = _capacity_server()
    request = object()
    server.request_accepted_at[id(request)] = 100.0
    monkeypatch.setattr(daemon_server, "time", SimpleNamespace(monotonic=lambda: 102.0))

    assert server.claim_request_capacity(request, "/v1/daemon/identity-challenge")
    assert server.request_deadline(request, 3.0) == 103.0

    assert server.claim_request_capacity(request, "/v1/hooks/claude-code?guard-home=x")
    assert server.request_deadline(request, 3.0) == 105.0


def test_first_request_keeps_the_socket_accept_clock() -> None:
    server = _capacity_server()
    request = object()
    server.request_accepted_at[id(request)] = 100.0

    assert server.claim_request_capacity(request, "/v1/hooks/claude-code")
    assert server.request_deadline(request, 3.0) == 103.0
