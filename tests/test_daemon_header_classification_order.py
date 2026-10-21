"""Preserve absolute header expiry while the HTTP parser still owns input."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard.daemon.server import _GuardDaemonHandler


@pytest.mark.parametrize("parsed,admitted", [(False, True), (True, True), (True, False)])
def test_headers_finish_before_classification_and_capacity(
    monkeypatch: pytest.MonkeyPatch, parsed: bool, admitted: bool
) -> None:
    """Do not exempt a partially read request from the header watchdog."""
    handler = object.__new__(_GuardDaemonHandler)
    handler.request = object()
    handler.path = "/v1/runtime/hook"
    events: list[str] = []

    def parse(_handler: BaseHTTPRequestHandler) -> bool:
        """Reject classification before the underlying parser has returned."""
        assert events == []
        events.append("parsed")
        return parsed

    def classify(request: object) -> None:
        """Require header parsing to finish before relinquishing its deadline."""
        assert request is handler.request
        assert events == ["parsed"]
        events.append("classified")

    def capacity(request: object, path: str) -> bool:
        """Admit capacity only after successful parsing and classification."""
        assert request is handler.request
        assert path == handler.path
        assert parsed
        assert events == ["parsed", "classified"]
        events.append("capacity")
        return admitted

    server = SimpleNamespace(classify_connection=classify, claim_request_capacity=capacity)
    monkeypatch.setattr(BaseHTTPRequestHandler, "parse_request", parse)
    monkeypatch.setattr(handler, "_daemon_server", lambda: server)
    errors: list[int] = []
    monkeypatch.setattr(handler, "send_error", lambda status, _reason: errors.append(status))

    assert handler.parse_request() is (parsed and admitted)
    assert events == ["parsed", "classified", *(["capacity"] if parsed else [])]
    assert errors == ([503] if parsed and not admitted else [])


def test_header_timeout_does_not_classify_the_connection(monkeypatch: pytest.MonkeyPatch) -> None:
    """A parser timeout must leave incomplete input subject to connection cleanup."""
    handler = object.__new__(_GuardDaemonHandler)
    handler.request = object()

    def timeout(_handler: BaseHTTPRequestHandler) -> bool:
        """Represent a read deadline expiring before complete headers arrive."""
        raise TimeoutError("header deadline")

    def unexpected(*_args: object) -> None:
        """Fail if parsing failure is incorrectly promoted into an admitted request."""
        pytest.fail("Incomplete headers must not be classified or claim capacity")

    server = SimpleNamespace(classify_connection=unexpected, claim_request_capacity=unexpected)
    monkeypatch.setattr(BaseHTTPRequestHandler, "parse_request", timeout)
    monkeypatch.setattr(handler, "_daemon_server", lambda: server)
    with pytest.raises(TimeoutError, match="header deadline"):
        handler.parse_request()
