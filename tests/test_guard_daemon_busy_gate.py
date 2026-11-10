"""An origin or session check that cannot reach the resident is not a denial."""

from __future__ import annotations

import io
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from codex_plugin_scanner.guard import native_daemon_route as route
from codex_plugin_scanner.guard.native_resident_client import record_native_resident_client_failure_code
from codex_plugin_scanner.guard.native_resident_revival import RESTART_BLOCKED_CODE
from codex_plugin_scanner.guard.routes import request_handler as daemon_server
from codex_plugin_scanner.guard.routes.request_handler import _GuardDaemonHandler


def _unanswered(*_args: object, **_kwargs: object) -> object:
    raise route.NativeDaemonRouteError("native_daemon_route_unavailable")


def _handler(home: Path) -> tuple[_GuardDaemonHandler, list[tuple[int, object]]]:
    handler = object.__new__(_GuardDaemonHandler)
    handler.server = SimpleNamespace(  # pyright: ignore[reportAttributeAccessIssue]
        store=SimpleNamespace(guard_home=home),
        classify_connection=lambda _request: None,
        claim_request_capacity=lambda _request, _path: True,
    )
    handler.request = None
    handler.client_address = ("127.0.0.1", 0)
    handler.request_version = "HTTP/1.1"
    handler._touch_runtime_heartbeat = lambda path: None  # pyright: ignore[reportAttributeAccessIssue]
    handler._record_auth_audit_event = lambda: None  # type: ignore[method-assign]
    written: list[tuple[int, object]] = []

    def capture(body: bytes, *, status: int, extra_headers: dict[str, str] | None = None) -> None:
        del extra_headers
        written.append((status, json.loads(body)))

    handler._write_json_bytes = capture  # type: ignore[method-assign]
    return handler, written


def _get(handler: _GuardDaemonHandler, path: str, headers: str) -> None:
    # Runs the real request parsing so each request starts from a clean slate,
    # as it does for every request on a kept-alive connection.
    handler.raw_requestline = f"GET {path} HTTP/1.1\r\n".encode()  # pyright: ignore[reportAttributeAccessIssue]
    handler.rfile = io.BytesIO(f"{headers}\r\n".encode())
    assert handler.parse_request()
    handler.do_GET()


def test_a_busy_origin_check_answers_retryable_503_and_a_real_denial_stays_403(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # On a busy computer the origin check timed out, the daemon answered 403,
    # and the dashboard treated that as a rejection and stopped CIGAR setup.
    handler, written = _handler(tmp_path)
    origin = "Origin: http://127.0.0.1:4781\r\n"

    monkeypatch.setattr(daemon_server, "native_origin_decision", _unanswered)
    _get(handler, "/v1/runtime", origin)
    monkeypatch.setattr(daemon_server, "native_origin_decision", lambda *_a, **_k: route.OriginDecision(False, False))
    _get(handler, "/v1/runtime", origin)

    assert written == [
        (503, {"error": "native_route_policy_unavailable"}),
        (403, {"error": "forbidden_origin"}),
    ]


def test_a_busy_session_check_answers_retryable_503(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    handler, written = _handler(tmp_path)
    monkeypatch.setattr(daemon_server, "native_route_facts", _unanswered)

    _get(handler, "/v1/healthz/details", "X-Guard-Dashboard-Session: unchecked\r\n")

    assert written == [(503, {"error": "native_route_policy_unavailable"})]


def test_a_busy_cors_lookup_does_not_turn_a_real_denial_into_a_retry(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Response headers are chosen after the gate already said no. If the
    # resident is busy by then, the denial must still go out as a denial.
    handler, written = _handler(tmp_path)
    handler.raw_requestline = b"GET /v1/runtime HTTP/1.1\r\n"  # pyright: ignore[reportAttributeAccessIssue]
    handler.rfile = io.BytesIO(b"Origin: http://127.0.0.1:4781\r\n\r\n")
    assert handler.parse_request()
    monkeypatch.setattr(daemon_server, "native_origin_decision", _unanswered)

    handler._write_json({"error": "unauthorized"}, status=401, extra_headers=handler._cors_headers_for_request())

    assert written == [(401, {"error": "unauthorized"})]


def test_a_busy_reconnect_origin_check_answers_retryable_503(tmp_path: Path) -> None:
    handler, written = _handler(tmp_path)
    handler._native_gate_unavailable = True

    handler._write_dashboard_reconnect_candidate_failure("dashboard_reconnect_origin_mismatch")

    assert written == [(503, {"error": "native_route_policy_unavailable"})]


def test_a_new_request_does_not_inherit_an_earlier_restart_refusal(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # A kept-alive connection reuses the worker thread. A restart refusal left
    # by an earlier request must not mark this request's busy reply as final.
    handler, written = _handler(tmp_path)
    record_native_resident_client_failure_code(RESTART_BLOCKED_CODE)
    monkeypatch.setattr(daemon_server, "native_origin_decision", _unanswered)

    _get(handler, "/v1/runtime", "Origin: http://127.0.0.1:4781\r\n")

    assert written == [(503, {"error": "native_route_policy_unavailable"})]
