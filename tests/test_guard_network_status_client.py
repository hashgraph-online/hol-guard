from __future__ import annotations

import http.client
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import pytest

from codex_plugin_scanner.guard.daemon.client import (
    GuardDaemonRequestError,
    GuardDaemonResponseSchemaError,
    GuardDaemonTimeoutError,
    GuardDaemonTransportError,
    GuardSurfaceDaemonClient,
)
from codex_plugin_scanner.guard.runtime.network_status import build_network_status


def test_network_status_client_uses_fast_status_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = GuardSurfaceDaemonClient("http://127.0.0.1:1", "token")
    observed: dict[str, object] = {}

    def fake_get(path: str, *, timeout: float) -> dict[str, object]:
        observed.update(path=path, timeout=timeout)
        return build_network_status(platform_name="darwin")

    monkeypatch.setattr(client, "_get", fake_get)
    client.network_status()
    assert observed == {"path": "/v1/network/status", "timeout": 0.25}


def test_dashboard_session_capabilities_uses_scoped_initialize_then_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = GuardSurfaceDaemonClient("http://127.0.0.1:1", "private-auth-token")
    requests: list[tuple[str, str | None, str | None, dict[str, object]]] = []
    timeouts: list[float] = []
    opener_handlers: list[object] = []

    def fake_urlopen(request: urllib.request.Request, *, timeout: float) -> _RawResponse:
        timeouts.append(timeout)
        body = json.loads((request.data or b"{}").decode("utf-8"))
        path = urllib.parse.urlsplit(request.full_url).path
        local_token = request.headers.get("X-guard-token")
        dashboard_token = request.headers.get("X-guard-dashboard-session")
        requests.append((path, local_token, dashboard_token, body))
        if path == "/v1/initialize":
            return _RawResponse(payload=b'{"dashboard_session_token":"fresh-dashboard-session"}')
        assert path == "/v1/capabilities"
        return _RawResponse(payload=b'{"capabilities": ["dashboard"]}')

    class FakeOpener:
        def open(self, request: urllib.request.Request, *, timeout: float) -> _RawResponse:
            return fake_urlopen(request, timeout=timeout)

    monkeypatch.setattr(
        urllib.request,
        "build_opener",
        lambda *handlers: opener_handlers.extend(handlers) or FakeOpener(),
    )

    capabilities = client.dashboard_session_capabilities(timeout=0.5)

    assert capabilities == {"capabilities": ["dashboard"]}
    assert len(requests) == 2
    first_path, first_local_token, first_dashboard_token, first_body = requests[0]
    assert first_path == "/v1/initialize"
    assert first_local_token is None
    assert first_dashboard_token is not None and first_dashboard_token.startswith("gld1.")
    assert first_body == {
        "client_name": "guard-dashboard-web",
        "surface": "dashboard",
        "supported_protocol_versions": ["1.1", "1.0"],
    }
    assert requests[1] == ("/v1/capabilities", None, "fresh-dashboard-session", {})
    assert len(timeouts) == 2
    assert all(0.0 < value <= 0.5 for value in timeouts)
    assert timeouts[1] <= timeouts[0]
    assert any(
        isinstance(handler, urllib.request.ProxyHandler) and handler.proxies == {}
        for handler in opener_handlers
    )
    assert any(
        isinstance(handler, type) and issubclass(handler, urllib.request.HTTPRedirectHandler)
        for handler in opener_handlers
    )


def test_dashboard_session_rejects_redirect_without_sending_session_to_target() -> None:
    paths: list[tuple[str, str | None]] = []

    class RedirectingHandler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            paths.append((self.path, self.headers.get("X-Guard-Dashboard-Session")))
            self.send_response(302)
            self.send_header("Location", "/collect")
            self.end_headers()

        def do_GET(self) -> None:
            paths.append((self.path, self.headers.get("X-Guard-Dashboard-Session")))
            self.send_response(200)
            self.end_headers()

        def log_message(self, *_args: object) -> None:
            return None

    server = ThreadingHTTPServer(("127.0.0.1", 0), RedirectingHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        client = GuardSurfaceDaemonClient(f"http://127.0.0.1:{server.server_port}", "private-auth-token")
        with pytest.raises(GuardDaemonRequestError):
            client.dashboard_session_capabilities(timeout=0.5)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1.0)

    assert len(paths) == 1
    assert paths[0][0] == "/v1/initialize"
    assert paths[0][1] is not None and paths[0][1].startswith("gld1.")


def test_dashboard_session_capabilities_reports_normal_request_unauthorized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests: list[tuple[str, str | None, str | None]] = []

    class UnauthorizedOpener:
        def open(self, request: urllib.request.Request, *, timeout: float) -> _RawResponse:
            del timeout
            path = urllib.parse.urlsplit(request.full_url).path
            requests.append(
                (
                    path,
                    request.headers.get("X-guard-token"),
                    request.headers.get("X-guard-dashboard-session"),
                )
            )
            if path == "/v1/initialize":
                return _RawResponse(payload=b'{"dashboard_session_token":"fresh-dashboard-session"}')
            raise urllib.error.HTTPError(
                request.full_url,
                401,
                "Unauthorized",
                {},
                _RawResponse(payload=b'{"error":"unauthorized"}'),
            )

    monkeypatch.setattr(urllib.request, "build_opener", lambda *_handlers: UnauthorizedOpener())
    client = GuardSurfaceDaemonClient("http://127.0.0.1:1", "private-auth-token")

    with pytest.raises(GuardDaemonRequestError) as error:
        client.dashboard_session_capabilities(timeout=0.5)

    assert error.value.status == 401
    assert len(requests) == 2
    assert requests[0][0] == "/v1/initialize"
    assert requests[0][1] is None
    assert requests[0][2] is not None and requests[0][2].startswith("gld1.")
    assert requests[1] == ("/v1/capabilities", None, "fresh-dashboard-session")


def test_network_status_client_types_timeout_without_transport_detail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = GuardSurfaceDaemonClient("http://127.0.0.1:1", "token")

    def timeout(_request: urllib.request.Request, *, timeout: float) -> None:
        assert timeout == 0.25
        raise TimeoutError("private operating system detail")

    monkeypatch.setattr(urllib.request, "urlopen", timeout)
    with pytest.raises(GuardDaemonTimeoutError, match="timed out") as error:
        client.network_status()
    assert "private" not in str(error.value)


class _RawResponse:
    def __init__(self, *, payload: bytes | None = None, read_error: Exception | None = None) -> None:
        self.payload = payload
        self.read_error = read_error
        self.read_timeout: float | None = None
        self.consumed = False
        self.closed = False

    def __enter__(self) -> _RawResponse:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self, _amount: int = -1) -> bytes:
        if self.read_error is not None:
            raise self.read_error
        assert self.payload is not None
        if self.consumed:
            return b""
        self.consumed = True
        return self.payload

    def settimeout(self, timeout: float) -> None:
        self.read_timeout = timeout

    def close(self) -> None:
        self.closed = True


def test_network_status_client_enforces_total_body_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class SlowResponse(_RawResponse):
        def read(self, _amount: int = -1) -> bytes:
            assert self.read_timeout is not None
            time.sleep(self.read_timeout)
            raise TimeoutError("private socket timeout")

    client = GuardSurfaceDaemonClient("http://127.0.0.1:1", "token")
    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda _request, *, timeout: SlowResponse(payload=b"{}"),
    )
    started_at = time.monotonic()
    with pytest.raises(GuardDaemonTimeoutError, match="timed out"):
        client.network_status()
    assert time.monotonic() - started_at < 0.75


def test_network_status_client_bounds_http_error_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class SlowErrorBody(_RawResponse):
        def read(self, _amount: int = -1) -> bytes:
            assert self.read_timeout is not None
            time.sleep(self.read_timeout)
            raise TimeoutError("private socket timeout")

    error_body = SlowErrorBody(payload=b"{}")

    def raise_http_error(_request: urllib.request.Request, *, timeout: float) -> None:
        raise urllib.error.HTTPError(
            "http://127.0.0.1:1/v1/network/status",
            503,
            "private",
            {},
            error_body,
        )

    client = GuardSurfaceDaemonClient("http://127.0.0.1:1", "token")
    monkeypatch.setattr(urllib.request, "urlopen", raise_http_error)
    started_at = time.monotonic()
    with pytest.raises(GuardDaemonTimeoutError, match="timed out") as error:
        client.network_status()
    assert "private" not in str(error.value)
    assert error_body.closed is True
    assert time.monotonic() - started_at < 0.75


def test_network_status_client_enforces_deadline_across_slow_chunks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class TrickleResponse(_RawResponse):
        def read1(self, _amount: int = -1) -> bytes:
            time.sleep(0.06)
            return b"x"

    client = GuardSurfaceDaemonClient("http://127.0.0.1:1", "token")
    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda _request, *, timeout: TrickleResponse(payload=b"unused"),
    )
    started_at = time.monotonic()
    with pytest.raises(GuardDaemonTimeoutError, match="timed out"):
        client.network_status()
    assert time.monotonic() - started_at < 0.75


def test_network_status_client_types_invalid_utf8_as_schema_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = GuardSurfaceDaemonClient("http://127.0.0.1:1", "token")
    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda _request, *, timeout: _RawResponse(payload=b"\xffprivate"),
    )
    with pytest.raises(GuardDaemonResponseSchemaError) as error:
        client.network_status()
    assert "private" not in str(error.value)


def test_network_status_client_types_truncated_body_as_transport_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = GuardSurfaceDaemonClient("http://127.0.0.1:1", "token")
    monkeypatch.setattr(
        urllib.request,
        "urlopen",
        lambda _request, *, timeout: _RawResponse(read_error=http.client.IncompleteRead(b"private partial body", 100)),
    )
    with pytest.raises(GuardDaemonTransportError, match="truncated") as error:
        client.network_status()
    assert "private" not in str(error.value)


def test_post_decodes_truncated_json_without_retry(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = {"count": 0}

    def fake_urlopen(_request: urllib.request.Request, *, timeout: float) -> _RawResponse:
        del timeout
        calls["count"] += 1
        return _RawResponse(read_error=http.client.IncompleteRead(b'{"claimed": true}', 32))

    client = GuardSurfaceDaemonClient("http://127.0.0.1:1", "token")
    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    assert client.claim_policy_decision({"decision_id": "1"}) is True
    assert calls["count"] == 1


def test_post_does_not_retry_truncated_non_json(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = {"count": 0}

    def fake_urlopen(_request: urllib.request.Request, *, timeout: float) -> _RawResponse:
        del timeout
        calls["count"] += 1
        return _RawResponse(read_error=http.client.IncompleteRead(b"private partial body", 100))

    client = GuardSurfaceDaemonClient("http://127.0.0.1:1", "token")
    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    with pytest.raises(GuardDaemonTransportError, match="truncated") as error:
        client.resolve_policy_decision({"action": "allow"})
    assert "private" not in str(error.value)
    assert calls["count"] == 1


def test_network_status_retry_timeout_stays_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = {"count": 0}

    def fake_urlopen(_request: urllib.request.Request, *, timeout: float) -> _RawResponse:
        del timeout
        calls["count"] += 1
        if calls["count"] == 1:
            return _RawResponse(read_error=http.client.IncompleteRead(b"{", 8))
        raise TimeoutError("private socket timeout")

    client = GuardSurfaceDaemonClient("http://127.0.0.1:1", "token")
    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    with pytest.raises(GuardDaemonTimeoutError, match="timed out") as error:
        client.network_status()
    assert "private" not in str(error.value)
    assert calls["count"] == 2


@pytest.mark.parametrize("raw_payload", ("not-json", "[]"))
def test_network_status_client_types_invalid_json_object(raw_payload: str) -> None:
    with pytest.raises(GuardDaemonResponseSchemaError):
        GuardSurfaceDaemonClient._decode_json_response(raw_payload)
