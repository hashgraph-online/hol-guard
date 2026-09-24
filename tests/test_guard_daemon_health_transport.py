"""Authenticated daemon health stays within the audited loopback transport boundary."""

from __future__ import annotations

import json
import threading
import time
from contextlib import suppress
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from codex_plugin_scanner.guard.daemon import client, live_identity


def _authenticated_state(guard_home) -> dict[str, object]:
    return {
        "package_version": "3.0.181",
        "host": "127.0.0.1",
        "port": 24781,
        "pid": 321,
        "compatibility_version": live_identity.GUARD_DAEMON_COMPATIBILITY_VERSION,
        "runtime_fingerprint": "runtime-generation-1",
        "generation": "daemon-generation-1",
        "user": "uid:501",
        "start_marker": "process-start-1",
        "guard_home": str(guard_home),
    }


def _health_details(state: dict[str, object]) -> dict[str, object]:
    return {
        "ok": True,
        "guard_home": state["guard_home"],
        "package_version": state["package_version"],
        "compatibility_version": state["compatibility_version"],
        "runtime_fingerprint": state["runtime_fingerprint"],
        "pid": state["pid"],
    }


@pytest.mark.security_critical
@pytest.mark.parametrize(
    "status,body,expected",
    [
        (200, b'{"ok":true}', {"ok": True}),
        (302, b'{"ok":true}', None),
        (500, b'{"ok":true}', None),
        (200, b"[]", None),
        (200, b"not-json", None),
        (200, b"\xff", None),
        (200, b" " * 65_537, None),
    ],
)
def test_health_probe_is_bounded_proxy_free_and_does_not_follow_redirects(
    monkeypatch: pytest.MonkeyPatch, status: int, body: bytes, expected: object
) -> None:
    """Use a real loopback server to verify token delivery and refusal of unsafe responses."""
    requests: list[tuple[str, str | None]] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            """Return the selected response and record any attempted redirect follow-up."""
            requests.append((self.path, self.headers.get("X-Guard-Token")))
            self.send_response(status)
            self.send_header("Location", "/redirected")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, message_format: str, *args: object) -> None:
            """Keep the test server's expected error statuses out of console output."""

    for key in ("HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.setenv(key, "http://127.0.0.1:1")
    monkeypatch.setenv("NO_PROXY", "")
    monkeypatch.setenv("no_proxy", "")
    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_port}"
            assert live_identity._proxy_disabled_health_details(url, "test-token") == expected
            assert requests == [("/v1/healthz/details", "test-token")]
        finally:
            server.shutdown()
            thread.join(timeout=2)


def test_live_identity_shares_remaining_deadline_across_health_and_session_transport(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The default authenticated probe cannot restart its deadline for the dashboard session."""
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    state = {
        "package_version": "3.0.34",
        "host": "127.0.0.1",
        "port": 0,
        "pid": 321,
        "compatibility_version": live_identity.GUARD_DAEMON_COMPATIBILITY_VERSION,
        "runtime_fingerprint": "fingerprint",
        "generation": "generation-1",
        "user": "uid:501",
        "start_marker": "start-generation-1",
        "guard_home": str(guard_home),
    }
    requests: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            requests.append(self.path)
            if self.path == "/v1/healthz/details":
                time.sleep(0.15)
                body = {**state, "ok": True}
            elif self.path == "/v1/capabilities":
                body = {"capabilities": ["dashboard"]}
            else:
                self.send_error(404)
                return
            encoded = json.dumps(body).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            with suppress(OSError):
                self.wfile.write(encoded)

        def do_POST(self) -> None:
            requests.append(self.path)
            if self.path != "/v1/initialize":
                self.send_error(404)
                return
            time.sleep(0.4)
            encoded = b'{"dashboard_session_token":"fresh-session"}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            with suppress(OSError):
                self.wfile.write(encoded)

        def log_message(self, *_args: object) -> None:
            return None

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        state["port"] = server.server_port
        monkeypatch.setattr(live_identity, "load_authenticated_daemon_state", lambda _home: state)
        monkeypatch.setattr(live_identity, "load_guard_daemon_auth_token", lambda _home: "private-auth-token")
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        try:
            started = time.monotonic()
            _identity, reason = live_identity.probe_live_guard_daemon_identity(
                guard_home,
                session_timeout=0.5,
            )
            elapsed = time.monotonic() - started
        finally:
            server.shutdown()
            thread.join(timeout=2)

    assert reason == "session_invalid"
    assert elapsed < 0.75
    assert requests == ["/v1/healthz/details", "/v1/initialize"]


def test_live_identity_requires_the_same_generation_after_dashboard_session(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A daemon replacement during reconnect cannot inherit the earlier health proof."""
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    original = _authenticated_state(guard_home)
    replacement = {**original, "generation": "daemon-generation-2", "start_marker": "process-start-2"}
    states = iter([original, replacement])
    tokens = iter(["initial-token", "refreshed-token"])
    health_requests: list[tuple[str, str]] = []
    session_requests: list[tuple[str, str, float]] = []

    monkeypatch.setattr(live_identity, "load_authenticated_daemon_state", lambda _home: next(states))
    monkeypatch.setattr(live_identity, "load_guard_daemon_auth_token", lambda _home: next(tokens))

    def health(url: str, token: str, *, timeout: float | None = None) -> dict[str, object]:
        health_requests.append((url, token))
        return _health_details(original if len(health_requests) == 1 else replacement)

    def session(url: str, token: str, *, timeout: float) -> dict[str, object]:
        session_requests.append((url, token, timeout))
        return {"capabilities": ["dashboard"]}

    monkeypatch.setattr(live_identity, "_proxy_disabled_health_details", health)
    monkeypatch.setattr(live_identity, "_proxy_dashboard_session_capabilities", session)

    identity, reason = live_identity.probe_live_guard_daemon_identity(guard_home, session_timeout=1.0)

    assert reason == "identity_unverified"
    assert identity == {**original, "daemon_url": "http://127.0.0.1:24781"}
    assert health_requests == [("http://127.0.0.1:24781", "initial-token")]
    assert len(session_requests) == 1


def test_live_identity_does_not_send_refreshed_token_to_replaced_remote_authority(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """State drift is rejected before refreshed credentials reach any new endpoint."""
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    original = _authenticated_state(guard_home)
    replaced = {
        **original,
        "host": "203.0.113.44",
        "port": 443,
    }
    states = iter([original, replaced])
    tokens = iter(["initial-token", "refreshed-private-token"])
    health_requests: list[tuple[str, str]] = []

    monkeypatch.setattr(live_identity, "load_authenticated_daemon_state", lambda _home: next(states))
    monkeypatch.setattr(live_identity, "load_guard_daemon_auth_token", lambda _home: next(tokens))

    def health(url: str, token: str, *, timeout: float | None = None) -> dict[str, object]:
        health_requests.append((url, token))
        return _health_details(original if len(health_requests) == 1 else replaced)

    monkeypatch.setattr(live_identity, "_proxy_disabled_health_details", health)
    monkeypatch.setattr(
        live_identity,
        "_proxy_dashboard_session_capabilities",
        lambda _url, _token, *, timeout: {"capabilities": ["dashboard"]},
    )

    identity, reason = live_identity.probe_live_guard_daemon_identity(guard_home, session_timeout=1.0)

    assert reason == "identity_unverified"
    assert identity == {**original, "daemon_url": "http://127.0.0.1:24781"}
    assert health_requests == [("http://127.0.0.1:24781", "initial-token")]


def test_live_identity_rejects_boolean_initial_port_before_network_access(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Python booleans are integers, but are never valid persisted daemon ports."""
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    state = {**_authenticated_state(guard_home), "port": True}
    monkeypatch.setattr(live_identity, "load_authenticated_daemon_state", lambda _home: state)
    monkeypatch.setattr(live_identity, "load_guard_daemon_auth_token", lambda _home: "private-token")
    monkeypatch.setattr(
        live_identity,
        "_proxy_disabled_health_details",
        lambda *_args, **_kwargs: pytest.fail("Boolean port reached authenticated transport"),
    )

    identity, reason = live_identity.probe_live_guard_daemon_identity(
        guard_home,
        verify_dashboard=False,
    )

    assert identity is None
    assert reason == "identity_unverified"


def test_live_identity_accepts_alias_markers_only_after_matching_refresh(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Legacy marker aliases remain valid only when the refreshed process matches."""
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    original = _authenticated_state(guard_home)
    refreshed = {
        key: value
        for key, value in original.items()
        if key not in {"generation", "user", "start_marker"}
    }
    refreshed.update(
        {
            "runtime": original["runtime_fingerprint"],
            "state_id": original["generation"],
            "uid": original["user"],
            "process_start_marker": original["start_marker"],
        }
    )
    states = iter([original, refreshed])
    tokens = iter(["initial-token", "refreshed-token"])

    monkeypatch.setattr(live_identity, "load_authenticated_daemon_state", lambda _home: next(states))
    monkeypatch.setattr(live_identity, "load_guard_daemon_auth_token", lambda _home: next(tokens))
    monkeypatch.setattr(
        live_identity,
        "_proxy_disabled_health_details",
        lambda _url, _token, *, timeout=None: _health_details(original),
    )
    monkeypatch.setattr(
        live_identity,
        "_proxy_dashboard_session_capabilities",
        lambda _url, _token, *, timeout: {"capabilities": ["dashboard"]},
    )

    identity, reason = live_identity.probe_live_guard_daemon_identity(guard_home, session_timeout=1.0)

    assert reason == "healthy"
    assert identity == {**original, "daemon_url": "http://127.0.0.1:24781"}


def test_live_identity_rejects_markerless_refreshed_state_before_reloading_token(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A session round-trip must retain every process-generation marker."""
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    original = _authenticated_state(guard_home)
    markerless = {
        key: value
        for key, value in original.items()
        if key
        not in {
            "runtime_fingerprint",
            "runtime",
            "generation",
            "state_id",
            "user",
            "uid",
            "start_marker",
            "process_start_marker",
        }
    }
    states = iter([original, markerless])
    loaded_tokens: list[str] = []
    health_requests: list[tuple[str, str]] = []
    session_requests: list[tuple[str, str]] = []

    def load_token(_home) -> str:
        loaded_tokens.append("initial-token")
        return "initial-token"

    monkeypatch.setattr(live_identity, "load_authenticated_daemon_state", lambda _home: next(states))
    monkeypatch.setattr(live_identity, "load_guard_daemon_auth_token", load_token)

    def health(url: str, token: str, *, timeout: float | None = None) -> dict[str, object]:
        health_requests.append((url, token))
        return _health_details(original)

    def session(url: str, token: str, *, timeout: float) -> dict[str, object]:
        session_requests.append((url, token))
        return {"capabilities": ["dashboard"]}

    monkeypatch.setattr(live_identity, "_proxy_disabled_health_details", health)
    monkeypatch.setattr(live_identity, "_proxy_dashboard_session_capabilities", session)

    identity, reason = live_identity.probe_live_guard_daemon_identity(guard_home, session_timeout=1.0)

    assert reason == "identity_unverified"
    assert identity == {**original, "daemon_url": "http://127.0.0.1:24781"}
    assert loaded_tokens == ["initial-token"]
    assert health_requests == [("http://127.0.0.1:24781", "initial-token")]
    assert session_requests == [("http://127.0.0.1:24781", "initial-token")]


def test_live_identity_rejects_empty_refreshed_token_before_second_health_probe(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The refreshed transport cannot be authenticated with an empty bearer value."""
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    state = _authenticated_state(guard_home)
    tokens = iter(["initial-token", ""])
    health_requests: list[tuple[str, str]] = []

    monkeypatch.setattr(live_identity, "load_authenticated_daemon_state", lambda _home: state)
    monkeypatch.setattr(live_identity, "load_guard_daemon_auth_token", lambda _home: next(tokens))

    def health(url: str, token: str, *, timeout: float | None = None) -> dict[str, object]:
        health_requests.append((url, token))
        return _health_details(state)

    monkeypatch.setattr(live_identity, "_proxy_disabled_health_details", health)
    monkeypatch.setattr(
        live_identity,
        "_proxy_dashboard_session_capabilities",
        lambda _url, _token, *, timeout: {"capabilities": ["dashboard"]},
    )

    identity, reason = live_identity.probe_live_guard_daemon_identity(guard_home, session_timeout=1.0)

    assert reason == "identity_unverified"
    assert identity == {**state, "daemon_url": "http://127.0.0.1:24781"}
    assert health_requests == [("http://127.0.0.1:24781", "initial-token")]


@pytest.mark.parametrize("timeout", [0, -1, float("nan"), "invalid"])
def test_live_identity_rejects_invalid_deadlines_before_loading_state(
    tmp_path, monkeypatch: pytest.MonkeyPatch, timeout: object
) -> None:
    """Malformed probe deadlines fail closed before reading authority or opening transport."""

    def unexpected_state(_home) -> dict[str, object]:
        pytest.fail("Invalid timeout reached authenticated daemon-state loading")

    monkeypatch.setattr(live_identity, "load_authenticated_daemon_state", unexpected_state)

    identity, reason = live_identity.probe_live_guard_daemon_identity(
        tmp_path,
        session_timeout=timeout,  # type: ignore[arg-type]
    )

    assert identity is None
    assert reason == "service_unresponsive"


@pytest.mark.security_critical
@pytest.mark.parametrize(
    "url",
    [
        "http://example.test:1234",
        "https://127.0.0.1:1234",
        "http://127.0.0.1",
        "http://user:password@127.0.0.1:1234",
        "http://127.0.0.1:0",
        "http://127.0.0.1:65536",
        "http://127.0.0.1:1234/wrong-path",
        "http://127.0.0.1:1234?redirect=external",
        "http://[::1]:1234#fragment",
    ],
)
def test_health_probe_rejects_invalid_authorities_before_connecting(monkeypatch: pytest.MonkeyPatch, url: str) -> None:
    """Malformed and non-loopback URLs must not open a socket with the daemon token."""

    def unexpected_connection(*args: object, **kwargs: object) -> None:
        """Fail immediately if URL validation allows a network connection."""
        pytest.fail("Invalid daemon authority reached the network transport")

    monkeypatch.setattr(client, "HTTPConnection", unexpected_connection)
    assert client.read_guard_health_details(url, "test-token") is None


@pytest.mark.security_critical
@pytest.mark.parametrize("drip_headers", [False, True])
def test_health_probe_enforces_deadline_against_byte_drip(monkeypatch: pytest.MonkeyPatch, drip_headers: bool) -> None:
    """Neither a partial header nor a slowly arriving body can extend the total deadline."""

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            """Drip bytes more frequently than the socket timeout until the client closes."""
            if not drip_headers:
                self.send_response(200)
                self.send_header("Content-Length", "1000")
                self.end_headers()
            try:
                for _ in range(100):
                    self.wfile.write(b"x")
                    self.wfile.flush()
                    time.sleep(0.04)
            except OSError:
                pass  # The deadline deliberately closes the client connection.

        def log_message(self, message_format: str, *args: object) -> None:
            """Suppress expected loopback-test access logs."""

    monkeypatch.setattr(client, "_HEALTH_PROBE_DEADLINE_SECONDS", 0.2)
    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        try:
            started = time.monotonic()
            result = client.read_guard_health_details(f"http://127.0.0.1:{server.server_port}", "test-token")
            elapsed = time.monotonic() - started
            assert result is None
            assert elapsed < 1.0
        finally:
            server.shutdown()
            thread.join(timeout=2)
