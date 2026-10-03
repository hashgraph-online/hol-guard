"""Authenticated daemon health stays within the audited loopback transport boundary."""

from __future__ import annotations

import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from codex_plugin_scanner.guard.daemon import client, live_identity


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
@pytest.mark.parametrize("outer_deadline", [False, True])
def test_health_probe_enforces_deadline_against_byte_drip(
    monkeypatch: pytest.MonkeyPatch,
    drip_headers: bool,
    outer_deadline: bool,
) -> None:
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
            result = client.read_guard_health_details(
                f"http://127.0.0.1:{server.server_port}",
                "test-token",
                deadline_monotonic=started + 0.08 if outer_deadline else None,
            )
            elapsed = time.monotonic() - started
            assert result is None
            assert elapsed < (0.5 if outer_deadline else 1.0)
        finally:
            server.shutdown()
            thread.join(timeout=2)


@pytest.mark.parametrize("deadline", [float("nan"), float("inf"), True, -1.0])
def test_health_probe_invalid_or_expired_operation_deadline_never_connects(monkeypatch, deadline):
    def unexpected_connection(*args, **kwargs):
        pytest.fail("expired or invalid operation opened a connection")

    monkeypatch.setattr(client, "HTTPConnection", unexpected_connection)
    assert (
        client.read_guard_health_details(
            "http://127.0.0.1:1234",
            "test-token",
            deadline_monotonic=deadline,
        )
        is None
    )


@pytest.mark.parametrize(
    "fault",
    [None, "version", "fingerprint", "path", "source", "superseded", "expiry", "reread_expiry"],
)
def test_exact_live_identity_requires_planned_executable_generation_through_admission(tmp_path, monkeypatch, fault):
    executable = tmp_path / "core-generation" / "hol-guard"
    binding = live_identity.DaemonArtifactBinding(executable, "a" * 64, "3.13.1")
    state = {
        "package_version": binding.package_version,
        "executable": str(executable),
        "source_root": str(executable),
        "runtime_fingerprint": binding.executable_sha256,
        "pid": 123,
        "host": "127.0.0.1",
        "port": 4321,
        "state_id": "first-state",
        "compatibility_version": live_identity.GUARD_DAEMON_COMPATIBILITY_VERSION,
    }
    if fault in {"version", "fingerprint", "path", "source"}:
        field, value = {
            "version": ("package_version", "4.0.0"),
            "fingerprint": ("runtime_fingerprint", "b" * 64),
            "path": ("executable", str(tmp_path / "foreign-core")),
            "source": ("source_root", str(tmp_path / "foreign-source")),
        }[fault]
        state[field] = value
    current = dict(state)
    calls = []
    deadline = time.monotonic() + 5
    state_reads = []

    def read_state(_home):
        state_reads.append(True)
        if fault == "reread_expiry" and len(state_reads) == 2:
            monkeypatch.setattr(live_identity.time, "monotonic", lambda: deadline + 1)
        return dict(current)

    monkeypatch.setattr(live_identity, "load_authenticated_daemon_state", read_state)
    monkeypatch.setattr(live_identity, "load_guard_daemon_auth_token", lambda _home: "fixture-token")

    def health(url, token, *, deadline_monotonic):
        calls.append((url, token, deadline_monotonic))
        if fault == "superseded":
            current["state_id"] = "replacement-state"
        if fault == "expiry":
            monkeypatch.setattr(live_identity.time, "monotonic", lambda: deadline + 1)
        return {**state, "ok": True, "guard_home": str(tmp_path)}

    monkeypatch.setattr(live_identity, "_proxy_disabled_health_details", health)
    result = live_identity.verified_live_guard_daemon_identity(
        tmp_path,
        expected_artifact=binding,
        deadline_monotonic=deadline,
    )
    if fault is None:
        assert result is not None and binding.matches(result)
    else:
        assert result is None
    assert len(calls) == (0 if fault in {"version", "fingerprint", "path", "source"} else 1)
    if calls:
        assert calls[0][2] == deadline
