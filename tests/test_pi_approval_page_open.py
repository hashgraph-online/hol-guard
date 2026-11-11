"""The Pi-family extension opens the approval page unless Guard says never to."""

from __future__ import annotations

import json
import os
import subprocess
import threading
import time
from collections.abc import Iterator
from contextlib import suppress
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from tests.pi_extension_template import fragment
from tests.test_guard_settings_api import _with_daemon
from tests.test_pi_hook_latency import _bun_executable, _decode_json_object

pytestmark = pytest.mark.skipif(
    _bun_executable() is None or os.name == "nt",
    reason="Runs the generated extension fragment with Bun on POSIX",
)

TOKEN = "settings-read-token"


class _Settings:
    """A loopback daemon that answers ``GET /v1/settings`` and records each read."""

    def __init__(self) -> None:
        self.status = 200
        self.body: bytes = b"{}"
        self.delay = 0.0
        self.reads: list[dict[str, str | None]] = []


@pytest.fixture
def daemon() -> Iterator[tuple[_Settings, int]]:
    settings = _Settings()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            settings.reads.append({"path": self.path, "token": self.headers.get("X-Guard-Token")})
            time.sleep(settings.delay)
            self.send_response(settings.status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(settings.body)))
            self.end_headers()
            # A timed-out client has already closed this response.
            with suppress(BrokenPipeError, ConnectionResetError):
                self.wfile.write(settings.body)

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - http.server API
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield settings, server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()


def _policy_body(policy: object) -> bytes:
    return json.dumps({"settings": {"approval_surface_policy": policy}}).encode("utf-8")


def _open_twice(
    tmp_path: Path, connection: dict[str, object] | None, harness_name: str = "omp"
) -> dict[str, object]:
    """Pause twice on one approval center and report what the extension spawned."""

    harness = tmp_path / "open.ts"
    _ = harness.write_text(
        "const calls: Array<{ command: string; args: string[] }> = [];\n"
        "function spawn(command: string, args: string[]) {\n"
        "  calls.push({ command, args });\n"
        "  const child = {\n"
        "    once(event: string, listener: () => void) {\n"
        "      if (event === 'spawn') queueMicrotask(listener);\n"
        "      return child;\n"
        "    },\n"
        "    unref() {},\n"
        "  };\n"
        "  return child;\n"
        "}\n"
        "type GuardResponse = { approval_url?: string };\n"
        f"const CONNECTION = {json.dumps(connection)};\n"
        "function loadGuardDaemonConnection() { return CONNECTION; }\n"
        "function approvalUrlFromResponse(response: GuardResponse): string | null {\n"
        "  return typeof response.approval_url === 'string' ? response.approval_url : null;\n"
        "}\n"
        "function approvalCenterKey(approvalUrl: string): string { return new URL(approvalUrl).origin; }\n"
        + fragment("approval_page_open", harness=harness_name)
        + "const opened = new Set<string>();\n"
        "await openApprovalUrl({ approval_url: 'http://127.0.0.1:9/requests/first' }, opened);\n"
        "await openApprovalUrl({ approval_url: 'http://127.0.0.1:9/requests/second' }, opened);\n"
        "console.log(JSON.stringify({ calls, opened: [...opened] }));\n",
        encoding="utf-8",
    )
    bun = _bun_executable()
    assert bun is not None
    completed = subprocess.run([bun, str(harness)], check=True, capture_output=True, text=True, timeout=20)
    return _decode_json_object(completed.stdout)


def _calls(result: dict[str, object]) -> list[dict[str, object]]:
    calls = result["calls"]
    assert isinstance(calls, list)
    return [call for call in calls if isinstance(call, dict)]


def _connection(port: int) -> dict[str, object]:
    return {"port": port, "authToken": TOKEN, "stateId": None}


@pytest.mark.parametrize("harness_name", ["pi", "omp"])
def test_never_open_a_browser_keeps_the_page_closed(
    tmp_path: Path, daemon: tuple[_Settings, int], harness_name: str
) -> None:
    settings, port = daemon
    settings.body = _policy_body("native-only")

    result = _open_twice(tmp_path, _connection(port), harness_name)

    assert result == {"calls": [], "opened": []}
    # Each pause asks again, so turning the setting off works in the same session.
    assert settings.reads == [{"path": "/v1/settings", "token": TOKEN}] * 2


@pytest.mark.parametrize("policy", ["attention-aware", "approval-center", None, ["native-only"]])
def test_any_other_setting_opens_the_page_once(tmp_path: Path, daemon: tuple[_Settings, int], policy: object) -> None:
    settings, port = daemon
    settings.body = _policy_body(policy)

    result = _open_twice(tmp_path, _connection(port))

    calls = _calls(result)
    assert len(calls) == 1
    args = calls[0]["args"]
    assert isinstance(args, list) and args[-1] == "http://127.0.0.1:9/requests/first"
    assert result["opened"] == ["http://127.0.0.1:9"]
    assert len(settings.reads) == 1


@pytest.mark.parametrize(("status", "body"), [(500, b"{}"), (403, _policy_body("native-only")), (200, b"not json")])
def test_a_failed_settings_read_still_opens_the_page(
    tmp_path: Path, daemon: tuple[_Settings, int], status: int, body: bytes
) -> None:
    settings, port = daemon
    settings.status = status
    settings.body = body

    result = _open_twice(tmp_path, _connection(port))

    assert len(_calls(result)) == 1
    assert len(settings.reads) == 1


def test_no_reachable_daemon_still_opens_the_page(tmp_path: Path, daemon: tuple[_Settings, int]) -> None:
    settings, port = daemon

    assert len(_calls(_open_twice(tmp_path, None))) == 1
    # A port nothing listens on: the read fails and the page opens as before.
    with ThreadingHTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler) as probe:
        closed_port = probe.server_address[1]
    assert closed_port != port
    assert len(_calls(_open_twice(tmp_path, _connection(closed_port)))) == 1
    assert settings.reads == []


def test_stalled_settings_read_opens_within_timeout(tmp_path: Path, daemon: tuple[_Settings, int]) -> None:
    settings, port = daemon
    settings.delay = 8.0
    settings.body = _policy_body("native-only")
    started = time.monotonic()

    result = _open_twice(tmp_path, _connection(port))

    assert len(_calls(result)) == 1
    assert 1.0 <= time.monotonic() - started < 6.0
    assert len(settings.reads) == 1


@pytest.mark.parametrize(("config", "opens"), [('approval_surface_policy = "native-only"\n', False), ("", True)])
def test_the_guard_daemon_answers_the_settings_read(tmp_path: Path, config: str, opens: bool) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir()
    _ = (guard_home / "config.toml").write_text(config, encoding="utf-8")
    _store, daemon = _with_daemon(guard_home)
    try:
        connection = {"port": daemon.port, "authToken": daemon._server.auth_token, "stateId": None}
        result = _open_twice(tmp_path, connection)
    finally:
        daemon.stop()

    assert len(_calls(result)) == (1 if opens else 0)
