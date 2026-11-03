"""Local stand-in for Guard Cloud and CLI helpers for the Cloud actions sign-in tests.

The stand-in speaks the same metadata, registration, token and revocation
shapes as Guard Cloud; tests change `FakeCloud.overrides` to bend one answer.
"""

from __future__ import annotations

import base64
import http.server
import json
import threading
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner import cli
from codex_plugin_scanner.guard.cli import commands_dispatch_cloud_actions as dispatch
from codex_plugin_scanner.guard.cli.cloud_actions_oauth import CLOUD_ACTIONS_SCOPES

WS = "4f0c2b9e-1d7a-4c3e-9b8a-2e5f6a7b8c9d"
OTHER_WS = "0b6e7a52-9f1c-4d3e-8a2b-7c6d5e4f3a21"
RESOURCE_PATH = "/api/guard/gateway/mcp"


def _jwt(claims: dict[str, object]) -> str:
    def part(value: dict[str, object]) -> str:
        return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")

    return f"{part({'alg': 'ES256', 'typ': 'JWT'})}.{part(claims)}.c2ln"


@dataclass
class FakeCloud:
    """Answers like Guard Cloud; tests change `overrides` to bend one answer."""

    origin: str = ""
    overrides: dict[str, Any] = field(default_factory=dict)
    registrations: list[dict[str, Any]] = field(default_factory=list)
    token_requests: list[dict[str, str]] = field(default_factory=list)
    revocations: list[dict[str, str]] = field(default_factory=list)
    issued: list[str] = field(default_factory=list)
    gateway_requests: list[dict[str, str]] = field(default_factory=list)
    rejected: set[str] = field(default_factory=set)
    counter: int = 0

    def gateway(self, authorization: str) -> tuple[int, dict[str, Any]]:
        """Answer like the gateway before its methods land: 501 once the bearer is accepted."""

        status = self.overrides.get("gateway_status")
        if isinstance(status, int):
            return status, {"jsonrpc": "2.0", "id": None, "error": {"code": -32000, "message": "refused"}}
        token = authorization.removeprefix("Bearer ")
        if token not in self.issued or token in self.rejected:
            return 401, {"jsonrpc": "2.0", "id": None, "error": {"code": -32000, "message": "Invalid token"}}
        return 501, {"jsonrpc": "2.0", "id": None, "error": {"code": -32601, "message": "Not available yet"}}

    def protected_resource(self) -> dict[str, Any]:
        body = {
            "resource": f"{self.origin}{RESOURCE_PATH}",
            "authorization_servers": [self.origin],
            "scopes_supported": list(CLOUD_ACTIONS_SCOPES),
        }
        body.update(self.overrides.get("protected_resource", {}))
        return body

    def authorization_server(self) -> dict[str, Any]:
        body = {
            "issuer": self.origin,
            "authorization_endpoint": f"{self.origin}/api/guard/oauth/authorize",
            "token_endpoint": f"{self.origin}/api/guard/oauth/token",
            "registration_endpoint": f"{self.origin}/api/guard/oauth/register",
            "revocation_endpoint": f"{self.origin}/api/guard/oauth/revoke",
            "code_challenge_methods_supported": ["S256"],
            "authorization_response_iss_parameter_supported": True,
        }
        body.update(self.overrides.get("authorization_server", {}))
        return body

    def token(self, form: dict[str, str]) -> dict[str, Any]:
        self.counter += 1
        claims: dict[str, Any] = {
            "aud": form.get("resource"),
            "client_id": form.get("client_id"),
            "workspace": {"workspaceId": self.overrides.get("workspace", WS)},
            "grant": {"grantId": f"grant-{self.counter}", "scopeIds": list(CLOUD_ACTIONS_SCOPES)},
        }
        claims.update(self.overrides.get("claims", {}))
        access = _jwt(claims)
        refresh = f"refresh-secret-{self.counter}"
        self.issued += [access, refresh]
        body: dict[str, Any] = {
            "access_token": access,
            "refresh_token": refresh,
            "expires_in": 900,
            "scope": " ".join(CLOUD_ACTIONS_SCOPES),
            "token_type": "Bearer",
        }
        body.update(self.overrides.get("token", {}))
        return body


@contextmanager
def serve_fake_cloud() -> Iterator[FakeCloud]:
    state = FakeCloud()

    class Handler(http.server.BaseHTTPRequestHandler):
        def _send(self, status: int, body: object) -> None:
            raw = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self) -> None:
            if self.path == f"/.well-known/oauth-protected-resource{RESOURCE_PATH}":
                if state.overrides.get("disabled"):
                    self._send(404, {"error": "not_found"})
                    return
                self._send(200, state.protected_resource())
            elif self.path == "/.well-known/oauth-authorization-server":
                self._send(200, state.authorization_server())
            else:
                self._send(404, {"error": "not_found"})

        def do_POST(self) -> None:
            raw = self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode()
            if self.path == "/api/guard/oauth/register":
                body = json.loads(raw)
                state.registrations.append(body)
                self._send(201, {"client_id": f"guard-dcr-{len(state.registrations)}", **body})
            elif self.path == "/api/guard/oauth/token":
                form = dict(urllib.parse.parse_qsl(raw))
                state.token_requests.append(form)
                self._send(200, state.token(form))
            elif self.path == RESOURCE_PATH:
                if state.overrides.get("disabled"):
                    self._send(404, {"error": "not_found"})
                    return
                state.gateway_requests.append({key.lower(): value for key, value in self.headers.items()})
                redirect = state.overrides.get("gateway_redirect")
                if isinstance(redirect, str):
                    self.send_response(307)
                    self.send_header("Location", redirect)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                self._send(*state.gateway(self.headers.get("Authorization", "")))
            elif self.path == "/api/guard/oauth/revoke":
                state.revocations.append(dict(urllib.parse.parse_qsl(raw)))
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()
            else:
                self._send(404, {"error": "not_found"})

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            del format, args

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    state.origin = f"http://127.0.0.1:{server.server_address[1]}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield state
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture(name="cloud")
def cloud_fixture() -> Iterator[FakeCloud]:
    with serve_fake_cloud() as state:
        yield state


@dataclass
class Browser:
    """Stands in for the person approving in the browser."""

    cloud: FakeCloud
    opened: list[str] = field(default_factory=list)
    callback: dict[str, str | None] = field(default_factory=dict)
    statuses: list[int] = field(default_factory=list)

    def __call__(self, url: str) -> bool:
        self.opened.append(url)
        params = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))
        answer: dict[str, str | None] = {"code": "the-code", "state": params["state"], "iss": self.cloud.origin}
        answer.update(self.callback)
        query = urllib.parse.urlencode({key: value for key, value in answer.items() if value is not None})
        try:
            with urllib.request.urlopen(f"{params['redirect_uri']}?{query}", timeout=5) as response:
                self.statuses.append(response.status)
        except urllib.error.HTTPError as error:
            self.statuses.append(error.code)
        return True


@pytest.fixture(name="browser")
def browser_fixture(cloud: FakeCloud, monkeypatch: pytest.MonkeyPatch) -> Browser:
    opener = Browser(cloud)
    monkeypatch.setattr(dispatch, "open_browser_url", opener)
    return opener


def _cli(*argv: str) -> int:
    try:
        return cli.main(["cloud-actions", *argv])
    except SystemExit as exit_:
        return int(exit_.code or 0)


def _login(cloud: FakeCloud, home: Path, *extra: str) -> int:
    return _cli("login", "--cloud-url", cloud.origin, "--guard-home", str(home), "--json", *extra)


def _json_out(capsys: pytest.CaptureFixture[str]) -> tuple[dict[str, Any], str]:
    captured = capsys.readouterr()
    return json.loads(captured.out), captured.out + captured.err


def _all_file_bytes(home: Path) -> bytes:
    return b"".join(path.read_bytes() for path in home.rglob("*") if path.is_file())
