"""Cloud actions sign-in against a local stand-in for Guard Cloud.

The stand-in speaks the same metadata, registration, token and revocation
shapes as Guard Cloud. Each test bends one answer and checks that nothing is
saved unless every check passes, and that no credential reaches the output.
"""

from __future__ import annotations

import base64
import http.server
import io
import json
import stat
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner import cli
from codex_plugin_scanner.guard.cli import commands_dispatch_cloud_actions as dispatch
from codex_plugin_scanner.guard.cli.cloud_actions_login import sign_in
from codex_plugin_scanner.guard.cli.cloud_actions_oauth import (
    CLOUD_ACTIONS_SCOPES,
    CloudActionsSignInError,
    resolve_cloud_origin,
)
from codex_plugin_scanner.guard.cli.cloud_actions_session import CloudActionsSessionStore

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
    counter: int = 0

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


@pytest.fixture
def cloud() -> Iterator[FakeCloud]:
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


@pytest.fixture
def browser(cloud: FakeCloud, monkeypatch: pytest.MonkeyPatch) -> Browser:
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


def test_sign_in_saves_one_workspace_and_prints_no_credentials(
    cloud: FakeCloud, browser: Browser, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = _login(cloud, tmp_path, "--cloud-workspace", WS)
    payload, output = _json_out(capsys)

    assert exit_code == 0, output
    assert payload == {
        "schema": "guard.cloud-actions.v1",
        "command": "login",
        "state": "signed_in",
        "profile": "default",
        "cloud_url": cloud.origin,
        "cloud_workspace": WS,
        "scopes": list(CLOUD_ACTIONS_SCOPES),
        "expires_at": payload["expires_at"],
    }
    for secret in cloud.issued:
        assert secret not in output
        assert secret.encode() not in _all_file_bytes(tmp_path)
    store = CloudActionsSessionStore(tmp_path)
    saved = store.load_secrets("default")
    assert saved is not None
    assert saved.refresh_token == "refresh-secret-1"
    profile_file = tmp_path / "cloud-actions" / "profiles" / "default.json"
    if sys.platform != "win32":
        assert stat.S_IMODE(profile_file.stat().st_mode) == 0o600
        assert stat.S_IMODE(profile_file.parent.stat().st_mode) == 0o700


def test_sign_in_asks_only_for_cloud_actions(
    cloud: FakeCloud, browser: Browser, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert _login(cloud, tmp_path, "--cloud-workspace", WS) == 0
    capsys.readouterr()

    [registration] = cloud.registrations
    assert registration["token_endpoint_auth_method"] == "none"
    assert registration["grant_types"] == ["authorization_code", "refresh_token"]
    assert set(registration["scope"].split()) == set(CLOUD_ACTIONS_SCOPES)
    assert all(urllib.parse.urlsplit(uri).hostname in {"127.0.0.1", "::1"} for uri in registration["redirect_uris"])
    [url] = browser.opened
    params = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).query))
    assert url.startswith(f"{cloud.origin}/api/guard/oauth/authorize?")
    assert params["resource"] == f"{cloud.origin}{RESOURCE_PATH}"
    assert params["scope"].split() == list(CLOUD_ACTIONS_SCOPES)
    assert params["code_challenge_method"] == "S256"
    assert params["workspace_id"] == WS
    assert not {"runtime_id", "machine_id", "application_id", "runtime_label", "audience"} & set(params)
    assert urllib.parse.urlsplit(params["redirect_uri"]).hostname == "127.0.0.1"
    [token_request] = cloud.token_requests
    assert token_request["grant_type"] == "authorization_code"
    assert token_request["resource"] == params["resource"]
    assert token_request["redirect_uri"] == params["redirect_uri"]
    assert len(token_request["code_verifier"]) >= 43


def test_registered_client_is_reused_for_the_same_cloud(
    cloud: FakeCloud, browser: Browser, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert _login(cloud, tmp_path) == 0
    assert _login(cloud, tmp_path, "--profile", "second") == 0
    capsys.readouterr()

    assert len(cloud.registrations) == 1
    assert {request["client_id"] for request in cloud.token_requests} == {"guard-dcr-1"}


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"authorization_server": {"issuer": "https://hol.org"}}, "metadata_issuer_mismatch"),
        ({"protected_resource": {"resource": "https://hol.org/api/guard/gateway/mcp"}}, "metadata_resource_mismatch"),
        ({"protected_resource": {"authorization_servers": ["https://hol.org"]}}, "metadata_origin_mismatch"),
        (
            {"authorization_server": {"token_endpoint": "https://hol.org/api/guard/oauth/token"}},
            "metadata_origin_mismatch",
        ),
        ({"authorization_server": {"code_challenge_methods_supported": ["plain"]}}, "metadata_invalid"),
        ({"disabled": True}, "cloud_actions_not_enabled"),
    ],
    ids=["issuer", "resource", "authorization-server", "endpoint-origin", "no-s256", "not-enabled"],
)
def test_metadata_for_another_server_is_refused_before_the_browser_opens(
    cloud: FakeCloud,
    browser: Browser,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    overrides: dict[str, Any],
    reason: str,
) -> None:
    cloud.overrides.update(overrides)

    exit_code = _login(cloud, tmp_path)
    payload, _ = _json_out(capsys)

    assert exit_code == 1
    assert payload["state"] == "failed"
    assert payload["reason"] == reason
    assert browser.opened == []
    assert cloud.registrations == []
    assert not (tmp_path / "cloud-actions" / "profiles").exists()


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"claims": {"aud": "local-daemon"}}, "grant_audience_mismatch"),
        ({"claims": {"aud": "https://hol.org/api/guard/gateway/mcp"}}, "grant_audience_mismatch"),
        ({"claims": {"client_id": "hol-guard-local"}}, "grant_client_mismatch"),
        ({"token": {"scope": "gateway:discover guard:sync"}}, "grant_scope_mismatch"),
        ({"token": {"scope": ""}}, "grant_scope_mismatch"),
        ({"token": {"token_type": "DPoP"}}, "grant_invalid"),
        ({"claims": {"workspace": None}}, "grant_invalid"),
        ({"workspace": OTHER_WS}, "workspace_mismatch"),
    ],
    ids=[
        "local-daemon-audience",
        "other-cloud-audience",
        "other-client",
        "extra-scope",
        "no-scope",
        "not-bearer",
        "no-workspace",
        "other-workspace",
    ],
)
def test_a_grant_that_is_not_for_cloud_actions_is_revoked_and_not_saved(
    cloud: FakeCloud,
    browser: Browser,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    overrides: dict[str, Any],
    reason: str,
) -> None:
    cloud.overrides.update(overrides)

    exit_code = _login(cloud, tmp_path, "--cloud-workspace", WS)
    payload, output = _json_out(capsys)

    assert exit_code == 1
    assert payload["reason"] == reason
    assert not (tmp_path / "cloud-actions" / "profiles").exists()
    assert {entry["token"] for entry in cloud.revocations} == set(cloud.issued)
    for secret in cloud.issued:
        assert secret not in output


@pytest.mark.parametrize(
    ("callback", "reason"),
    [
        ({"iss": "https://hol.org"}, "callback_issuer_mismatch"),
        ({"iss": None}, "callback_issuer_mismatch"),
        ({"code": None, "error": "access_denied"}, "sign_in_declined"),
        ({"code": None, "error": "invalid_scope"}, "sign_in_refused"),
    ],
    ids=["other-issuer", "missing-issuer", "declined", "refused"],
)
def test_a_callback_that_fails_its_checks_never_reaches_the_token_endpoint(
    cloud: FakeCloud,
    browser: Browser,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    callback: dict[str, str | None],
    reason: str,
) -> None:
    browser.callback.update(callback)

    exit_code = _login(cloud, tmp_path)
    payload, _ = _json_out(capsys)

    assert exit_code == 1
    assert payload["reason"] == reason
    assert cloud.token_requests == []
    assert not (tmp_path / "cloud-actions" / "profiles").exists()


def test_a_callback_with_another_state_is_ignored(cloud: FakeCloud, tmp_path: Path) -> None:
    browser = Browser(cloud, callback={"state": "someone-elses-state"})

    with pytest.raises(CloudActionsSignInError) as raised:
        _ = sign_in(
            store=CloudActionsSessionStore(tmp_path),
            profile_name="default",
            cloud_url=cloud.origin,
            workspace_id=None,
            timeout_seconds=1,
            open_browser=browser,
            notice=io.StringIO(),
        )

    assert raised.value.reason == "sign_in_timed_out"
    assert browser.statuses == [400]
    assert cloud.token_requests == []


def test_cancelling_saves_nothing(
    cloud: FakeCloud, tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    def interrupt(url: str) -> bool:
        del url
        raise KeyboardInterrupt

    monkeypatch.setattr(dispatch, "open_browser_url", interrupt)

    exit_code = _login(cloud, tmp_path)
    payload, _ = _json_out(capsys)

    assert exit_code == 130
    assert payload["state"] == "cancelled"
    assert cloud.token_requests == []
    assert not (tmp_path / "cloud-actions" / "profiles").exists()


def test_no_browser_prints_the_link_on_stderr_only(
    cloud: FakeCloud, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    store = CloudActionsSessionStore(tmp_path)
    notice = io.StringIO()
    browser = Browser(cloud)

    profile = sign_in(
        store=store,
        profile_name="default",
        cloud_url=cloud.origin,
        workspace_id=None,
        timeout_seconds=5,
        open_browser=lambda url: browser(url) and False,
        notice=notice,
    )

    assert profile.workspace_id == WS
    assert notice.getvalue().startswith("Open this link to sign in:\n")
    assert capsys.readouterr().out == ""


def test_profiles_keep_workspaces_apart(
    cloud: FakeCloud, browser: Browser, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert _login(cloud, tmp_path, "--cloud-workspace", WS, "--profile", "work") == 0
    cloud.overrides["workspace"] = OTHER_WS
    assert _login(cloud, tmp_path, "--cloud-workspace", OTHER_WS, "--profile", "client") == 0
    capsys.readouterr()
    home = ("--guard-home", str(tmp_path), "--json")

    assert _cli("status", "--profile", "work", *home) == 0
    work, _ = _json_out(capsys)
    assert (work["state"], work["cloud_workspace"]) == ("signed_in", WS)
    assert _cli("status", "--profile", "work", "--cloud-workspace", OTHER_WS, *home) == 0
    assert _json_out(capsys)[0]["workspace_matches"] is False

    assert _cli("workspace", "select", OTHER_WS, "--profile", "work", *home) == 4
    refused, _ = _json_out(capsys)
    assert refused["reason"] == "workspace_needs_sign_in"
    assert refused["signed_in_workspace"] == WS
    assert _cli("workspace", "select", OTHER_WS, "--profile", "client", *home) == 0
    assert _json_out(capsys)[0]["state"] == "selected"
    assert _cli("status", *home) == 0
    assert _json_out(capsys)[0]["state"] == "signed_out"


def test_workspace_select_points_to_the_sign_in_command(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = _cli("workspace", "select", WS, "--profile", "work", "--guard-home", str(tmp_path))

    assert exit_code == 4
    assert f"hol-guard cloud-actions login --cloud-workspace {WS} --profile work" in capsys.readouterr().out


def test_signing_in_again_ends_the_previous_grant(
    cloud: FakeCloud, browser: Browser, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert _login(cloud, tmp_path) == 0
    first_access, first_refresh = cloud.issued
    assert _login(cloud, tmp_path) == 0
    capsys.readouterr()

    assert {entry["token"] for entry in cloud.revocations} == {first_access, first_refresh}
    saved = CloudActionsSessionStore(tmp_path).load_secrets("default")
    assert saved is not None and saved.refresh_token == "refresh-secret-2"


def test_a_failed_sign_in_keeps_the_previous_one(
    cloud: FakeCloud, browser: Browser, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert _login(cloud, tmp_path, "--cloud-workspace", WS) == 0
    cloud.overrides["workspace"] = OTHER_WS
    assert _login(cloud, tmp_path, "--cloud-workspace", WS) == 1
    capsys.readouterr()

    profile = CloudActionsSessionStore(tmp_path).load("default")
    assert profile is not None and profile.workspace_id == WS
    assert CloudActionsSessionStore(tmp_path).load_secrets("default") is not None


def test_logout_ends_the_grant_and_removes_it(
    cloud: FakeCloud, browser: Browser, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert _login(cloud, tmp_path) == 0
    capsys.readouterr()

    assert _cli("logout", "--guard-home", str(tmp_path), "--json") == 0
    payload, _ = _json_out(capsys)

    assert (payload["was_signed_in"], payload["revoked"]) == (True, True)
    assert {entry["token_type_hint"] for entry in cloud.revocations} == {"refresh_token", "access_token"}
    store = CloudActionsSessionStore(tmp_path)
    assert store.load("default") is None
    assert store.load_secrets("default") is None


def test_status_reports_an_expired_sign_in(
    cloud: FakeCloud, browser: Browser, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert _login(cloud, tmp_path) == 0
    capsys.readouterr()
    profile_file = tmp_path / "cloud-actions" / "profiles" / "default.json"
    record = json.loads(profile_file.read_text())
    record["expires_at"] = "2020-01-01T00:00:00Z"
    profile_file.write_text(json.dumps(record))

    assert _cli("status", "--guard-home", str(tmp_path), "--json") == 0

    assert _json_out(capsys)[0]["state"] == "expired"


def test_sign_in_leaves_the_device_sign_in_alone(
    cloud: FakeCloud, browser: Browser, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert _login(cloud, tmp_path) == 0
    capsys.readouterr()

    top_level = {path.name for path in tmp_path.iterdir()}
    assert top_level <= {"cloud-actions", "secrets"}
    assert {path.name for path in (tmp_path / "secrets").iterdir() if not path.name.startswith(".")} <= {
        "key.bin",
        "cloud-actions-default.enc",
    }


@pytest.mark.parametrize(
    "url",
    [
        "https://guard.example.com",
        "http://hol.org",
        "https://user@hol.org",
        "ftp://127.0.0.1",
        "hol.org",
    ],
)
def test_only_hol_guard_cloud_or_this_computer_is_accepted(url: str) -> None:
    with pytest.raises(CloudActionsSignInError):
        _ = resolve_cloud_origin(url)


def test_cloud_url_is_reduced_to_its_origin() -> None:
    assert resolve_cloud_origin("https://hol.org/guard/connect") == "https://hol.org"
    assert resolve_cloud_origin("http://127.0.0.1:3017") == "http://127.0.0.1:3017"
