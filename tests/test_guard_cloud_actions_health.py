"""`cloud-actions status` and `doctor` from the `hol-guard connect` pairing.

A local stand-in plays Guard Cloud: the public Cloud actions description and
the Cloud actions server. The pairing and the exchange are replaced (see
cloud_actions_pairing_support); cloud_actions_access has its own tests. Each
test bends one answer and checks the reported state matches what Guard Cloud
said, and that the exchanged access never reaches the output, a bundle or
another server.
"""

from __future__ import annotations

import http.server
import json
import os
import socket
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner import cli
from codex_plugin_scanner.guard.cli import cloud_actions_health
from codex_plugin_scanner.guard.cli import commands_dispatch_cloud_actions_status as status_commands
from codex_plugin_scanner.guard.cli.cloud_actions_access import CloudActionsAccessError, CloudActionsPairing
from tests.cloud_actions_pairing_support import WS, FakeCloud, pair

RESOURCE_PATH = "/api/guard/gateway/mcp"
ACCESS = "exchanged-access"
_REAL_RENEWAL_REFUSED = status_commands._renewal_refused  # pyright: ignore[reportPrivateUsage]
_NOT_YET = {"jsonrpc": "2.0", "id": "hol-guard-status", "error": {"code": -32601, "message": "Method not found"}}


@dataclass
class StandIn:
    """Answers like Guard Cloud; tests change one field to bend one answer."""

    origin: str = ""
    description_status: int = 200
    description: dict[str, Any] | None = None
    ping_status: int = 501
    ping_body: bytes = json.dumps(_NOT_YET).encode()
    ping_headers: dict[str, str] = field(default_factory=dict)
    gets: list[str] = field(default_factory=list)
    posts: list[dict[str, str]] = field(default_factory=list)

    def default_description(self) -> dict[str, Any]:
        return {
            "resource": f"{self.origin}{RESOURCE_PATH}",
            "scopes_supported": ["gateway:discover", "gateway:invoke"],
        }


def _serve(state: StandIn) -> tuple[http.server.ThreadingHTTPServer, str]:
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - base class signature
            return

        def _reply(self, status: int, raw: bytes, headers: dict[str, str] | None = None) -> None:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            for name, value in (headers or {}).items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self) -> None:
            state.gets.append(self.path)
            if self.path != f"/.well-known/oauth-protected-resource{RESOURCE_PATH}":
                self._reply(404, b"{}")
                return
            body = state.description if state.description is not None else state.default_description()
            self._reply(state.description_status, json.dumps(body).encode())

        def do_POST(self) -> None:
            _ = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            state.posts.append({key.lower(): value for key, value in self.headers.items()} | {"path": self.path})
            self._reply(state.ping_status, state.ping_body, state.ping_headers)

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


@pytest.fixture
def cloud() -> Iterator[StandIn]:
    state = StandIn()
    server, state.origin = _serve(state)
    try:
        yield state
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def paired(cloud: StandIn, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> FakeCloud:
    monkeypatch.setenv("HOME", str(tmp_path / "user"))
    # Guard Cloud renews this computer's access unless a test says otherwise.
    monkeypatch.setattr(status_commands, "_renewal_refused", lambda _store: None)
    return pair(monkeypatch, FakeCloud(origin=cloud.origin))


def _run(*argv: str) -> int:
    try:
        return cli.main(["cloud-actions", *argv])
    except SystemExit as exit_:
        return int(exit_.code or 0)


def _json(capsys: pytest.CaptureFixture[str]) -> tuple[dict[str, Any], str]:
    text = capsys.readouterr().out
    return json.loads(text), text


def _status(home: Path, capsys: pytest.CaptureFixture[str], *extra: str) -> tuple[int, dict[str, Any], str]:
    code = _run("status", "--guard-home", str(home / "guard"), "--json", *extra)
    payload, text = _json(capsys)
    return code, payload, text


def _configure(home: Path, capsys: pytest.CaptureFixture[str], ai_tool: str = "codex") -> None:
    assert _run("ai-tools", "configure", ai_tool, "--apply", "--home", str(home / "user"), "--json") == 0
    capsys.readouterr()


def _doctor(home: Path, capsys: pytest.CaptureFixture[str], *extra: str) -> tuple[int, dict[str, Any], str]:
    code = _run("doctor", "--home", str(home / "user"), "--json", *extra)
    payload, text = _json(capsys)
    return code, payload, text


def _closed_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def test_status_reports_the_pairing_and_the_service(
    cloud: StandIn, paired: FakeCloud, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, payload, _ = _status(tmp_path, capsys)

    assert code == 0
    assert payload["state"] == "paired"
    assert (payload["cloud_url"], payload["cloud_workspace"]) == (cloud.origin, WS)
    assert payload["cloud_actions"] == "unknown"
    assert payload["service"] == {
        "state": "current",
        "message": "Guard Cloud offers Cloud actions.",
        "http_status": 200,
    }
    assert payload["included_actions"] == "not_available_yet"
    # Status asks only the public description: no access is exchanged or sent.
    assert cloud.posts == [] and paired.exchanged == []


@pytest.mark.parametrize(("report", "state"), [({"status": "on"}, "on"), ({"status": "off"}, "off")])
def test_status_says_what_connect_reported_about_cloud_actions(
    paired: FakeCloud, tmp_path: Path, capsys: pytest.CaptureFixture[str], report: dict[str, object], state: str
) -> None:
    paired.connect_report = report

    _, payload, _ = _status(tmp_path, capsys, "--offline")

    assert payload["cloud_actions"] == state


def test_status_offline_asks_nothing(
    cloud: StandIn, paired: FakeCloud, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _, payload, _ = _status(tmp_path, capsys, "--offline")

    assert payload["service"]["state"] == "not_checked"
    assert cloud.gets == [] and cloud.posts == []


def test_status_offline_reads_the_pairing_without_changing_guard_db(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    import sqlite3

    guard_home = tmp_path / "guard"
    guard_home.mkdir()
    database = guard_home / "guard.db"
    with sqlite3.connect(database) as connection:
        connection.execute("create table sync_state (state_key text primary key, payload_json text, updated_at text)")
        pairing = {"issuer": "https://hol.org", "client_id": "client-1", "grant_id": "grant-1", "workspace_id": WS}
        connection.executemany(
            "insert into sync_state values (?, ?, '2026-11-03T00:00:00Z')",
            [("oauth_local_credentials", json.dumps(pairing)), ("cloud_actions_connect:grant-1", '{"status": "on"}')],
        )
    connection.close()
    before = sorted((path.name, path.read_bytes()) for path in guard_home.iterdir())

    code, payload, _ = _status(tmp_path, capsys, "--offline")

    assert (code, payload["state"], payload["cloud_actions"]) == (0, "paired", "on")
    assert payload["cloud_url"] == "https://hol.org"
    assert sorted((path.name, path.read_bytes()) for path in guard_home.iterdir()) == before


@pytest.mark.parametrize(
    ("change", "state"),
    [
        ({"description_status": 404}, "not_turned_on"),
        ({"description_status": 503}, "unexpected_answer"),
        (
            {"description": {"resource": "https://elsewhere.example/api/guard/gateway/mcp", "scopes_supported": []}},
            "changed",
        ),
        ({"description": {"resource": "SELF", "scopes_supported": ["gateway:discover"]}}, "changed"),
        ({"description": {"resource": "SELF"}}, "unexpected_answer"),
    ],
    ids=["not-turned-on", "server-error", "other-address", "no-invoke", "no-scopes"],
)
def test_status_names_each_service_answer(
    cloud: StandIn,
    paired: FakeCloud,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    change: dict[str, Any],
    state: str,
) -> None:
    for name, value in change.items():
        if name == "description" and value.get("resource") == "SELF":
            value = {**value, "resource": f"{cloud.origin}{RESOURCE_PATH}"}
        setattr(cloud, name, value)

    _, payload, _ = _status(tmp_path, capsys)

    assert payload["service"]["state"] == state


def test_status_points_to_connect_when_the_service_changed(
    cloud: StandIn, paired: FakeCloud, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cloud.description = {"resource": "https://elsewhere.example/api/guard/gateway/mcp", "scopes_supported": []}

    assert _run("status", "--guard-home", str(tmp_path / "guard")) == 0

    human = capsys.readouterr().out
    assert "Connect again: `hol-guard connect`." in human
    assert "cloud-actions login" not in human


def test_status_offline_when_guard_cloud_cannot_be_reached(
    paired: FakeCloud, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    paired.origin = f"http://127.0.0.1:{_closed_port()}"

    code, payload, _ = _status(tmp_path, capsys)

    assert (code, payload["service"]["state"]) == (0, "offline")


def test_status_before_connect_points_to_connect(
    paired: FakeCloud, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    paired.paired = False

    assert _run("status", "--guard-home", str(tmp_path / "guard")) == 0

    assert "Run `hol-guard connect`." in capsys.readouterr().out


def test_status_names_the_workspace_to_connect_to(
    paired: FakeCloud, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    other = "0b6e7a52-9f1c-4d3e-8a2b-7c6d5e4f3a21"

    _, payload, _ = _status(tmp_path, capsys, "--offline", "--cloud-workspace", other)
    assert payload["workspace_matches"] is False
    assert _run("status", "--guard-home", str(tmp_path / "guard"), "--offline", "--cloud-workspace", other) == 0

    assert f"run `hol-guard connect --cloud-workspace {other}`" in capsys.readouterr().out


def test_doctor_sends_one_ai_tools_access_and_reports_each_check(
    cloud: StandIn, paired: FakeCloud, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _configure(tmp_path, capsys)
    paired.exchanged.clear()

    code, payload, text = _doctor(tmp_path, capsys)

    assert (code, payload["result"]) == (0, "ok")
    checks = payload["checks"]
    assert checks["connection"]["state"] == "paired"
    assert checks["service"]["state"] == "current"
    assert checks["access"] == {
        "state": "connected",
        "message": "Guard Cloud accepted this computer. Actions are not available on this Guard Cloud yet.",
        "http_status": 501,
        "actions": "not_available_yet",
        "ai_tool": "codex",
    }
    assert payload["ai_tools"]["codex"]["state"] == "configured"
    assert payload["ai_tools"]["codex"]["settings_file"].startswith("~")
    assert paired.exchanged == ["codex"]
    [ping] = cloud.posts
    assert ping["path"] == RESOURCE_PATH
    assert ping["authorization"] == f"Bearer {ACCESS}"
    assert ping["x-guard-workspace-id"] == WS
    assert ACCESS not in text


def test_doctor_without_a_configured_ai_tool_exchanges_nothing(
    cloud: StandIn, paired: FakeCloud, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code, payload, _ = _doctor(tmp_path, capsys)

    assert (code, payload["result"]) == (0, "ok")
    assert payload["checks"]["access"]["state"] == "not_checked"
    assert paired.exchanged == [] and cloud.posts == []


def test_doctor_without_an_ai_tool_asks_to_connect_again_after_revocation(
    cloud: StandIn,
    paired: FakeCloud,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from codex_plugin_scanner.guard.daemon import cloud_actions_status
    from codex_plugin_scanner.guard.runtime import runner

    def refresh(_store: object, *, force_refresh: bool = False, **_kwargs: object) -> dict[str, object]:
        assert force_refresh
        raise runner.GuardSyncAuthorizationExpiredError(runner._guard_oauth_reconnect_after_revoked_message())  # pyright: ignore[reportPrivateUsage]

    monkeypatch.setattr(runner, "_resolve_guard_sync_auth_context", refresh)
    monkeypatch.setattr(status_commands, "_renewal_refused", _REAL_RENEWAL_REFUSED)

    code, payload, _ = _doctor(tmp_path, capsys)

    assert (code, payload["result"]) == (4, "needs_connect")
    assert payload["checks"]["access"] == {
        "state": "reconnect",
        "message": cloud_actions_status._RECONNECT_MESSAGE,  # pyright: ignore[reportPrivateUsage]
    }
    assert paired.exchanged == [] and cloud.posts == []


def test_doctor_asks_to_connect_again_when_guard_cloud_refuses_the_access(
    cloud: StandIn, paired: FakeCloud, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _configure(tmp_path, capsys)
    cloud.ping_status, cloud.ping_body = 401, b"{}"

    code, payload, _ = _doctor(tmp_path, capsys)
    assert (code, payload["result"], payload["checks"]["access"]["state"]) == (4, "needs_connect", "reconnect")
    assert _run("doctor", "--home", str(tmp_path / "user")) == 4

    assert "Connect again: `hol-guard connect`." in capsys.readouterr().out


@pytest.mark.parametrize(
    ("reason", "result"),
    [("cloud_actions_not_allowed", "needs_connect"), ("cloud_unreachable", "problems_found")],
)
def test_doctor_reports_a_refused_exchange_without_sending_anything(
    cloud: StandIn, paired: FakeCloud, tmp_path: Path, capsys: pytest.CaptureFixture[str], reason: str, result: str
) -> None:
    _configure(tmp_path, capsys)
    paired.exchange_error = CloudActionsAccessError(reason, "Refused.")

    _, payload, _ = _doctor(tmp_path, capsys)

    assert payload["result"] == result
    assert payload["checks"]["access"]["state"] == reason
    assert cloud.posts == []


@pytest.mark.parametrize(
    ("ping_status", "state"),
    [(403, "not_permitted"), (400, "workspace_mismatch"), (500, "unexpected_answer")],
)
def test_doctor_names_each_refusal(
    cloud: StandIn,
    paired: FakeCloud,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    ping_status: int,
    state: str,
) -> None:
    _configure(tmp_path, capsys)
    cloud.ping_status, cloud.ping_body = ping_status, b"{}"

    code, payload, _ = _doctor(tmp_path, capsys)

    assert (code, payload["result"]) == (3, "problems_found")
    assert payload["checks"]["access"]["state"] == state


def test_doctor_with_cloud_actions_off_exchanges_nothing(
    cloud: StandIn, paired: FakeCloud, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _configure(tmp_path, capsys)
    paired.exchanged.clear()
    paired.connect_report = {"status": "off"}

    code, payload, _ = _doctor(tmp_path, capsys)

    assert (code, payload["result"]) == (4, "needs_connect")
    assert payload["checks"]["connection"]["state"] == "cloud_actions_off"
    assert paired.exchanged == [] and cloud.posts == []


def test_doctor_before_connect_reads_no_ai_tool_settings(
    paired: FakeCloud, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    paired.paired = False

    code, payload, _ = _doctor(tmp_path, capsys)

    assert (code, payload["result"]) == (4, "needs_connect")
    assert {entry["state"] for entry in payload["ai_tools"].values()} == {"not_checked"}


@pytest.mark.parametrize(
    ("status", "body", "state", "actions"),
    [
        (200, b'{"jsonrpc": "2.0", "id": "hol-guard-status", "result": {}}', "connected", "available"),
        (200, json.dumps(_NOT_YET).encode(), "connected", "not_available_yet"),
        (200, b"<html>proxy sign-in</html>", "unexpected_answer", None),
        (200, b'{"jsonrpc": "2.0", "id": "other", "result": {}}', "unexpected_answer", None),
        (501, b"{}", "unexpected_answer", None),
    ],
    ids=["ping-reply", "method-not-found", "proxy-page", "other-id", "bare-501"],
)
def test_a_success_status_counts_only_with_a_ping_reply(
    cloud: StandIn, status: int, body: bytes, state: str, actions: str | None
) -> None:
    cloud.ping_status, cloud.ping_body = status, body

    check = cloud_actions_health.check_connection(CloudActionsPairing(cloud.origin, WS), ACCESS, WS)

    assert check.state == state
    assert dict(check.details).get("actions") == actions


def test_the_access_never_follows_a_redirect(cloud: StandIn) -> None:
    elsewhere = StandIn(ping_status=200)
    server, elsewhere.origin = _serve(elsewhere)
    try:
        cloud.ping_status, cloud.ping_body = 307, b"{}"
        cloud.ping_headers = {"Location": f"{elsewhere.origin}{RESOURCE_PATH}"}

        check = cloud_actions_health.check_connection(CloudActionsPairing(cloud.origin, WS), ACCESS, WS)
    finally:
        server.shutdown()
        server.server_close()

    assert check.state == "unexpected_answer"
    assert elsewhere.posts == []


def test_doctor_bundle_is_private_and_holds_no_access_or_user_folder(
    paired: FakeCloud, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _configure(tmp_path, capsys)
    bundle = tmp_path / "doctor.json"

    code, payload, _ = _doctor(tmp_path, capsys, "--bundle", str(bundle))

    assert code == 0 and payload["bundle"] == str(bundle)
    saved = bundle.read_text(encoding="utf-8")
    assert json.loads(saved)["schema"] == status_commands.CLOUD_ACTIONS_DIAGNOSTICS_SCHEMA
    assert ACCESS not in saved
    assert str(tmp_path / "user") not in saved
    if os.name != "nt":
        assert bundle.stat().st_mode & 0o077 == 0


def test_doctor_bundle_never_overwrites_a_file(
    paired: FakeCloud, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bundle = tmp_path / "doctor.json"
    bundle.write_text("kept", encoding="utf-8")

    code, payload, _ = _doctor(tmp_path, capsys, "--bundle", str(bundle))

    assert (code, payload["reason"]) == (1, "bundle_not_written")
    assert bundle.read_text(encoding="utf-8") == "kept"


def test_a_bundle_that_would_hold_the_access_is_not_written(tmp_path: Path) -> None:
    bundle = tmp_path / "doctor.json"

    reason = status_commands._write_bundle(bundle, {"echo": ACCESS}, ACCESS)  # pyright: ignore[reportPrivateUsage]

    assert reason is not None
    assert not bundle.exists()
