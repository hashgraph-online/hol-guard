"""`cloud-actions status` and `doctor` against a local stand-in for Guard Cloud.

The stand-in's gateway answers like Guard Cloud's before actions land: 501
once it accepts the sign-in, 401 when it does not. Each test bends one answer
and checks that the reported state matches what Guard Cloud said, and that
the saved access never reaches the output, a bundle or another server.
"""

from __future__ import annotations

import json
import os
import socket
import sys
from pathlib import Path
from typing import Any

import pytest

from codex_plugin_scanner.guard.cli import commands_dispatch_cloud_actions_status as status_commands
from codex_plugin_scanner.guard.cli.cloud_actions_oauth import CLOUD_ACTIONS_SCOPES
from codex_plugin_scanner.guard.cli.cloud_actions_session import CloudActionsSessionStore
from tests.cloud_actions_login_support import (
    WS,
    Browser,
    FakeCloud,
    _cli,
    _json_out,
    _login,
    browser_fixture,  # noqa: F401 -- shared fixture
    cloud_fixture,  # noqa: F401 -- shared fixture
    serve_fake_cloud,
)

CANARY = "codex-env-canary-7f3a"


def _signed_in(cloud: FakeCloud, home: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert _login(cloud, home) == 0
    capsys.readouterr()


def _status(home: Path, capsys: pytest.CaptureFixture[str], *extra: str) -> tuple[int, dict[str, Any], str]:
    code = _cli("status", "--guard-home", str(home), "--json", *extra)
    payload, text = _json_out(capsys)
    return code, payload, text


def _doctor(home: Path, capsys: pytest.CaptureFixture[str], *extra: str) -> tuple[int, dict[str, Any], str]:
    code = _cli("doctor", "--guard-home", str(home), "--home", str(home / "user"), "--json", *extra)
    payload, text = _json_out(capsys)
    return code, payload, text


def _edit_profile(home: Path, **changes: object) -> None:
    path = home / "cloud-actions" / "profiles" / "default.json"
    record = json.loads(path.read_text())
    record.update(changes)
    path.write_text(json.dumps(record))


def _closed_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _no_credentials(cloud: FakeCloud, text: str) -> None:
    assert cloud.issued
    for value in cloud.issued:
        assert value not in text


def test_status_reports_that_guard_cloud_accepts_the_sign_in(
    cloud: FakeCloud, browser: Browser, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _signed_in(cloud, tmp_path, capsys)

    code, payload, text = _status(tmp_path, capsys)

    assert code == 0
    assert payload["state"] == "signed_in"
    assert payload["service"]["state"] == "current"
    assert payload["connection"] == {
        "state": "connected",
        "message": "Guard Cloud accepted this sign-in. Actions are not available on this Guard Cloud yet.",
        "http_status": 501,
        "actions": "not_available_yet",
    }
    assert payload["included_actions"] == "not_available_yet"
    [request] = cloud.gateway_requests
    assert request["authorization"] == f"Bearer {cloud.issued[0]}"
    assert request["x-guard-workspace-id"] == WS
    _no_credentials(cloud, text)


def test_status_says_when_guard_cloud_no_longer_accepts_the_sign_in(
    cloud: FakeCloud, browser: Browser, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _signed_in(cloud, tmp_path, capsys)
    cloud.rejected.update(cloud.issued)

    code, payload, text = _status(tmp_path, capsys)
    assert code == 0
    # Saved locally as signed in; Guard Cloud's answer shows it is stale.
    assert (payload["state"], payload["connection"]["state"]) == ("signed_in", "sign_in_again")
    assert _cli("status", "--guard-home", str(tmp_path)) == 0
    human = capsys.readouterr().out
    assert "Guard Cloud no longer accepts this sign-in" in human
    assert "Sign in again: `hol-guard cloud-actions login" in human
    _no_credentials(cloud, text + human)


@pytest.mark.parametrize(
    ("gateway_status", "state"),
    [(403, "not_permitted"), (400, "workspace_mismatch"), (500, "unexpected_answer")],
)
def test_status_names_each_refusal(
    cloud: FakeCloud,
    browser: Browser,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    gateway_status: int,
    state: str,
) -> None:
    _signed_in(cloud, tmp_path, capsys)
    cloud.overrides["gateway_status"] = gateway_status

    _, payload, _ = _status(tmp_path, capsys)

    assert payload["connection"]["state"] == state
    assert payload["connection"]["http_status"] == gateway_status


def test_status_offline_when_guard_cloud_cannot_be_reached(
    cloud: FakeCloud, browser: Browser, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _signed_in(cloud, tmp_path, capsys)
    origin = f"http://127.0.0.1:{_closed_port()}"
    _edit_profile(tmp_path, issuer=origin, resource=f"{origin}/api/guard/gateway/mcp")

    code, payload, _ = _status(tmp_path, capsys)

    assert code == 0
    assert payload["state"] == "signed_in"
    assert payload["service"]["state"] == "offline"
    assert payload["connection"]["state"] == "offline"


def test_status_offline_flag_asks_nothing(
    cloud: FakeCloud, browser: Browser, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _signed_in(cloud, tmp_path, capsys)

    _, payload, _ = _status(tmp_path, capsys, "--offline")

    assert payload["service"]["state"] == payload["connection"]["state"] == "not_checked"
    assert cloud.gateway_requests == []


def test_an_expired_sign_in_is_never_sent(
    cloud: FakeCloud, browser: Browser, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _signed_in(cloud, tmp_path, capsys)
    _edit_profile(tmp_path, expires_at="2020-01-01T00:00:00Z")

    _, payload, _ = _status(tmp_path, capsys)

    assert (payload["state"], payload["connection"]["state"]) == ("expired", "sign_in_expired")
    assert cloud.gateway_requests == []


def test_cloud_actions_turned_off_sends_no_sign_in(
    cloud: FakeCloud, browser: Browser, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _signed_in(cloud, tmp_path, capsys)
    cloud.overrides["disabled"] = True

    _, payload, _ = _status(tmp_path, capsys)

    assert payload["service"]["state"] == payload["connection"]["state"] == "not_turned_on"
    assert cloud.gateway_requests == []


def test_status_notices_when_guard_cloud_drops_a_permission(
    cloud: FakeCloud, browser: Browser, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _signed_in(cloud, tmp_path, capsys)
    cloud.overrides["protected_resource"] = {"scopes_supported": list(CLOUD_ACTIONS_SCOPES[1:])}

    _, payload, _ = _status(tmp_path, capsys)

    assert payload["service"]["state"] == "changed"
    assert payload["service"]["scopes_missing"] == [CLOUD_ACTIONS_SCOPES[0]]


def test_the_sign_in_never_follows_a_redirect(
    cloud: FakeCloud, browser: Browser, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _signed_in(cloud, tmp_path, capsys)
    with serve_fake_cloud() as elsewhere:
        cloud.overrides["gateway_redirect"] = f"{elsewhere.origin}/api/guard/gateway/mcp"

        _, payload, _ = _status(tmp_path, capsys)

        assert payload["connection"] == {
            "state": "unexpected_answer",
            "message": "Guard Cloud answered HTTP 307.",
            "http_status": 307,
        }
        assert elsewhere.gateway_requests == []


def test_a_saved_address_on_another_site_is_never_sent_the_sign_in(
    cloud: FakeCloud, browser: Browser, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _signed_in(cloud, tmp_path, capsys)
    with serve_fake_cloud() as elsewhere:
        _edit_profile(tmp_path, resource=f"{elsewhere.origin}/api/guard/gateway/mcp")

        _, payload, _ = _status(tmp_path, capsys)

        assert payload["connection"]["state"] == "profile_damaged"
        assert elsewhere.gateway_requests == [] and cloud.gateway_requests == []


def _ai_tool_settings(home: Path, resource: str) -> None:
    user = home / "user"
    (user / ".codex").mkdir(parents=True)
    (user / ".codex" / "config.toml").write_text(
        f'[mcp_servers.docs]\ncommand = "docs"\nenv = {{ TOKEN = "{CANARY}" }}\n\n'
        f'[mcp_servers.hol-guard-cloud]\nurl = "{resource}"\n'
    )
    (user / ".cursor").mkdir()
    (user / ".cursor" / "mcp.json").write_text(
        json.dumps({"mcpServers": {"hol-guard-cloud": {"url": "https://old.example.test/mcp?key=x"}}})
    )


def test_doctor_reports_each_check_and_ai_tool(
    cloud: FakeCloud, browser: Browser, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _signed_in(cloud, tmp_path, capsys)
    _ai_tool_settings(tmp_path, f"{cloud.origin}/api/guard/gateway/mcp")

    code, payload, text = _doctor(tmp_path, capsys)

    assert code == 0
    assert payload["result"] == "ok"
    assert {name: check["state"] for name, check in payload["checks"].items()} == {
        "sign_in": "signed_in",
        "files": "not_checked" if os.name == "nt" else "private",
        "service": "current",
        "connection": "connected",
    }
    assert payload["ai_tools"] == {
        "claude-code": {"state": "not_configured", "settings_file": "~/.claude.json"},
        "codex": {"state": "configured", "settings_file": "~/.codex/config.toml"},
        "cursor": {
            "state": "points_elsewhere",
            "settings_file": "~/.cursor/mcp.json",
            "points_to": "https://old.example.test/mcp",
        },
    }
    assert CANARY not in text
    _no_credentials(cloud, text)


def test_doctor_bundle_holds_no_sign_in_settings_or_user_folder(
    cloud: FakeCloud, browser: Browser, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _signed_in(cloud, tmp_path, capsys)
    _ai_tool_settings(tmp_path, f"{cloud.origin}/api/guard/gateway/mcp")
    bundle = tmp_path / "bundle.json"

    code, payload, _ = _doctor(tmp_path, capsys, "--bundle", str(bundle))

    assert code == 0 and payload["bundle"] == str(bundle)
    raw = bundle.read_text()
    saved = json.loads(raw)
    assert saved["schema"] == "guard.cloud-actions.diagnostics.v1"
    assert saved["checks"]["connection"]["state"] == "connected"
    if sys.platform != "win32":
        assert bundle.stat().st_mode & 0o777 == 0o600
    _no_credentials(cloud, raw)
    assert CANARY not in raw
    assert "secret_ref" not in raw and "cloud-actions-default-" not in raw
    assert str(tmp_path / "user") not in raw


def test_doctor_bundle_never_overwrites_a_file(
    cloud: FakeCloud, browser: Browser, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _signed_in(cloud, tmp_path, capsys)
    bundle = tmp_path / "bundle.json"
    bundle.write_text("keep")

    code, payload, _ = _doctor(tmp_path, capsys, "--bundle", str(bundle))

    assert (code, payload["reason"]) == (1, "bundle_not_written")
    assert bundle.read_text() == "keep"


def test_doctor_refuses_a_bundle_that_would_hold_the_sign_in(
    cloud: FakeCloud,
    browser: Browser,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _signed_in(cloud, tmp_path, capsys)
    leaked = cloud.issued[1]
    original = status_commands._profile_fields  # pyright: ignore[reportPrivateUsage]
    monkeypatch.setattr(status_commands, "_profile_fields", lambda profile: {**original(profile), "note": leaked})
    bundle = tmp_path / "bundle.json"

    code = _cli("doctor", "--guard-home", str(tmp_path), "--home", str(tmp_path / "user"), "--bundle", str(bundle))

    assert code == 1
    assert "were not saved to a file" in capsys.readouterr().out
    assert not bundle.exists()


def test_doctor_asks_for_a_new_sign_in_when_guard_cloud_refuses_it(
    cloud: FakeCloud, browser: Browser, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _signed_in(cloud, tmp_path, capsys)
    cloud.rejected.update(cloud.issued)

    code, payload, _ = _doctor(tmp_path, capsys)

    assert (code, payload["result"]) == (4, "needs_sign_in")
    assert payload["checks"]["connection"]["state"] == "sign_in_again"


def test_doctor_reports_problems_when_offline(
    cloud: FakeCloud, browser: Browser, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _signed_in(cloud, tmp_path, capsys)
    origin = f"http://127.0.0.1:{_closed_port()}"
    _edit_profile(tmp_path, issuer=origin, resource=f"{origin}/api/guard/gateway/mcp")

    code, payload, _ = _doctor(tmp_path, capsys)

    assert (code, payload["result"]) == (3, "problems_found")
    assert payload["checks"]["connection"]["state"] == "offline"


@pytest.mark.skipif(os.name == "nt", reason="POSIX file modes")
def test_doctor_notices_saved_files_others_can_read(
    cloud: FakeCloud, browser: Browser, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _signed_in(cloud, tmp_path, capsys)
    (tmp_path / "cloud-actions" / "profiles" / "default.json").chmod(0o644)

    code, payload, _ = _doctor(tmp_path, capsys)

    assert (code, payload["result"]) == (3, "problems_found")
    assert payload["checks"]["files"] == {
        "state": "too_open",
        "message": "Other users on this computer can read Cloud actions files.",
        "paths": ["cloud-actions/profiles/default.json"],
    }


def test_doctor_without_a_sign_in_reads_no_ai_tool_settings(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code, payload, _ = _doctor(tmp_path, capsys)

    assert (code, payload["result"]) == (4, "needs_sign_in")
    assert {entry["state"] for entry in payload["ai_tools"].values()} == {"not_checked"}
    assert CloudActionsSessionStore(tmp_path).load("default") is None
