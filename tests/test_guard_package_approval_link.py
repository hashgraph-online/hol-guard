from __future__ import annotations

import copy
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from argparse import Namespace
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from codex_plugin_scanner.guard import approval_hook_copy, dashboard_launcher
from codex_plugin_scanner.guard.cli import render
from codex_plugin_scanner.guard.cli.approval_commands import run_approval_open_command
from codex_plugin_scanner.guard.cli.render import emit_guard_payload
from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.store import GuardStore


@pytest.mark.parametrize("as_json", [False, True])
def test_package_link_is_authenticated_only_in_live_output(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path, as_json: bool
) -> None:
    monkeypatch.setattr(approval_hook_copy, "load_guard_daemon_auth_token", lambda _home: "test-private-key")
    payload = {
        "approval_center_url": "http://127.0.0.1:5474",
        "primary_approval_url": "http://127.0.0.1:5474/requests/test-request",
        "verdict": {"action": "review", "reason": "Approval required"},
        "supply_chain_evaluation": {
            "user_copy": {
                "harness_message": "Approval required",
                "dashboard_url": "http://127.0.0.1:5474/old-review",
            }
        },
    }
    original = copy.deepcopy(payload)
    emit_guard_payload("protect", payload, as_json, live_approval_home=tmp_path)
    output = capsys.readouterr().out
    assert ("guard-token=" in output) is not as_json
    assert "test-private-key" not in output
    assert payload == original
    assert "guard-token" not in json.dumps(payload)
    if not as_json:
        assert "/requests/test-request" in output
        assert "old-review" not in output


def test_printed_package_link_authenticates_isolated_daemon(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        origin = f"http://127.0.0.1:{daemon.port}"
        monkeypatch.setattr(approval_hook_copy, "load_guard_daemon_auth_token", lambda _home: daemon._server.auth_token)
        monkeypatch.setattr(render, "_RICH_AVAILABLE", False)
        emit_guard_payload(
            "protect",
            {
                "approval_center_url": origin,
                "primary_approval_url": f"{origin}/requests/test-request",
                "verdict": {"action": "review"},
                "supply_chain_evaluation": {"user_copy": {"harness_message": "Review required"}},
            },
            False,
            live_approval_home=store.guard_home,
        )
        output = capsys.readouterr().out
        match = re.search(r"http://[^\s]+#guard-token=([^\s]+)", output)
        assert match is not None
        token = urllib.parse.unquote(match.group(1).removesuffix("."))
        for candidate, expected_status in [(None, 401), (token, 200), (token + "tampered", 401)]:
            headers = {"Origin": origin}
            if candidate is not None:
                headers["X-Guard-Dashboard-Session"] = candidate
            request = urllib.request.Request(f"{origin}/v1/requests", headers=headers)
            try:
                with urllib.request.urlopen(request, timeout=5) as response:
                    status = response.status
            except urllib.error.HTTPError as error:
                status = error.code
                error.close()
            assert status == expected_status
    finally:
        daemon.stop()


def test_approval_open_uses_authenticated_launcher_without_publishing_token(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    store = MagicMock()
    store.guard_home = tmp_path
    store.get_approval_request.return_value = {"approval_url": "http://127.0.0.1:1/requests/example"}
    monkeypatch.setattr(dashboard_launcher, "ensure_guard_daemon", lambda _home: "http://127.0.0.1:5474")
    monkeypatch.setattr(dashboard_launcher, "load_guard_daemon_auth_token", lambda _home: "test-private-key")
    surface = MagicMock()
    surface.ensure_surface.return_value = {"opened": True, "reason": "opened"}
    monkeypatch.setattr(dashboard_launcher, "GuardSurfaceRuntime", lambda _store: surface)
    payload, status = run_approval_open_command(Namespace(request_id="example"), store=store)
    assert status == 0
    assert payload["opened"] is True
    assert payload["approval_url"] == "http://127.0.0.1:5474/requests/example"
    launched = surface.ensure_surface.call_args.kwargs["browser_url"]
    assert launched.startswith("http://127.0.0.1:5474/requests/example#guard-token=")
    assert "guard-token" not in json.dumps(payload)


@pytest.mark.parametrize("reason", ["live-client", "already-opened", "policy-disabled"])
def test_existing_approval_surface_is_successful(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, reason: str) -> None:
    store = MagicMock()
    store.guard_home = tmp_path
    store.get_approval_request.return_value = {"approval_url": "http://127.0.0.1:5474/requests/example"}
    monkeypatch.setattr(
        dashboard_launcher,
        "open_dashboard",
        lambda **_kwargs: dashboard_launcher.DashboardLaunchResult(
            opened=False,
            approval_center_url="http://127.0.0.1:5474",
            browser_url="http://127.0.0.1:5474/requests/example",
            reason=reason,
        ),
    )
    _, status = run_approval_open_command(Namespace(request_id="example"), store=store)
    assert status == 0


@pytest.mark.parametrize("as_json", [False, True])
def test_manual_approval_open_link_is_signed_only_in_live_output(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path, as_json: bool
) -> None:
    monkeypatch.setattr(approval_hook_copy, "load_guard_daemon_auth_token", lambda _home: "test-private-key")
    monkeypatch.setattr(render, "_RICH_AVAILABLE", False)
    payload = {"approval_url": "http://127.0.0.1:5474/requests/example", "opened": False}
    emit_guard_payload("approvals", payload, as_json, live_approval_home=tmp_path)
    output = capsys.readouterr().out
    assert ("guard-token=" in output) is not as_json
    assert "guard-token" not in json.dumps(payload)
