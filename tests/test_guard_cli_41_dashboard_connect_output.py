"""Guard CLI dashboard connect output behavior."""

from __future__ import annotations

import json
import urllib.parse
import urllib.request

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.cli import commands as guard_commands_module
from codex_plugin_scanner.guard.cli.render import emit_guard_payload
from tests.guard_cli_test_fixtures import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)
from tests.guard_cli_test_fixtures import (
    _use_legacy_update_context as _use_legacy_update_context,
)


class TestGuardCli:
    def test_guard_admin_alias_opens_local_approval_center(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        from unittest.mock import MagicMock

        from codex_plugin_scanner.guard import dashboard_launcher

        monkeypatch.setattr(
            dashboard_launcher,
            "ensure_guard_daemon",
            lambda guard_home: "http://127.0.0.1:5474",
        )
        monkeypatch.setattr(
            dashboard_launcher,
            "load_guard_daemon_auth_token",
            lambda guard_home: "fake-token",
        )
        mock_surface = MagicMock()
        mock_surface.ensure_surface.return_value = {
            "opened": False,
            "reason": "policy-disabled",
            "browser_url": "http://127.0.0.1:5474",
        }
        monkeypatch.setattr(dashboard_launcher, "GuardSurfaceRuntime", lambda store: mock_surface)

        rc = main(["guard", "admin", "--home", str(home_dir), "--json"])
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["approval_center_url"] == "http://127.0.0.1:5474"
        assert output["opened"] is False
        assert output["reason"] == "policy-disabled"

    def test_guard_dashboard_returns_error_when_daemon_start_fails(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        from codex_plugin_scanner.guard import dashboard_launcher

        monkeypatch.setattr(
            dashboard_launcher,
            "ensure_guard_daemon",
            lambda guard_home: (_ for _ in ()).throw(RuntimeError("dashboard_unavailable")),
        )

        rc = main(["guard", "dashboard", "--home", str(home_dir), "--json"])
        output = json.loads(capsys.readouterr().out)

        assert rc == 1
        assert output["opened"] is False
        assert output["error"] == "dashboard_unavailable"

    def test_public_approval_center_url_strips_guard_token(self):
        browser_url = guard_commands_module._approval_center_browser_url(
            "http://127.0.0.1:5474#section=inbox",
            "secret-token",
        )

        assert browser_url is not None
        parsed = urllib.parse.urlparse(browser_url)
        fragment = urllib.parse.parse_qs(parsed.fragment)
        assert fragment["guard-token"][0].startswith("gld1.")
        assert "guard-token=" not in guard_commands_module._public_approval_center_url(browser_url)

    def test_guard_connect_pending_output_uses_product_copy_for_sign_in_gap(self, capsys):
        emit_guard_payload(
            "connect",
            {
                "browser_opened": True,
                "completed_at": "2026-04-20T00:00:00Z",
                "status": "connected",
                "milestone": "first_sync_pending",
                "connect_url": "https://hol.org/guard/connect",
                "sync_url": "https://hol.org/api/guard/receipts/sync",
                "sync": {
                    "receipts_stored": 0,
                    "inventory_tracked": 0,
                },
                "sync_message": "Guard is not logged in.",
            },
            False,
        )

        output = capsys.readouterr().out

        assert "Guard is running locally" in output
        assert "Sign in to finish Guard Cloud setup" in output
        assert "Local Guard is available." in output
        assert "Sign in on the Guard connect page" in output
        assert "Machine registered, first proof pending" not in output
        assert "Dashboard proof is still syncing" not in output
        assert "Guard is not logged in." not in output
        assert "Receipts stored" not in output
        assert "Inventory tracked" not in output

    def test_guard_connect_pending_output_uses_product_copy_for_plan_limit(self, capsys):
        emit_guard_payload(
            "connect",
            {
                "browser_opened": True,
                "completed_at": "2026-04-20T00:00:00Z",
                "status": "connected",
                "milestone": "sync_not_available",
                "connect_url": "https://hol.org/guard/connect",
                "sync_url": "https://hol.org/api/guard/receipts/sync",
                "sync_message": "Guard Cloud sync requires a paid Guard plan",
            },
            False,
        )

        output = capsys.readouterr().out

        assert "Guard is running locally" in output
        assert "Upgrade to sync this device to Guard Cloud" in output
        assert "Local Guard is available." in output
        assert "Upgrade your Guard plan" in output
        assert "shared proof" in output
        assert "Fleet history to Guard Cloud" in output
        assert "Shared proof sync needs a paid Guard plan" not in output

    def test_guard_connect_pending_output_treats_upgrade_copy_as_plan_limit(self, capsys):
        emit_guard_payload(
            "connect",
            {
                "browser_opened": True,
                "completed_at": "2026-04-20T00:00:00Z",
                "status": "connected",
                "milestone": "sync_not_available",
                "connect_url": "https://hol.org/guard/connect",
                "sync_url": "https://hol.org/api/guard/receipts/sync",
                "sync_message": "Upgrade your plan to sync Guard Cloud receipts.",
            },
            False,
        )

        output = capsys.readouterr().out

        assert "Guard is running locally" in output
        assert "Upgrade to sync this device to Guard Cloud" in output
        assert "First Guard Cloud proof is on the way" not in output
