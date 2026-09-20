"""Guard CLI disconnect login behavior."""

from __future__ import annotations

import json
import urllib.parse
import urllib.request

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.cli import commands as guard_commands_module
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_cli_test_fixtures import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)
from tests.guard_cli_test_fixtures import (
    _use_legacy_update_context as _use_legacy_update_context,
)


class TestGuardCli:
    def test_guard_disconnect_revokes_cloud_grant_through_oauth_disconnect_helper(
        self,
        tmp_path,
        capsys,
        monkeypatch,
    ):
        home_dir = tmp_path / "home"
        calls: list[dict[str, object]] = []

        def fake_disconnect(
            *,
            store: GuardStore,
            revoke_cloud_grant: bool,
            now: str | None = None,
            urlopen=None,
        ) -> dict[str, object]:
            del store, now, urlopen
            calls.append({"revoke_cloud_grant": revoke_cloud_grant})
            return {
                "status": "disconnected",
                "cloud_grant_revoked": revoke_cloud_grant,
                "reconnect_command": "hol-guard connect",
            }

        monkeypatch.setattr(guard_commands_module, "run_guard_disconnect_command", fake_disconnect)

        rc = main(
            [
                "guard",
                "disconnect",
                "--home",
                str(home_dir),
                "--revoke-cloud-grant",
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output == {
            "status": "disconnected",
            "cloud_grant_revoked": True,
            "reconnect_command": "hol-guard connect",
        }
        assert calls == [{"revoke_cloud_grant": True}]

    def test_guard_disconnect_reports_network_layer_errors_in_json_mode(
        self,
        tmp_path,
        capsys,
        monkeypatch,
    ):
        home_dir = tmp_path / "home"

        def fake_disconnect(
            *,
            store: GuardStore,
            revoke_cloud_grant: bool,
            now: str | None = None,
            urlopen=None,
        ) -> dict[str, object]:
            del store, revoke_cloud_grant, now, urlopen
            raise urllib.error.URLError("loopback refused")

        monkeypatch.setattr(guard_commands_module, "run_guard_disconnect_command", fake_disconnect)

        rc = main(
            [
                "guard",
                "disconnect",
                "--home",
                str(home_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)

        assert rc == 1
        assert output == {
            "status": "error",
            "error": "<urlopen error loopback refused>",
        }

    def test_guard_login_without_manual_credentials_uses_browser_oauth_flow(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        store = GuardStore(home_dir)

        def fake_browser_flow(
            *,
            store: GuardStore,
            connect_url: str,
            wait_timeout_seconds: int = 180,
        ) -> dict[str, object]:
            del store
            assert wait_timeout_seconds == 180
            assert connect_url == "https://hol.org/guard/connect"
            return {
                "status": "connected",
                "connect_mode": "browser_oauth",
                "browser_opened": True,
                "authorize_url": "https://hol.org/guard/oauth/authorize?request_id=req-456",
                "grant_id": "grant-456",
                "machine_id": "machine-456",
                "workspace_id": "workspace-456",
            }

        monkeypatch.setattr(guard_commands_module, "_run_guard_browser_connect_flow", fake_browser_flow)
        login_rc = main(
            [
                "guard",
                "login",
                "--home",
                str(home_dir),
                "--connect-url",
                "https://hol.org/guard/connect",
                "--json",
            ]
        )
        login_output = json.loads(capsys.readouterr().out)

        assert login_rc == 0
        assert login_output["status"] == "retry_required"
        assert login_output["milestone"] == "first_sync_failed"
        assert login_output["connect_mode"] == "browser_oauth"
        assert login_output["browser_opened"] is True
        assert isinstance(login_output["authorize_url"], str)
        assert login_output["authorize_url"]
        assert "user_code" not in login_output
        assert login_output["grant_id"] == "grant-456"
        assert login_output["machine_id"] == "machine-456"
        assert login_output["workspace_id"] == "workspace-456"
        assert store.get_cloud_sync_profile() is None

    def test_guard_login_rejects_manual_token_mode_and_redirects_to_connect(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        store = GuardStore(home_dir)

        login_rc = main(
            [
                "guard",
                "login",
                "--home",
                str(home_dir),
                "--sync-url",
                "https://hol.org/api/guard/receipts/sync",
                "--token",
                "demo-token",
            ]
        )
        stderr = capsys.readouterr().err

        assert login_rc == 2
        assert "Manual token login is retired." in stderr
        assert "Run `hol-guard connect`" in stderr
        assert store.get_cloud_sync_profile() is None
        assert store.list_events(event_name="sign_in") == []
