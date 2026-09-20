"""Guard CLI connect flows behavior."""

from __future__ import annotations

import json
from pathlib import Path

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.cli import commands as guard_commands_module
from codex_plugin_scanner.guard.cli import commands_support_connect as guard_connect_support_module
from codex_plugin_scanner.guard.store import GuardStore
from tests import test_guard_cli as _guard_cli_fixture
from tests.guard_cli_fixture_support import _build_guard_fixture, _build_stable_guard_fixture, _write_text
from tests.guard_cli_test_fixtures import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)
from tests.guard_cli_test_fixtures import (
    _use_legacy_update_context as _use_legacy_update_context,
)


class TestGuardCli:
    def test_guard_connect_uses_browser_oauth_flow_without_pairing(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_stable_guard_fixture(home_dir, workspace_dir)
        _write_text(home_dir / "config.toml", 'changed_hash_action = "allow"\n')
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
                "authorize_url": "https://hol.org/guard/oauth/authorize?request_id=req-123",
                "grant_id": "grant-123",
                "machine_id": "machine-123",
                "workspace_id": "workspace-123",
            }

        monkeypatch.setattr(guard_commands_module, "_run_guard_browser_connect_flow", fake_browser_flow)
        run_rc = main(
            [
                "guard",
                "run",
                "codex",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--dry-run",
                "--default-action",
                "allow",
                "--json",
            ]
        )
        json.loads(capsys.readouterr().out)
        connect_rc = main(
            [
                "guard",
                "connect",
                "--home",
                str(home_dir),
                "--connect-url",
                "https://hol.org/guard/connect",
                "--json",
            ]
        )
        connect_output = json.loads(capsys.readouterr().out)

        assert run_rc == 0
        assert connect_rc == 0
        assert connect_output["status"] == "retry_required"
        assert connect_output["milestone"] == "first_sync_failed"
        assert connect_output["connect_mode"] == "browser_oauth"
        assert connect_output["browser_opened"] is True
        assert isinstance(connect_output["authorize_url"], str)
        assert connect_output["authorize_url"]
        assert "user_code" not in connect_output
        assert connect_output["grant_id"] == "grant-123"
        assert connect_output["machine_id"] == "machine-123"
        assert connect_output["workspace_id"] == "workspace-123"
        assert "guardPairSecret" not in json.dumps(connect_output)
        assert "guardPairRequest" not in json.dumps(connect_output)
        assert store.get_cloud_sync_profile() is None

    def test_guard_connect_runs_first_sync_and_surfaces_cloud_urls(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        store = GuardStore(home_dir)
        sync_calls: list[str] = []
        bundle_calls: list[str] = []

        def fake_browser_flow(
            *,
            store: GuardStore,
            connect_url: str,
            wait_timeout_seconds: int = 180,
        ) -> dict[str, object]:
            del connect_url, wait_timeout_seconds
            _guard_cli_fixture._OAuthCredentialsFixture.seed(store, now="2026-06-04T18:30:00+00:00")
            return {
                "status": "connected",
                "connect_mode": "browser_oauth",
                "browser_opened": True,
                "workspace_id": "workspace-123",
            }

        def fake_sync_local_guard_cloud_proof(
            store: GuardStore,
            *,
            auth_context: dict[str, object] | None = None,
            now: str | None = None,
            home_dir: Path | None = None,
            workspace_dir: Path | None = None,
        ) -> dict[str, object]:
            del store
            assert auth_context is None
            del home_dir, workspace_dir
            sync_calls.append("first-proof")
            return {
                "synced_at": "2026-06-04T18:31:00+00:00",
                "receipts_stored": 4,
                "inventory_tracked": 2,
                "runtime_session_synced_at": "2026-06-04T18:30:59+00:00",
                "runtime_session_id": "runtime-session-123",
                "runtime_sessions_visible": 1,
                "runtime_harness": "hol-guard",
                "runtime_surface": "cli",
                "runtime_workspace": "local-machine",
                "runtime_device_id": "machine-123",
                "local_guard_online_at": "2026-06-04T18:30:59+00:00",
                "runtime": {
                    "synced_at": "2026-06-04T18:30:59+00:00",
                    "runtime_session_synced_at": "2026-06-04T18:30:59+00:00",
                    "runtime_session_id": "runtime-session-123",
                },
                "receipts": {
                    "synced_at": "2026-06-04T18:31:00+00:00",
                    "receipts_stored": 4,
                    "inventory_tracked": 2,
                },
            }

        def fake_sync_supply_chain_cloud_state(
            store: GuardStore,
            *,
            auth_context: dict[str, object] | None = None,
            workspace_dir: Path | None = None,
        ) -> dict[str, object]:
            del store
            assert auth_context is None
            assert workspace_dir is None
            bundle_calls.append("bundle")
            return {
                "synced_at": "2026-06-04T18:31:05+00:00",
                "status": "synced",
                "workspace_audits": {"status": "synced", "completed_jobs": 1},
            }

        monkeypatch.setattr(guard_commands_module, "_run_guard_browser_connect_flow", fake_browser_flow)
        monkeypatch.setattr(guard_commands_module, "sync_local_guard_cloud_proof", fake_sync_local_guard_cloud_proof)
        monkeypatch.setattr(guard_commands_module, "sync_supply_chain_cloud_state", fake_sync_supply_chain_cloud_state)

        rc = main(
            [
                "guard",
                "connect",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--connect-url",
                "https://hol.org/guard/connect",
                "--json",
            ]
        )
        captured = capsys.readouterr()
        assert rc == 0, captured.err
        output = json.loads(captured.out)
        latest_state = store.get_latest_guard_connect_state(now="2026-06-04T18:31:00+00:00")

        assert rc == 0
        assert sync_calls == ["first-proof"]
        assert bundle_calls == ["bundle"]
        assert output["status"] == "connected"
        assert output["milestone"] == "first_sync_succeeded"
        assert output["sync_attempted"] is True
        assert output["sync_succeeded"] is True
        assert output["connect_url"] == "https://hol.org/guard/connect"
        assert output["sync_url"] == "https://hol.org/api/guard/receipts/sync"
        assert output["last_sync_at"] == "2026-06-04T18:31:00+00:00"
        assert output["sync"]["receipts_stored"] == 4
        assert output["sync"]["runtime_session_id"] == "runtime-session-123"
        assert isinstance(latest_state, dict)
        assert latest_state["status"] == "connected"
        assert latest_state["milestone"] == "first_sync_succeeded"
        assert latest_state["proof"]["runtime_session_id"] == "runtime-session-123"
        assert latest_state["proof"]["runtime_session_synced_at"] == "2026-06-04T18:30:59+00:00"

    def test_guard_connect_headless_keeps_device_code_flow(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        opened: list[str] = []

        def unexpected_browser_flow(
            *,
            store: GuardStore,
            connect_url: str,
            wait_timeout_seconds: int = 180,
        ) -> dict[str, object]:
            del store, connect_url, wait_timeout_seconds
            raise AssertionError("browser flow should not run for --headless")

        def fake_device_flow(
            *,
            store: GuardStore,
            connect_url: str,
            wait_timeout_seconds: int = 180,
            announce_copy=None,
            open_browser=None,
            ci_safe: bool = False,
            machine_label: str | None = None,
        ) -> dict[str, object]:
            del store, announce_copy, ci_safe, machine_label
            assert connect_url == "https://hol.org/guard/connect"
            assert wait_timeout_seconds == 180
            assert open_browser is guard_connect_support_module.open_browser_url
            browser_opened = bool(open_browser("https://hol.org/guard/oauth/device"))
            return {
                "status": "connected",
                "connect_mode": "device_code",
                "browser_opened": browser_opened,
                "user_code": "WXYZ-1234",
                "verification_uri": "https://hol.org/guard/oauth/device",
                "verification_uri_complete": "https://hol.org/guard/oauth/device?user_code=WXYZ-1234",
            }

        monkeypatch.setattr(guard_commands_module, "_run_guard_browser_connect_flow", unexpected_browser_flow)
        monkeypatch.setattr(guard_commands_module, "_run_guard_device_connect_flow", fake_device_flow)
        monkeypatch.setattr(
            guard_connect_support_module,
            "open_browser_url",
            lambda target: opened.append(target) or True,
        )

        connect_rc = main(
            [
                "guard",
                "connect",
                "--home",
                str(home_dir),
                "--connect-url",
                "https://hol.org/guard/connect",
                "--headless",
                "--open-browser",
                "--json",
            ]
        )
        connect_output = json.loads(capsys.readouterr().out)

        assert connect_rc == 0
        assert opened == ["https://hol.org/guard/oauth/device"]
        assert connect_output["connect_mode"] == "device_code"
        assert connect_output["browser_opened"] is True
