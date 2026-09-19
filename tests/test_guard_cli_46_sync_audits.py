"""Guard CLI sync audits behavior."""

from __future__ import annotations

import json

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli import commands as guard_commands_module
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_cli_test_fixtures import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)
from tests.guard_cli_test_fixtures import (
    _use_legacy_update_context as _use_legacy_update_context,
)


class TestGuardCli:
    def test_guard_sync_includes_supply_chain_workspace_audits(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        workspace_dir.mkdir()
        captured_auth_context: list[dict[str, object]] = []
        captured_receipt_kwargs: list[dict[str, object]] = []

        monkeypatch.setattr(
            guard_commands_module,
            "_resolve_guard_sync_auth_context",
            lambda _store: {
                "access_token": "token",
                "sync_url": "https://hol.org/api/guard/receipts/sync",
            },
        )
        monkeypatch.setattr(
            guard_commands_module,
            "_require_guard_context",
            lambda _context: HarnessContext(home_dir=home_dir, workspace_dir=workspace_dir, guard_home=home_dir),
        )

        def _fake_sync_local_guard_cloud_proof(_store: GuardStore, **kwargs: object) -> dict[str, object]:
            captured_receipt_kwargs.append(dict(kwargs))
            auth_context = kwargs.get("auth_context")
            assert isinstance(auth_context, dict)
            captured_auth_context.append(auth_context)
            assert kwargs.get("workspace_dir") == workspace_dir
            return {
                "synced_at": "2026-06-18T22:00:00Z",
                "receipts_stored": 2,
            }

        def _fake_sync_supply_chain_cloud_state(_store: GuardStore, **kwargs: object) -> dict[str, object]:
            auth_context = kwargs.get("auth_context")
            assert isinstance(auth_context, dict)
            captured_auth_context.append(auth_context)
            assert kwargs.get("workspace_dir") == workspace_dir
            return {
                "synced_at": "2026-06-18T22:00:01Z",
                "status": "synced",
                "workspace_audits": {
                    "status": "synced",
                    "completed_jobs": 1,
                },
            }

        monkeypatch.setattr(guard_commands_module, "sync_local_guard_cloud_proof", _fake_sync_local_guard_cloud_proof)
        monkeypatch.setattr(
            guard_commands_module,
            "sync_supply_chain_cloud_state",
            _fake_sync_supply_chain_cloud_state,
        )

        sync_rc = main(["guard", "sync", "--home", str(home_dir), "--json"])
        output = json.loads(capsys.readouterr().out)

        assert sync_rc == 0
        assert output["receipts_stored"] == 2
        assert output["supply_chain"]["workspace_audits"]["completed_jobs"] == 1
        assert len(captured_auth_context) == 2
        assert captured_auth_context[0] == captured_auth_context[1]
        assert captured_receipt_kwargs[0]["include_aibom"] is True
        assert captured_receipt_kwargs[0]["force_aibom"] is False

    def test_guard_sync_deep_forces_aibom_refresh(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        workspace_dir.mkdir()
        captured_receipt_kwargs: list[dict[str, object]] = []

        monkeypatch.setattr(
            guard_commands_module,
            "_resolve_guard_sync_auth_context",
            lambda _store: {
                "access_token": "token",
                "sync_url": "https://hol.org/api/guard/receipts/sync",
            },
        )
        monkeypatch.setattr(
            guard_commands_module,
            "_require_guard_context",
            lambda _context: HarnessContext(home_dir=home_dir, workspace_dir=workspace_dir, guard_home=home_dir),
        )

        def _fake_sync_local_guard_cloud_proof(_store: GuardStore, **kwargs: object) -> dict[str, object]:
            captured_receipt_kwargs.append(dict(kwargs))
            return {
                "synced_at": "2026-06-18T22:00:00Z",
                "receipts_stored": 2,
            }

        monkeypatch.setattr(guard_commands_module, "sync_local_guard_cloud_proof", _fake_sync_local_guard_cloud_proof)
        monkeypatch.setattr(
            guard_commands_module,
            "sync_supply_chain_cloud_state",
            lambda *_args, **_kwargs: {
                "synced_at": "2026-06-18T22:00:01Z",
                "status": "synced",
            },
        )

        sync_rc = main(["guard", "sync", "--deep", "--home", str(home_dir), "--json"])
        output = json.loads(capsys.readouterr().out)

        assert sync_rc == 0
        assert output["receipts_stored"] == 2
        assert captured_receipt_kwargs[0]["include_aibom"] is True
        assert captured_receipt_kwargs[0]["force_aibom"] is True

    def test_guard_supply_chain_sync_includes_workspace_audits(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        workspace_dir.mkdir()
        captured: dict[str, object] = {}

        monkeypatch.setattr(
            guard_commands_module,
            "_resolve_guard_sync_auth_context",
            lambda _store: {
                "access_token": "token",
                "sync_url": "https://guard.example/api/guard/receipts/sync",
            },
        )

        def _fake_sync_supply_chain_cloud_state(_store: GuardStore, **kwargs: object) -> dict[str, object]:
            captured.update(kwargs)
            return {
                "synced_at": "2026-06-18T22:00:01Z",
                "status": "synced",
                "workspace_audits": {
                    "status": "synced",
                    "completed_jobs": 1,
                    "workspaces": [{"package_count": 280, "cloud_visible_count": 280}],
                },
            }

        monkeypatch.setattr(
            guard_commands_module,
            "sync_supply_chain_cloud_state",
            _fake_sync_supply_chain_cloud_state,
        )

        rc = main(
            [
                "guard",
                "supply-chain",
                "sync",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert captured["workspace_dir"] == workspace_dir
        assert output["workspace_audits"]["completed_jobs"] == 1
        assert output["workspace_audits"]["workspaces"][0]["package_count"] == 280
        assert output["workspace_audits"]["workspaces"][0]["cloud_visible_count"] == 280

    def test_guard_supply_chain_sync_reports_unavailable_error(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        workspace_dir.mkdir()

        monkeypatch.setattr(
            guard_commands_module,
            "_resolve_guard_sync_auth_context",
            lambda _store: {
                "access_token": "token",
                "sync_url": "https://guard.example/api/guard/receipts/sync",
            },
        )

        def _fail_sync(_store: GuardStore, **_kwargs: object) -> dict[str, object]:
            raise guard_commands_module.GuardSyncNotAvailableError("Guard supply-chain audit is not available.")

        monkeypatch.setattr(
            guard_commands_module,
            "sync_supply_chain_cloud_state",
            _fail_sync,
        )

        rc = main(
            [
                "guard",
                "supply-chain",
                "sync",
                "--home",
                str(home_dir),
                "--workspace",
                str(workspace_dir),
                "--json",
            ]
        )
        output = json.loads(capsys.readouterr().out)

        assert rc == 1
        assert output == {
            "synced": False,
            "error": "Guard supply-chain audit is not available.",
        }
