"""Guard CLI sync intel behavior."""

from __future__ import annotations

import json

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.cli import commands as guard_commands_module
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_cli_cloud_support import _seed_guard_cloud
from tests.guard_cli_test_fixtures import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)
from tests.guard_cli_test_fixtures import (
    _use_legacy_update_context as _use_legacy_update_context,
)


class TestGuardCli:
    def test_guard_cloud_sync_intel_emits_bundle_summary(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        store = GuardStore(home_dir)
        _seed_guard_cloud(store, workspace_id="workspace-alpha")

        def _fake_sync_intel(_store: GuardStore) -> dict[str, object]:
            return {
                "status": "synced",
                "workspace_id": "workspace-alpha",
                "bundle_version": "1747612800000-deadbeef",
                "package_count": 1,
                "advisory_count": 1,
                "ecosystem_support": [
                    {
                        "ecosystem": "npm",
                        "display_name": "npm",
                        "support_level": "protected",
                        "support_label": "Protected",
                    },
                    {
                        "ecosystem": "cargo",
                        "display_name": "Cargo",
                        "support_level": "beta",
                        "support_label": "Beta",
                    },
                    {
                        "ecosystem": "system",
                        "display_name": "System packages",
                        "support_level": "monitor-only",
                        "support_label": "Monitor-only",
                    },
                ],
            }

        monkeypatch.setattr(guard_commands_module, "sync_supply_chain_bundle", _fake_sync_intel)

        rc = main(["guard", "cloud", "sync-intel", "--home", str(home_dir), "--json"])
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["status"] == "synced"
        assert output["bundle_version"] == "1747612800000-deadbeef"
        assert output["workspace_id"] == "workspace-alpha"
        assert output["ecosystem_support"][0]["support_level"] == "protected"
        assert output["ecosystem_support"][1]["support_label"] == "Beta"

    def test_guard_cloud_sync_intel_without_login_returns_cli_error(self, tmp_path, capsys):
        home_dir = tmp_path / "home"

        rc = main(["guard", "cloud", "sync-intel", "--home", str(home_dir)])

        assert rc == 1
        stderr = capsys.readouterr().err
        assert "Guard Cloud is not connected yet." in stderr
        assert "Run `hol-guard connect`" in stderr

    def test_guard_sync_surfaces_auth_expired_reauth_message(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"

        def _fail_auth(_store: GuardStore) -> dict[str, object]:
            raise guard_commands_module.GuardSyncAuthorizationExpiredError(
                "Guard authorization expired. Run `hol-guard connect` to sign in again."
            )

        monkeypatch.setattr(guard_commands_module, "_resolve_guard_sync_auth_context", _fail_auth)

        rc = main(["guard", "sync", "--home", str(home_dir), "--json"])
        output = json.loads(capsys.readouterr().out)

        assert rc == 1
        assert output == {
            "synced": False,
            "error": "Guard authorization expired. Run `hol-guard connect` to sign in again.",
        }
