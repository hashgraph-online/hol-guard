"""Guard CLI sync advisories behavior."""

from __future__ import annotations

import json
import threading
from http.server import HTTPServer

import pytest

from codex_plugin_scanner.cli import main
from tests.guard_cli_cloud_support import _seed_sync_credentials, _SyncRequestHandler
from tests.guard_cli_fixture_support import _build_guard_fixture, _build_stable_guard_fixture, _write_text
from tests.guard_cli_test_fixtures import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)
from tests.guard_cli_test_fixtures import (
    _use_legacy_update_context as _use_legacy_update_context,
)


class TestGuardCli:
    def test_guard_connect_rejects_invalid_sync_url(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)

        with pytest.raises(SystemExit) as exc_info:
            main(
                [
                    "guard",
                    "connect",
                    "--home",
                    str(home_dir),
                    "--workspace",
                    str(workspace_dir),
                    "--sync-url",
                    "not-a-url",
                ]
            )

        assert exc_info.value.code == 2
        assert "Guard URLs must be absolute http(s) URLs." in capsys.readouterr().err

    def test_guard_sync_persists_advisories_from_endpoint(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_stable_guard_fixture(home_dir, workspace_dir)
        _write_text(home_dir / "config.toml", 'changed_hash_action = "allow"\n')
        _SyncRequestHandler.response_payload = {
            "syncedAt": "2026-04-09T00:00:00Z",
            "receiptsStored": 1,
            "advisories": [
                {
                    "id": "adv-001",
                    "publisher": "hashgraph-online",
                    "severity": "high",
                    "headline": "Publisher rotated to a new remote domain.",
                }
            ],
            "policy": {
                "mode": "enforce",
                "defaultAction": "warn",
                "unknownPublisherAction": "review",
                "changedHashAction": "allow",
                "newNetworkDomainAction": "warn",
                "subprocessAction": "block",
                "telemetryEnabled": False,
                "syncEnabled": True,
                "updatedAt": "2026-04-09T00:00:00Z",
            },
            "alertPreferences": {
                "emailEnabled": True,
                "digestMode": "daily",
                "watchlistEnabled": True,
                "advisoriesEnabled": True,
                "repeatedWarningsEnabled": True,
                "teamAlertsEnabled": True,
                "updatedAt": "2026-04-09T00:00:00Z",
            },
            "exceptions": [
                {
                    "exceptionId": "artifact:codex:project:workspace_skill",
                    "scope": "artifact",
                    "harness": None,
                    "artifactId": "codex:project:workspace_skill",
                    "publisher": None,
                    "reason": "Temporary allow for workspace skill",
                    "owner": "guard@example.com",
                    "source": "manual",
                    "expiresAt": "2099-01-01T00:00:00Z",
                    "createdAt": "2026-04-09T00:00:00Z",
                    "updatedAt": "2026-04-09T00:00:00Z",
                }
            ],
            "teamPolicyPack": {
                "name": "Security team default",
                "sharedHarnessDefaults": {"codex": "enforce"},
                "allowedPublishers": ["hashgraph-online"],
                "blockedArtifacts": [],
                "alertChannel": "email",
                "updatedAt": "2026-04-09T00:00:00Z",
                "auditTrail": [],
            },
        }

        server = HTTPServer(("127.0.0.1", 0), _SyncRequestHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            _seed_sync_credentials(home_dir, f"http://127.0.0.1:{server.server_port}/receipts")
            login_rc = 0

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

            sync_rc = main(["guard", "sync", "--home", str(home_dir), "--json"])
            sync_output = json.loads(capsys.readouterr().out)

            advisories_rc = main(["guard", "advisories", "--home", str(home_dir), "--json"])
            advisories_output = json.loads(capsys.readouterr().out)
            policies_rc = main(["guard", "policies", "--home", str(home_dir), "--json"])
            policies_output = json.loads(capsys.readouterr().out)
            exceptions_rc = main(["guard", "exceptions", "--home", str(home_dir), "--json"])
            exceptions_output = json.loads(capsys.readouterr().out)
        finally:
            server.shutdown()
            thread.join(timeout=5)

        assert login_rc == 0
        assert run_rc == 0
        assert sync_rc == 0
        assert advisories_rc == 0
        assert policies_rc == 0
        assert exceptions_rc == 0
        assert sync_output["advisories_stored"] == 1
        assert advisories_output["items"][0]["publisher"] == "hashgraph-online"
        assert advisories_output["items"][0]["headline"] == "Publisher rotated to a new remote domain."
        assert not any(
            item["source"] in {"cloud-sync", "team-policy", "policy-bundle"} for item in policies_output["items"]
        )
        assert exceptions_output["items"] == []

    def test_guard_exceptions_handles_synced_naive_expiry_timestamps(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        _SyncRequestHandler.response_payload = {
            "syncedAt": "2026-04-09T00:00:00Z",
            "receiptsStored": 0,
            "inventoryStored": 0,
            "inventoryDiff": {"generatedAt": "2026-04-09T00:00:00Z", "items": []},
            "advisories": [],
            "exceptions": [
                {
                    "exceptionId": "artifact:codex:project:workspace_skill",
                    "scope": "artifact",
                    "artifactId": "codex:project:workspace_skill",
                    "reason": "Temporary allow for workspace skill",
                    "owner": "guard@example.com",
                    "source": "manual",
                    "expiresAt": "2099-01-01T00:00:00",
                }
            ],
        }

        server = HTTPServer(("127.0.0.1", 0), _SyncRequestHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            _seed_sync_credentials(home_dir, f"http://127.0.0.1:{server.server_port}/receipts")
            login_rc = 0

            sync_rc = main(["guard", "sync", "--home", str(home_dir), "--json"])
            sync_output = json.loads(capsys.readouterr().out)
            exceptions_rc = main(["guard", "exceptions", "--home", str(home_dir), "--json"])
            exceptions_output = json.loads(capsys.readouterr().out)
        finally:
            server.shutdown()
            thread.join(timeout=5)

        assert login_rc == 0
        assert sync_rc == 0
        assert exceptions_rc == 0
        assert sync_output["exceptions_stored"] == 0
        assert exceptions_output["items"] == []
