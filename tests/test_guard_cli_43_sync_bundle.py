"""Guard CLI sync bundle behavior."""

from __future__ import annotations

import json
import threading
from http.server import HTTPServer

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_cli_cloud_support import _disable_oauth_persistence_assert, _seed_sync_credentials, _SyncRequestHandler
from tests.guard_cli_fixture_support import _build_guard_fixture, _write_text
from tests.guard_cli_test_fixtures import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)
from tests.guard_cli_test_fixtures import (
    _use_legacy_update_context as _use_legacy_update_context,
)
from tests.policy_bundle_signing_helpers import sign_policy_bundle


class TestGuardCli:
    def test_guard_sync_clears_cached_policy_when_server_omits_it(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        _SyncRequestHandler.response_payload = {
            "syncedAt": "2026-04-09T00:00:00Z",
            "receiptsStored": 0,
            "inventoryStored": 0,
            "inventoryDiff": {"generatedAt": "2026-04-09T00:00:00Z", "items": []},
            "advisories": [],
            "policy": {
                "mode": "enforce",
                "defaultAction": "warn",
                "unknownPublisherAction": "review",
                "changedHashAction": "require-reapproval",
            },
            "alertPreferences": {
                "emailEnabled": True,
                "digestMode": "daily",
            },
            "teamPolicyPack": {
                "name": "Security team default",
                "allowedPublishers": ["hashgraph-online"],
            },
        }

        server = HTTPServer(("127.0.0.1", 0), _SyncRequestHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            _seed_sync_credentials(home_dir, f"http://127.0.0.1:{server.server_port}/receipts")
            login_rc = 0

            first_sync_rc = main(["guard", "sync", "--home", str(home_dir), "--json"])
            json.loads(capsys.readouterr().out)

            _SyncRequestHandler.response_payload = {
                "syncedAt": "2026-04-10T00:00:00Z",
                "receiptsStored": 0,
                "inventoryStored": 0,
                "inventoryDiff": {"generatedAt": "2026-04-10T00:00:00Z", "items": []},
                "advisories": [],
            }

            second_sync_rc = main(["guard", "sync", "--home", str(home_dir), "--json"])
            json.loads(capsys.readouterr().out)
        finally:
            server.shutdown()
            thread.join(timeout=5)

        policy_rc = main(["guard", "policies", "--home", str(home_dir), "--json"])
        policy_output = json.loads(capsys.readouterr().out)
        store = GuardStore(home_dir)

        assert login_rc == 0
        assert first_sync_rc == 0
        assert second_sync_rc == 0
        assert policy_rc == 0
        assert not any(item["source"] == "cloud-sync" for item in policy_output["items"])
        assert store.get_sync_payload("policy") == {}
        assert store.get_sync_payload("alert_preferences") == {}
        assert store.get_sync_payload("team_policy_pack") == {}

    def test_guard_run_auto_syncs_cloud_policy_bundle(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _disable_oauth_persistence_assert(monkeypatch)
        _build_guard_fixture(home_dir, workspace_dir)
        _write_text(home_dir / "config.toml", 'changed_hash_action = "allow"\n')
        _SyncRequestHandler.response_payload = {
            "syncedAt": "2026-04-09T00:00:00Z",
            "receiptsStored": 0,
            "inventoryStored": 0,
            "inventoryDiff": {"generatedAt": "2026-04-09T00:00:00Z", "items": []},
            "advisories": [],
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
            "policyBundle": {
                "contractVersion": "guard-policy-bundle.v1",
                "bundleVersion": "policy-2026-04-09.1",
                "bundleHash": "",
                "issuedAt": "2026-04-09T00:00:00Z",
                "expiresAt": None,
                "verifier": {
                    "algorithm": "rsa-pss-sha256",
                    "keyId": "guard-policy-bundle-v1",
                    "signature": None,
                },
                "rolloutState": "enforcing",
                "policyDefaults": {
                    "mode": "enforce",
                    "defaultAction": "warn",
                    "unknownPublisherAction": "review",
                    "changedHashAction": "allow",
                    "newNetworkDomainAction": "warn",
                    "subprocessAction": "block",
                    "telemetryEnabled": False,
                    "syncEnabled": True,
                },
                "rules": [
                    {
                        "ruleId": "block-global-tools",
                        "action": "block",
                        "reason": "Block the global tools fixture through signed policy authority.",
                        "artifactId": "codex:global:global_tools",
                        "scope": {
                            "agents": [],
                            "devices": [],
                            "ecosystems": [],
                            "environments": [],
                            "harnesses": ["codex"],
                            "locations": [],
                        },
                    }
                ],
                "acknowledgements": [
                    {
                        "deviceId": "device-1",
                        "deviceName": "Guard local daemon",
                        "acknowledgedAt": "2026-04-09T00:01:00Z",
                        "status": "synced",
                    }
                ],
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
            "exceptions": [],
            "teamPolicyPack": {
                "name": "Security team default",
                "sharedHarnessDefaults": {"codex": "enforce"},
                "allowedPublishers": [],
                "blockedArtifacts": ["codex:global:global_tools"],
                "alertChannel": "email",
                "updatedAt": "2026-04-09T00:00:00Z",
                "auditTrail": [],
            },
        }
        policy_bundle = _SyncRequestHandler.response_payload["policyBundle"]
        signed_policy_bundle = sign_policy_bundle(policy_bundle)
        _SyncRequestHandler.response_payload["policyBundle"] = signed_policy_bundle

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
                    "--json",
                ]
            )
            run_output = json.loads(capsys.readouterr().out)
        finally:
            server.shutdown()
            thread.join(timeout=5)

        assert login_rc == 0
        assert run_rc == 1
        assert _SyncRequestHandler.captured_body is not None
        assert run_output["blocked"] is True
        store = GuardStore(home_dir)
        assert store.get_sync_payload("policy_bundle") == signed_policy_bundle
        assert any(
            artifact["artifact_id"] == "codex:global:global_tools" and artifact["policy_action"] == "block"
            for artifact in run_output["artifacts"]
        )
