"""Guard CLI sync receipts behavior."""

from __future__ import annotations

import json
import threading
from http.server import HTTPServer

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_cli_cloud_support import _seed_sync_credentials, _SyncRequestHandler
from tests.guard_cli_fixture_support import _build_stable_guard_fixture, _write_text
from tests.guard_cli_test_fixtures import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)
from tests.guard_cli_test_fixtures import (
    _use_legacy_update_context as _use_legacy_update_context,
)
from tests.policy_bundle_signing_helpers import sign_policy_bundle


class TestGuardCli:
    def test_guard_login_and_sync_posts_receipts(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_stable_guard_fixture(home_dir, workspace_dir)
        _write_text(home_dir / "config.toml", 'changed_hash_action = "allow"\n')
        _SyncRequestHandler.response_payload = {
            "syncedAt": "2026-04-09T00:00:00Z",
            "receiptsStored": 1,
        }
        _SyncRequestHandler.captured_bodies = []
        _SyncRequestHandler.captured_paths = []

        server = HTTPServer(("127.0.0.1", 0), _SyncRequestHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            _seed_sync_credentials(
                home_dir,
                f"http://127.0.0.1:{server.server_port}/receipts",
                "demo-token",
            )
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

            sync_rc = main(
                [
                    "guard",
                    "sync",
                    "--home",
                    str(home_dir),
                    "--json",
                ]
            )
            sync_output = json.loads(capsys.readouterr().out)
            status_rc = main(["guard", "status", "--home", str(home_dir), "--workspace", str(workspace_dir), "--json"])
            status_output = json.loads(capsys.readouterr().out)
        finally:
            server.shutdown()
            thread.join(timeout=5)

        assert login_rc == 0
        assert run_rc == 0
        assert sync_rc == 0
        assert status_rc == 0
        assert sync_output["receipts_stored"] == 1
        assert sync_output["inventory"] == 0
        assert sync_output["inventory_tracked"] >= 1
        assert status_output["cloud_state"] == "paired_active"
        assert status_output["last_sync_at"] == "2026-04-09T00:00:00Z"
        assert _SyncRequestHandler.captured_headers["authorization"] == "Bearer demo-token"
        receipt_body = next(
            body
            for body in _SyncRequestHandler.captured_bodies
            if isinstance(body.get("receipts"), list) and len(body["receipts"]) >= 1
        )
        event_body = next(body for body in _SyncRequestHandler.captured_bodies if "events" in body)
        assert len(receipt_body["receipts"]) >= 1
        assert "inventory" not in receipt_body
        assert len(event_body["events"]) >= 1
        first_receipt = receipt_body["receipts"][0]
        assert "artifactId" in first_receipt
        assert "artifact_id" not in first_receipt
        assert "receiptId" in first_receipt
        assert "artifactSlug" in first_receipt
        assert "artifactHash" in first_receipt
        assert "recommendation" in first_receipt

    def test_guard_sync_persists_cloud_policy_bundle_for_manual_sync(self, tmp_path, capsys):
        home_dir = tmp_path / "home"
        _SyncRequestHandler.response_code = 200
        _SyncRequestHandler.response_payload = {
            "syncedAt": "2026-06-05T13:45:00Z",
            "receiptsStored": 0,
            "policyBundle": {
                "contractVersion": "guard-policy-bundle.v1",
                "bundleVersion": "policy-2026-06-05.1",
                "bundleHash": "sha256:bundle-proof",
                "issuedAt": "2026-06-05T13:45:00Z",
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
                    "changedHashAction": "require-reapproval",
                    "newNetworkDomainAction": "warn",
                    "subprocessAction": "block",
                    "telemetryEnabled": False,
                    "syncEnabled": True,
                },
                "rules": [],
                "acknowledgements": [],
            },
        }
        policy_bundle = _SyncRequestHandler.response_payload["policyBundle"]
        _SyncRequestHandler.response_payload["policyBundle"] = sign_policy_bundle(policy_bundle)

        server = HTTPServer(("127.0.0.1", 0), _SyncRequestHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            _seed_sync_credentials(home_dir, f"http://127.0.0.1:{server.server_port}/receipts")
            rc = main(["guard", "sync", "--home", str(home_dir), "--json"])
            payload = json.loads(capsys.readouterr().out)
        finally:
            server.shutdown()
            thread.join(timeout=5)
            _SyncRequestHandler.response_code = 200
            _SyncRequestHandler.response_payload = {
                "syncedAt": "2026-04-09T00:00:00Z",
                "receiptsStored": 1,
            }

        assert rc == 0
        assert payload["synced_at"] == "2026-06-05T13:45:00Z"
        assert GuardStore(home_dir).get_sync_payload("policy_bundle")["bundleVersion"] == "policy-2026-06-05.1"
