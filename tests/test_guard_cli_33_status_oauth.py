"""Guard CLI status oauth behavior."""

from __future__ import annotations

import json

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli import product as guard_product_module
from codex_plugin_scanner.guard.config import load_guard_config
from codex_plugin_scanner.guard.store import GuardStore
from tests import test_guard_cli as _guard_cli_fixture
from tests.guard_cli_cloud_support import _seed_guard_cloud
from tests.guard_cli_fixture_support import _build_guard_fixture
from tests.guard_cli_test_fixtures import (
    _isolate_codex_runtime_marker as _isolate_codex_runtime_marker,
)
from tests.guard_cli_test_fixtures import (
    _use_legacy_update_context as _use_legacy_update_context,
)


class TestGuardCli:
    def test_guard_status_reports_oauth_key_storage_health(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        store = GuardStore(home_dir)
        _seed_guard_cloud(store, workspace_id="workspace-123")
        _guard_cli_fixture._OAuthCredentialsFixture.seed(store, now="2026-06-01T00:00:00+00:00")
        expected_storage_health = store.get_oauth_local_credential_health()
        monkeypatch.setattr(
            GuardStore,
            "get_oauth_local_credential_health",
            lambda _store: expected_storage_health,
        )

        status_rc = main(["guard", "status", "--home", str(home_dir), "--workspace", str(workspace_dir), "--json"])
        status_output = json.loads(capsys.readouterr().out)

        assert status_rc == 0
        assert status_output["oauth_storage_health"] == expected_storage_health
        assert status_output["oauth_storage_health"]["configured"] is True
        assert status_output["oauth_storage_health"]["state"] == "healthy"
        assert "refresh-secret-value" not in json.dumps(status_output)

    def test_guard_connect_status_prefers_active_sync_over_expired_browser_pairing(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        store = GuardStore(home_dir)
        _guard_cli_fixture._OAuthCredentialsFixture.seed(store, now="2026-06-04T18:30:00+00:00")
        store.set_sync_payload(
            "sync_summary",
            {
                "synced_at": "2026-06-04T18:31:00+00:00",
                "receipts_stored": 4,
                "inventory_tracked": 2,
            },
            "2026-06-04T18:31:00+00:00",
        )
        with store._connect() as connection:
            connection.execute(
                """
                insert into guard_connect_states (
                  request_id,
                  sync_url,
                  allowed_origin,
                  status,
                  milestone,
                  reason,
                  created_at,
                  updated_at,
                  expires_at,
                  completed_at,
                  proof_json
                )
                values (?, ?, ?, 'expired', 'expired', 'request_expired', ?, ?, ?, ?, ?)
                """,
                (
                    "connect-expired",
                    "https://hol.org/api/guard/receipts/sync",
                    "https://hol.org",
                    "2026-06-04T18:20:00+00:00",
                    "2026-06-04T18:20:00+00:00",
                    "2026-06-04T18:25:00+00:00",
                    "2026-06-04T18:20:00+00:00",
                    json.dumps({}),
                ),
            )

        rc = main(["guard", "connect", "status", "--home", str(home_dir), "--workspace", str(workspace_dir), "--json"])
        output = json.loads(capsys.readouterr().out)

        assert rc == 0
        assert output["status"] == "connected"
        assert output["milestone"] == "first_sync_succeeded"
        assert output["reason"] == "first_sync_succeeded"
        assert output["sync_url"] == "https://hol.org/api/guard/receipts/sync"
        assert output["connect_url"] == "https://hol.org/guard/connect"
        assert output["latest_connect_state"]["status"] == "connected"
        assert output["latest_connect_state"]["milestone"] == "first_sync_succeeded"
        assert output["latest_connect_state"]["proof"]["first_synced_at"] == "2026-06-04T18:31:00+00:00"

    def test_guard_status_degraded_oauth_does_not_fall_back_to_legacy_sync(self, tmp_path, capsys, monkeypatch):
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        store = GuardStore(home_dir)
        _guard_cli_fixture._OAuthCredentialsFixture.seed(store, now="2026-06-04T18:30:00+00:00")
        oauth_payload = store.get_sync_payload("oauth_local_credentials")
        assert isinstance(oauth_payload, dict)
        oauth_payload["credentials_sha256"] = "pbkdf2-sha256$invalid"
        store.set_sync_payload("oauth_local_credentials", oauth_payload, "2026-06-04T18:30:30+00:00")

        output = guard_product_module.build_guard_status_payload(
            HarnessContext(home_dir=home_dir, workspace_dir=workspace_dir, guard_home=home_dir),
            store,
            load_guard_config(home_dir),
        )

        assert output["sync_configured"] is False
        assert output["cloud_state"] == "local_only"
        assert "sign-in on this machine is incomplete" in output["cloud_state_detail"]
        assert output["oauth_storage_health"]["state"] == "degraded"

    def test_guard_status_marks_stale_connected_state_retry_required_when_oauth_is_missing(
        self,
        tmp_path,
        capsys,
    ):
        del capsys
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        store = GuardStore(home_dir)
        store.record_guard_connect_pairing_completed(
            sync_url="https://hol.org/api/guard/receipts/sync",
            allowed_origin="https://hol.org",
            now="2026-06-11T22:11:11+00:00",
            request_id="connect-401",
        )
        store.record_latest_guard_connect_sync_result(
            status="connected",
            milestone="first_sync_pending",
            now="2026-06-11T22:11:11+00:00",
            reason="Guard Cloud is unavailable. Local Guard keeps protecting this machine.",
        )

        output = guard_product_module.build_guard_status_payload(
            HarnessContext(home_dir=home_dir, workspace_dir=workspace_dir, guard_home=home_dir),
            store,
            load_guard_config(home_dir),
        )

        latest_state = output["latest_connect_state"]
        assert isinstance(latest_state, dict)
        assert latest_state["status"] == "retry_required"
        assert latest_state["milestone"] == "first_sync_failed"
        assert latest_state["reason"] == (
            "Guard Cloud authorization on this machine is incomplete. Run hol-guard connect again."
        )
        assert output["cloud_state"] == "local_only"
        assert "needs repair before the first shared proof can land" in output["cloud_state_detail"]

    def test_guard_status_marks_stale_connected_state_retry_required_when_oauth_is_degraded(
        self,
        tmp_path,
        capsys,
        monkeypatch,
    ):
        del capsys
        home_dir = tmp_path / "home"
        workspace_dir = tmp_path / "workspace"
        _build_guard_fixture(home_dir, workspace_dir)
        store = GuardStore(home_dir)
        store.record_guard_connect_pairing_completed(
            sync_url="https://hol.org/api/guard/receipts/sync",
            allowed_origin="https://hol.org",
            now="2026-06-11T22:11:11+00:00",
            request_id="connect-403",
        )
        store.record_latest_guard_connect_sync_result(
            status="connected",
            milestone="first_sync_pending",
            now="2026-06-11T22:11:11+00:00",
            reason="Guard Cloud is unavailable. Local Guard keeps protecting this machine.",
        )
        _guard_cli_fixture._OAuthCredentialsFixture.seed(store, now="2026-06-11T22:12:00+00:00")
        oauth_payload = store.get_sync_payload("oauth_local_credentials")
        assert isinstance(oauth_payload, dict)
        oauth_payload["credentials_sha256"] = "pbkdf2-sha256$invalid"
        store.set_sync_payload("oauth_local_credentials", oauth_payload, "2026-06-11T22:12:30+00:00")

        output = guard_product_module.build_guard_status_payload(
            HarnessContext(home_dir=home_dir, workspace_dir=workspace_dir, guard_home=home_dir),
            store,
            load_guard_config(home_dir),
        )

        latest_state = output["latest_connect_state"]
        assert isinstance(latest_state, dict)
        assert latest_state["status"] == "retry_required"
        assert latest_state["milestone"] == "first_sync_failed"
        assert latest_state["reason"] == (
            "Guard Cloud authorization on this machine is incomplete. Run hol-guard connect again."
        )
        assert output["oauth_storage_health"]["state"] == "degraded"
