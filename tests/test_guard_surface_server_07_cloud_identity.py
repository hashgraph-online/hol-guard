from __future__ import annotations

from tests.guard_surface_fixture_support import SYNTHETIC_DPOP_PRIVATE_KEY_PEM
from tests.test_guard_surface_server import (
    GuardArtifact,
    GuardDaemonServer,
    GuardStore,
    _guard_get_request,
    _seed_guard_cloud,
    json,
    urllib,
)


class TestGuardSurfaceServer:
    def test_guard_daemon_runtime_snapshot_exposes_cloud_handoff_state(self, tmp_path) -> None:
        store = GuardStore(tmp_path / "guard-home")
        _seed_guard_cloud(store)
        store.set_sync_payload(
            "sync_summary",
            {"synced_at": "2026-04-22T00:05:00Z"},
            "2026-04-22T00:05:00Z",
        )
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            with urllib.request.urlopen(
                _guard_get_request(daemon.port, "/v1/runtime", daemon._server.auth_token),
                timeout=5,
            ) as response:
                payload = json.loads(response.read().decode("utf-8"))
        finally:
            daemon.stop()

        assert payload["headline_state"] == "degraded"
        assert payload["headline_label"] == "Degraded"
        assert payload["protection_health"]["state"] == "degraded"
        assert "no_managed_harness" in payload["protection_health"]["reason_codes"]
        assert payload["cloud_state"] == "paired_active"
        assert payload["cloud_state_label"] == "Connected"
        assert payload["cloud_pairing_state"] == {
            "state": "paired_active",
            "label": "Connected",
            "detail": payload["cloud_state_detail"],
            "sync_configured": True,
            "cloud_user_profile": None,
            "workspace_id": None,
            "plan_id": None,
            "dashboard_url": "https://hol.org/guard",
            "inbox_url": "https://hol.org/guard/inbox",
            "fleet_url": "https://hol.org/guard/protect",
            "connect_url": "https://hol.org/guard/connect",
        }
        assert payload["dashboard_url"] == "https://hol.org/guard"
        assert payload["inbox_url"] == "https://hol.org/guard/inbox"
        assert payload["fleet_url"] == "https://hol.org/guard/protect"
        assert payload["connect_url"] == "https://hol.org/guard/connect"
        assert "inventory" not in payload

    def test_guard_daemon_inventory_endpoint_exposes_watched_artifacts(self, tmp_path) -> None:
        store = GuardStore(tmp_path / "guard-home")
        store.record_inventory_artifact(
            artifact=GuardArtifact(
                artifact_id="codex:project:workspace-tool",
                name="workspace-tool",
                harness="codex",
                artifact_type="tool",
                source_scope="project",
                config_path=str(tmp_path / "workspace" / "codex.json"),
                command="python",
                args=("-m", "workspace_tool"),
            ),
            artifact_hash="hash-workspace-tool",
            policy_action="allow",
            changed=False,
            now="2026-04-23T00:00:00+00:00",
            approved=True,
        )
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            with urllib.request.urlopen(
                _guard_get_request(daemon.port, "/v1/inventory", daemon._server.auth_token),
                timeout=5,
            ) as response:
                payload = json.loads(response.read().decode("utf-8"))
        finally:
            daemon.stop()

        assert payload["items"][0]["artifact_id"] == "codex:project:workspace-tool"
        assert payload["items"][0]["launch_command"] == "python -m workspace_tool"

    def test_guard_daemon_runtime_snapshot_derives_cloud_urls_from_sync_origin(self, tmp_path) -> None:
        store = GuardStore(tmp_path / "guard-home")
        _seed_guard_cloud(store)
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            with urllib.request.urlopen(
                _guard_get_request(daemon.port, "/v1/runtime", daemon._server.auth_token),
                timeout=5,
            ) as response:
                payload = json.loads(response.read().decode("utf-8"))
        finally:
            daemon.stop()

        assert payload["cloud_state"] == "paired_waiting"
        assert payload["cloud_pairing_state"]["state"] == "paired_waiting"
        assert payload["cloud_pairing_state"]["sync_configured"] is True
        assert payload["dashboard_url"] == "https://hol.org/guard"
        assert payload["inbox_url"] == "https://hol.org/guard/inbox"
        assert payload["fleet_url"] == "https://hol.org/guard/protect"
        assert payload["connect_url"] == "https://hol.org/guard/connect"

    def test_guard_daemon_runtime_snapshot_uses_oauth_profile_without_legacy_credentials(self, tmp_path) -> None:
        store = GuardStore(tmp_path / "guard-home")
        store.set_oauth_local_credentials(
            issuer="https://hol.org",
            client_id="guard-local-daemon",
            refresh_token="refresh-secret-value",
            dpop_private_key_pem=SYNTHETIC_DPOP_PRIVATE_KEY_PEM,
            dpop_public_jwk={
                "kty": "EC",
                "crv": "P-256",
                "x": "x-value",
                "y": "y-value",
                "alg": "ES256",
                "use": "sig",
            },
            dpop_public_jwk_thumbprint="thumbprint-123",
            grant_id="grant-123",
            machine_id="machine-123",
            workspace_id="workspace-123",
            now="2026-06-04T18:30:00+00:00",
        )
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            with urllib.request.urlopen(
                _guard_get_request(daemon.port, "/v1/runtime", daemon._server.auth_token),
                timeout=5,
            ) as response:
                payload = json.loads(response.read().decode("utf-8"))
        finally:
            daemon.stop()

        assert payload["cloud_state"] == "paired_waiting"
        assert payload["sync_configured"] is True
        assert payload["dashboard_url"] == "https://hol.org/guard"
        assert payload["inbox_url"] == "https://hol.org/guard/inbox"
        assert payload["fleet_url"] == "https://hol.org/guard/protect"
        assert payload["connect_url"] == "https://hol.org/guard/connect"
        assert payload["cloud_pairing_state"]["state"] == "paired_waiting"
        assert payload["cloud_pairing_state"]["sync_configured"] is True

    def test_guard_daemon_runtime_snapshot_extracts_plan_id_from_oauth_credentials(self, tmp_path) -> None:
        store = GuardStore(tmp_path / "guard-home")
        store.set_oauth_local_credentials(
            issuer="https://hol.org",
            client_id="guard-local-daemon",
            refresh_token="test-token-not-real",
            dpop_private_key_pem=SYNTHETIC_DPOP_PRIVATE_KEY_PEM,
            dpop_public_jwk={
                "kty": "EC",
                "crv": "P-256",
                "x": "x-value",
                "y": "y-value",
                "alg": "ES256",
                "use": "sig",
            },
            dpop_public_jwk_thumbprint="thumbprint-123",
            grant_id="grant-123",
            machine_id="machine-123",
            workspace_id="workspace-123",
            supply_chain_plan_id="team",
            now="2026-06-04T18:30:00+00:00",
        )
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            with urllib.request.urlopen(
                _guard_get_request(daemon.port, "/v1/runtime", daemon._server.auth_token),
                timeout=5,
            ) as response:
                payload = json.loads(response.read().decode("utf-8"))
        finally:
            daemon.stop()

        assert payload["cloud_pairing_state"]["plan_id"] == "team"

    def test_guard_daemon_runtime_snapshot_mirrors_oauth_repair_detail_in_pairing_state(self, tmp_path) -> None:
        store = GuardStore(tmp_path / "guard-home")
        store.set_oauth_local_credentials(
            issuer="https://hol.org",
            client_id="guard-local-daemon",
            refresh_token="refresh-secret-value",
            dpop_private_key_pem=SYNTHETIC_DPOP_PRIVATE_KEY_PEM,
            dpop_public_jwk={
                "kty": "EC",
                "crv": "P-256",
                "x": "x-value",
                "y": "y-value",
                "alg": "ES256",
                "use": "sig",
            },
            dpop_public_jwk_thumbprint="thumbprint-123",
            grant_id="grant-123",
            machine_id="machine-123",
            workspace_id="workspace-123",
            now="2026-06-04T18:30:00+00:00",
        )
        oauth_payload = store.get_sync_payload("oauth_local_credentials")
        assert isinstance(oauth_payload, dict)
        oauth_payload["credentials_sha256"] = "pbkdf2-sha256$invalid"
        store.set_sync_payload("oauth_local_credentials", oauth_payload, "2026-06-04T18:30:30+00:00")
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            with urllib.request.urlopen(
                _guard_get_request(daemon.port, "/v1/runtime", daemon._server.auth_token),
                timeout=5,
            ) as response:
                payload = json.loads(response.read().decode("utf-8"))
        finally:
            daemon.stop()

        assert payload["cloud_state"] == "local_only"
        assert "sign-in on this machine is incomplete" in payload["cloud_state_detail"]
        assert payload["cloud_pairing_state"]["detail"] == payload["cloud_state_detail"]

    def test_guard_daemon_runtime_snapshot_surfaces_first_sync_repair_consistently(self, tmp_path) -> None:
        store = GuardStore(tmp_path / "guard-home")
        store.set_oauth_local_credentials(
            issuer="https://hol.org",
            client_id="guard-local-daemon",
            refresh_token="refresh-secret-value",
            dpop_private_key_pem=SYNTHETIC_DPOP_PRIVATE_KEY_PEM,
            dpop_public_jwk={
                "kty": "EC",
                "crv": "P-256",
                "x": "x-value",
                "y": "y-value",
                "alg": "ES256",
                "use": "sig",
            },
            dpop_public_jwk_thumbprint="thumbprint-123",
            grant_id="grant-123",
            machine_id="machine-123",
            workspace_id="workspace-123",
            now="2026-06-04T18:30:00+00:00",
        )
        store.record_guard_connect_pairing_completed(
            sync_url="https://hol.org/api/guard/receipts/sync",
            allowed_origin="https://hol.org",
            now="2026-06-04T18:30:00+00:00",
        )
        store.record_latest_guard_connect_sync_result(
            status="retry_required",
            milestone="first_sync_failed",
            now="2026-06-04T18:31:00+00:00",
            reason="Guard authorization expired.",
        )
        daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
        daemon.start()

        try:
            with urllib.request.urlopen(
                _guard_get_request(daemon.port, "/v1/runtime", daemon._server.auth_token),
                timeout=5,
            ) as response:
                payload = json.loads(response.read().decode("utf-8"))
        finally:
            daemon.stop()

        assert payload["cloud_state"] == "paired_waiting"
        assert "needs repair before the first shared proof can land" in payload["cloud_state_detail"]
        assert payload["cloud_pairing_state"]["detail"] == payload["cloud_state_detail"]
        assert payload["proof_status"]["state"] == "failed"
        assert payload["cloud_sync_health"]["state"] == "failed"
        assert "Run hol-guard connect again to restore sync." in payload["cloud_sync_health"]["detail"]
