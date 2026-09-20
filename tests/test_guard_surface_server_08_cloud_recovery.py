from __future__ import annotations

from tests.guard_surface_fixture_support import SYNTHETIC_DPOP_PRIVATE_KEY_PEM
from tests.test_guard_surface_server import GuardDaemonServer, GuardStore, _guard_get_request, json, urllib


class TestGuardSurfaceServer:
    def test_guard_daemon_runtime_snapshot_softens_refresh_race_copy_when_local_protection_stays_active(
        self,
        tmp_path,
    ) -> None:
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
            supply_chain_entitlement_expires_at="2026-07-04T18:30:00+00:00",
            supply_chain_firewall=True,
            supply_chain_plan_id="team",
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
            reason="Guard authorization expired. The grant is missing, expired, or already consumed.",
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
        assert "Local Guard remains available" in payload["cloud_state_detail"]
        assert "protected" not in payload["cloud_state_detail"].lower()
        assert payload["cloud_pairing_state"]["detail"] == payload["cloud_state_detail"]
        assert payload["proof_status"]["state"] == "stalled"
        assert payload["proof_status"]["detail"].startswith("Local Guard remains available.")
        assert payload["cloud_sync_health"]["state"] == "failed"
        assert payload["cloud_sync_health"]["detail"].startswith("Local Guard remains available.")

    def test_guard_daemon_runtime_snapshot_reports_post_sync_reauth_as_local_only(self, tmp_path) -> None:
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
            request_id="connect-post-sync-401",
        )
        store.record_latest_guard_connect_sync_result(
            status="retry_required",
            milestone="first_sync_failed",
            now="2026-06-04T19:00:00+00:00",
            reason=(
                "Guard Cloud sign-in on this device is no longer valid. "
                "Run `hol-guard disconnect` then `hol-guard connect` to sign in again."
            ),
        )
        store.set_sync_payload(
            "sync_summary",
            {
                "synced_at": "2026-06-04T18:45:00+00:00",
                "receipts_stored": 11,
                "inventory": 0,
                "inventory_tracked": 261,
            },
            "2026-06-04T18:45:00+00:00",
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

        assert payload["cloud_state"] == "local_only"
        assert payload["cloud_pairing_state"]["state"] == "local_only"
        assert "needs repair before shared proof can resume" in payload["cloud_state_detail"]
        assert payload["cloud_pairing_state"]["detail"] == payload["cloud_state_detail"]
        assert payload["cloud_sync_health"]["state"] == "failed"

    def test_guard_daemon_runtime_snapshot_keeps_failed_sync_copy_distinct_from_oauth_repair(self, tmp_path) -> None:
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
        store.set_sync_payload(
            "guard_events_v1_summary",
            {
                "status": "failed",
                "synced_at": "2026-06-04T18:31:00+00:00",
                "next_retry_after": "2026-06-04T18:35:00+00:00",
            },
            "2026-06-04T18:31:00+00:00",
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

        assert payload["cloud_sync_health"]["state"] == "failed"
        assert "did not accept the last upload" in payload["cloud_sync_health"]["detail"]
        assert "Run hol-guard connect again" not in payload["cloud_sync_health"]["detail"]

    def test_guard_daemon_runtime_snapshot_prefers_active_sync_over_expired_connect_state(self, tmp_path) -> None:
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
        store.set_sync_payload(
            "sync_summary",
            {
                "synced_at": "2026-06-04T18:31:00+00:00",
                "receipts_stored": 3,
                "inventory_tracked": 1,
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

        assert payload["cloud_state"] == "paired_active"
        assert payload["proof_status"]["state"] == "synced"
        assert payload["proof_status"]["label"] == "First proof synced"
        assert payload["proof_status"]["first_synced_at"] == "2026-06-04T18:31:00+00:00"
        assert payload["latest_connect_state"]["status"] == "connected"
        assert payload["latest_connect_state"]["milestone"] == "first_sync_succeeded"
