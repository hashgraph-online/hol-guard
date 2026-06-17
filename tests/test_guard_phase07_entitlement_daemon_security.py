"""Phase 07 entitlement and local daemon security proofs (SCSR116-SCSR130)."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.approval_gate import update_settings as update_approval_gate_settings
from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.daemon.manager import load_guard_daemon_auth_token
from codex_plugin_scanner.guard.package_firewall_action_rate_limit import PackageFirewallActionRateLimiter
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_headless_daemon_api import (
    _dashboard_token_for,
    _dashboard_token_with_claims,
    _read_json_response,
    _request,
)


def _seed_free_entitlement(store: GuardStore) -> None:
    store.set_sync_payload(
        "supply_chain_bundle_entitlement",
        {"tier": "free", "workspace_id": "workspace-1"},
        "2026-06-09T12:00:00.000Z",
    )


def _seed_free_connect_state(store: GuardStore) -> None:
    store.set_sync_payload(
        "oauth_local_credentials",
        {
            "supply_chain_plan_id": "free",
            "supply_chain_firewall": False,
        },
        "2026-06-09T12:00:00.000Z",
    )


def _seed_premium_entitlement(store: GuardStore) -> None:
    store.set_sync_payload(
        "supply_chain_bundle_entitlement",
        {"tier": "premium", "workspace_id": "workspace-1"},
        "2026-06-09T12:00:00.000Z",
    )


def test_phase07_non_status_package_shim_operations_require_paid_entitlement(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _seed_free_entitlement(store)
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = _dashboard_token_for(store)
        install_status, install_payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/supply-chain/package-shims/install",
                token=token,
                payload={"managers": ["npm"], "workspace_id": "workspace-1"},
            ),
        )
        status_status, status_payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/supply-chain/package-shims",
                method="GET",
                token=token,
            ),
        )
    finally:
        daemon.stop()

    assert install_status in {402, 403}
    assert install_payload["entitlement"]["allowed"] is False
    assert install_payload["error"] in {"paid_guard_cloud_required", "guard_cloud_connect_required"}
    assert status_status == 200
    assert status_payload["operation"] == "status"


def test_phase07_revoked_entitlement_blocks_repair_and_remove(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="refresh-token-1",
        dpop_private_key_pem="private-key",
        dpop_public_jwk={"kty": "EC", "crv": "P-256", "x": "x-value", "y": "y-value"},
        dpop_public_jwk_thumbprint="thumbprint-1",
        grant_id="grant-1",
        machine_id="machine-1",
        workspace_id="workspace-1",
        now="2026-06-09T12:00:00.000Z",
    )
    store.record_guard_connect_pairing_completed(
        sync_url="https://hol.org/api/guard/receipts/sync",
        allowed_origin="https://hol.org",
        now="2026-06-09T12:00:00.000Z",
        request_id="connect-1",
    )
    store.record_latest_guard_connect_sync_result(
        status="retry_required",
        milestone="first_sync_failed",
        now="2026-06-09T12:00:10.000Z",
        reason="Guard authorization expired. Run `hol-guard connect` again.",
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.local_supply_chain.sync_local_guard_cloud_proof",
        lambda _store: (_ for _ in ()).throw(RuntimeError("cloud auth still expired")),
    )
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.local_supply_chain.sync_supply_chain_bundle",
        lambda _store: (_ for _ in ()).throw(RuntimeError("bundle refresh blocked")),
    )
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = _dashboard_token_for(store)
        repair_status, repair_payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/supply-chain/package-shims/repair",
                token=token,
                payload={"managers": ["npm"], "workspace_id": "workspace-1"},
            ),
        )
    finally:
        daemon.stop()

    assert repair_status == 403
    assert repair_payload["error"] == "guard_cloud_reconnect_required"


def test_phase07_local_dashboard_session_binds_operation_workspace_location_and_origin(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _seed_premium_entitlement(store)
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        auth_token = load_guard_daemon_auth_token(store.guard_home)
        assert auth_token is not None
        local_origin = f"http://127.0.0.1:{daemon.port}"
        token = _dashboard_token_with_claims(
            auth_token,
            {
                "action_path": "package_shims_test",
                "allowed_action_paths": ["package_shims_test"],
                "daemon_origin": local_origin,
                "location_id": "location-1",
                "managers": ["npm"],
                "nonce": "test-nonce-1",
                "workspace_id": "workspace-1",
            },
        )
        allowed_status, _allowed_payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/supply-chain/package-shims/test",
                dashboard_session_token=token,
                origin=local_origin,
                payload={
                    "daemon_origin": local_origin,
                    "location_id": "location-1",
                    "managers": ["npm"],
                    "workspace_id": "workspace-1",
                },
            ),
        )
        wrong_origin_status, _wrong_origin_payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/supply-chain/package-shims/test",
                dashboard_session_token=token,
                origin="https://evil.example",
                payload={
                    "daemon_origin": "https://evil.example",
                    "location_id": "location-1",
                    "managers": ["npm"],
                    "workspace_id": "workspace-1",
                },
            ),
        )
        replay_status, replay_payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/supply-chain/package-shims/test",
                dashboard_session_token=token,
                origin=local_origin,
                payload={
                    "daemon_origin": local_origin,
                    "location_id": "location-1",
                    "managers": ["npm"],
                    "workspace_id": "workspace-1",
                },
            ),
        )
    finally:
        daemon.stop()

    assert allowed_status == 200
    assert wrong_origin_status == 403
    assert replay_status == 401
    assert replay_payload["error"] == "unauthorized"


def test_phase07_install_and_sync_require_approval_gate(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _seed_premium_entitlement(store)
    update_approval_gate_settings(
        store.guard_home,
        {
            "enabled": True,
            "new_password": "phase07-password",
            "confirm_password": "phase07-password",
        },
    )
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = _dashboard_token_for(store)
        install_status, install_payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/supply-chain/package-shims/install",
                token=token,
                payload={"managers": ["npm"], "workspace_id": "workspace-1"},
            ),
        )
        sync_status, sync_payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/supply-chain/sync",
                token=token,
                payload={"workspace_id": "workspace-1"},
            ),
        )
    finally:
        daemon.stop()

    assert install_status == 403
    assert install_payload["error"] == "approval_gate_required"
    assert sync_status == 403
    assert sync_payload["error"] == "approval_gate_required"


def test_phase07_auth_audit_events_do_not_leak_dashboard_tokens(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        leaked_token = "gld1.leaked-payload.leaked-signature"
        request = _request(
            daemon.port,
            "/v1/supply-chain/package-shims/install",
            authorization_token=leaked_token,
            dashboard_session_token=leaked_token,
            payload={"managers": ["npm"], "workspace_id": "workspace-1"},
        )
        with pytest.raises(urllib.error.HTTPError):
            urllib.request.urlopen(request, timeout=5)
    finally:
        daemon.stop()

    events = store.list_events(limit=5, event_name="daemon.auth.unauthorized")
    serialized = json.dumps(events)
    assert "leaked-payload" not in serialized
    assert "leaked-signature" not in serialized
    assert events[0]["payload"]["has_dashboard_session"] is True


def test_phase07_package_firewall_rate_limiter_blocks_burst_actions() -> None:
    limiter = PackageFirewallActionRateLimiter(limit=2, window_seconds=60.0)
    assert limiter.allow("workspace-1:install", now=100.0) == (True, 0)
    assert limiter.allow("workspace-1:install", now=101.0) == (True, 0)
    allowed, retry_after = limiter.allow("workspace-1:install", now=102.0)
    assert allowed is False
    assert retry_after >= 1


def test_phase07_daemon_rate_limits_package_firewall_actions(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    _seed_premium_entitlement(store)
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon._server.package_firewall_action_rate_limiter = PackageFirewallActionRateLimiter(limit=1, window_seconds=60.0)  # type: ignore[attr-defined]
    daemon.start()
    try:
        token = _dashboard_token_for(store)
        first_status, _first_payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/supply-chain/package-shims/test",
                token=token,
                payload={"managers": ["npm"], "workspace_id": "workspace-1"},
            ),
        )
        second_status, second_payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/supply-chain/package-shims/test",
                token=token,
                payload={"managers": ["npm"], "workspace_id": "workspace-1"},
            ),
        )
    finally:
        daemon.stop()

    assert first_status == 200
    assert second_status == 429
    assert second_payload["error"] == "rate_limited"
