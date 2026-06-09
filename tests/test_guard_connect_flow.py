"""Focused tests for the OAuth-only Guard connect flow."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli.connect_flow import (
    GuardOAuthLoopbackCallback,
    GuardOAuthTokenExchangeResult,
    build_connect_status_payload,
    run_guard_browser_connect_command,
)
from codex_plugin_scanner.guard.cli.oauth_client import GuardDpopKeyMaterial
from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.package_firewall_entitlement import resolve_package_firewall_entitlement
from codex_plugin_scanner.guard.runtime import runner as guard_runner_module
from codex_plugin_scanner.guard.store import GuardStore


def _initialize_daemon(daemon: GuardDaemonServer) -> dict[str, object]:
    request = urllib.request.Request(
        f"http://127.0.0.1:{daemon.port}/v1/initialize",
        data=json.dumps(
            {
                "client_name": "hol-guard-cli",
                "surface": "cli",
                "supported_protocol_versions": ["1.1"],
            }
        ).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        payload = json.loads(response.read().decode("utf-8"))
    assert isinstance(payload, dict)
    return payload


def _post_legacy_connect_endpoint(
    *,
    daemon: GuardDaemonServer,
    path: str,
    token: object,
) -> tuple[int, dict[str, object]]:
    request = urllib.request.Request(
        f"http://127.0.0.1:{daemon.port}{path}",
        data=json.dumps(
            {
                "allowed_origin": "https://hol.org",
                "pairing_secret": "pairing-secret",
                "request_id": "connect-123",
                "sync_url": "https://hol.org/api/guard/receipts/sync",
                "token": "legacy-sync-secret",
            }
        ).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "X-Guard-Token": str(token),
        },
        method="POST",
    )
    try:
        urllib.request.urlopen(request, timeout=5)
    except urllib.error.HTTPError as error:
        payload = json.loads(error.read().decode("utf-8"))
        assert isinstance(payload, dict)
        return error.code, payload
    raise AssertionError(f"{path} must reject legacy pairing")


def test_daemon_rejects_legacy_connect_pairing_endpoints(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()

    try:
        _initialize_daemon(daemon)
        request_status, request_payload = _post_legacy_connect_endpoint(
            daemon=daemon,
            path="/v1/connect/requests",
            token=daemon._server.auth_token,
        )
        complete_status, complete_payload = _post_legacy_connect_endpoint(
            daemon=daemon,
            path="/v1/connect/complete",
            token=daemon._server.auth_token,
        )
        result_status, result_payload = _post_legacy_connect_endpoint(
            daemon=daemon,
            path="/v1/connect/result",
            token=daemon._server.auth_token,
        )
    finally:
        daemon.stop()

    assert request_status == 410
    assert request_payload["error"] == "legacy_pairing_disabled"
    assert complete_status == 410
    assert complete_payload["error"] == "legacy_pairing_disabled"
    assert result_status == 410
    assert result_payload["error"] == "legacy_pairing_disabled"
    assert "legacy-sync-secret" not in json.dumps([request_payload, complete_payload, result_payload])


def test_connect_repair_copy_points_to_device_code(tmp_path: Path) -> None:
    payload = build_connect_status_payload(
        store=GuardStore(tmp_path / "guard-home"),
        sync_url="https://hol.org/api/guard/receipts/sync",
        connect_url="https://hol.org/guard/connect",
        action="repair",
    )

    rendered = json.dumps(payload)
    assert payload["repair_action"] == "rerun_connect"
    assert payload["repair_message"] == "Run hol-guard connect to start OAuth Device Code approval."
    assert "pairing" not in rendered.lower()
    assert "guardPairSecret" not in rendered


def test_browser_connect_caches_paid_package_firewall_entitlement(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")

    class _BrowserSession:
        authorize_url = "https://hol.org/guard/connect?step=authorize"
        redirect_uri = "http://127.0.0.1:55221/oauth/callback"
        pkce_verifier = "pkce-verifier"
        dpop_key_material = GuardDpopKeyMaterial(
            algorithm="ES256",
            private_key_pem="private-key",
            public_jwk={"kty": "EC", "crv": "P-256", "x": "x-value", "y": "y-value"},
            public_jwk_thumbprint="thumbprint-1",
        )

        def wait_for_callback(self, _timeout_seconds: float) -> GuardOAuthLoopbackCallback:
            return GuardOAuthLoopbackCallback(code="auth-code-1", state="state-1")

        def close(self) -> None:
            return None

    payload = run_guard_browser_connect_command(
        store=store,
        connect_url="https://hol.org/guard/connect",
        start_browser_session=lambda **_kwargs: _BrowserSession(),
        open_browser=lambda _url: True,
        exchange_authorization_code=lambda **_kwargs: GuardOAuthTokenExchangeResult(
            access_token="access-token-1",
            refresh_token="refresh-token-1",
            expires_in=300,
            scope="guard:runtime.sync guard:receipt.write guard:runtime.session.write guard:insights.share guard:offline_access",
            token_type="Bearer",
            grant_id="grant-1",
            machine_id="machine-1",
            supply_chain_entitlement={
                "supply_chain_entitlement_expires_at": "2026-07-05T01:39:51+00:00",
                "supply_chain_firewall": True,
                "supply_chain_plan_id": "pro",
            },
            workspace_id="workspace-1",
        ),
        now="2026-06-05T01:39:51+00:00",
    )

    entitlement = resolve_package_firewall_entitlement(store)
    assert payload["status"] == "connected"
    assert entitlement == {
        "allowed": True,
        "reason": "paid_oauth_entitlement_active",
        "tier": "pro",
        "upgrade_cta": None,
    }


def test_missing_cloud_connection_prefers_connect_over_false_paywall(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")

    entitlement = resolve_package_firewall_entitlement(store)

    assert entitlement == {
        "allowed": False,
        "reason": "guard_cloud_connect_required",
        "tier": "unknown",
        "upgrade_cta": "Connect HOL Guard Cloud to check package firewall access and run package firewall actions.",
    }


def test_paid_metadata_without_usable_local_auth_still_prefers_connect_over_upgrade(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    store.set_sync_payload(
        "oauth_local_credentials",
        {
            "workspace_id": "workspace-1",
            "supply_chain_firewall": True,
            "supply_chain_plan_id": "team",
        },
        "2026-06-05T01:39:51+00:00",
    )

    entitlement = resolve_package_firewall_entitlement(store)

    assert entitlement == {
        "allowed": False,
        "reason": "guard_cloud_connect_required",
        "tier": "team",
        "upgrade_cta": "Connect HOL Guard Cloud to check package firewall access and run package firewall actions.",
    }


def test_sync_local_guard_cloud_proof_repairs_degraded_oauth_from_encrypted_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="refresh-token-old",
        dpop_private_key_pem="private-key-old",
        dpop_public_jwk={"kty": "EC", "crv": "P-256", "x": "x-value-old", "y": "y-value-old"},
        dpop_public_jwk_thumbprint="thumbprint-old",
        grant_id="grant-old",
        machine_id="machine-old",
        supply_chain_entitlement_expires_at="2026-07-05T01:39:51+00:00",
        supply_chain_firewall=True,
        supply_chain_plan_id="team",
        workspace_id="workspace-1",
        now="2026-06-05T01:39:51+00:00",
    )
    store.record_guard_connect_pairing_completed(
        sync_url="https://hol.org/api/guard/receipts/sync",
        allowed_origin="https://hol.org",
        now="2026-06-05T01:39:51+00:00",
        request_id="connect-1",
    )
    oauth_payload = store.get_sync_payload("oauth_local_credentials")
    assert isinstance(oauth_payload, dict)
    oauth_payload["credentials_sha256"] = "pbkdf2-sha256$" + ("0" * 64)
    store.set_sync_payload("oauth_local_credentials", oauth_payload, "2026-06-05T01:40:00+00:00")

    monkeypatch.setattr(
        guard_runner_module,
        "_refresh_guard_oauth_access_token",
        lambda **_kwargs: {
            "access_token": "access-token-1",
            "refresh_token": "refresh-token-new",
            "package_firewall_entitlement": {
                "supply_chain_entitlement_expires_at": "2026-07-05T01:39:51+00:00",
                "supply_chain_firewall": True,
                "supply_chain_plan_id": "team",
            },
        },
    )
    monkeypatch.setattr(
        guard_runner_module,
        "sync_runtime_session",
        lambda *_args, **_kwargs: {
            "runtime_session_id": "runtime-session-1",
            "runtime_session_synced_at": "2026-06-05T01:40:15+00:00",
            "runtime_sessions_visible": 1,
            "local_guard_online_at": "2026-06-05T01:40:15+00:00",
            "runtime_harness": "hol-guard",
            "runtime_surface": "local",
            "runtime_workspace": "workspace-1",
            "runtime_device_id": "machine-old",
        },
    )
    monkeypatch.setattr(
        guard_runner_module,
        "sync_receipts",
        lambda *_args, **_kwargs: {
            "synced_at": "2026-06-05T01:40:20+00:00",
            "receipts_stored": 4,
            "inventory_tracked": 2,
            "local_guard_online_at": "2026-06-05T01:40:20+00:00",
        },
    )

    summary = guard_runner_module.sync_local_guard_cloud_proof(store)

    assert summary["synced_at"] == "2026-06-05T01:40:20+00:00"
    assert store.get_oauth_local_credential_health()["state"] == "healthy"
    repaired_credentials = store.get_oauth_local_credentials()
    assert repaired_credentials is not None
    assert repaired_credentials["refresh_token"] == "refresh-token-new"
    entitlement = resolve_package_firewall_entitlement(store)
    assert entitlement == {
        "allowed": True,
        "reason": "paid_oauth_entitlement_active",
        "tier": "team",
        "upgrade_cta": None,
    }
    latest_state = store.get_latest_guard_connect_state(now="2026-06-05T01:40:25+00:00")
    assert latest_state is not None
    assert latest_state["milestone"] == "first_sync_succeeded"


def test_retry_required_connect_state_prefers_reconnect_over_false_paywall(tmp_path: Path) -> None:
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
        now="2026-06-05T01:39:51+00:00",
    )
    store.record_guard_connect_pairing_completed(
        sync_url="https://hol.org/api/guard/receipts/sync",
        allowed_origin="https://hol.org",
        now="2026-06-05T01:39:51+00:00",
        request_id="connect-1",
    )
    store.record_latest_guard_connect_sync_result(
        status="retry_required",
        milestone="first_sync_failed",
        now="2026-06-05T01:40:10+00:00",
        reason="Guard authorization expired. Run `hol-guard connect` again.",
    )

    entitlement = resolve_package_firewall_entitlement(store)

    assert entitlement == {
        "allowed": False,
        "reason": "guard_cloud_reconnect_required",
        "tier": "unknown",
        "upgrade_cta": "Reconnect HOL Guard Cloud to refresh package firewall access.",
    }


def test_free_oauth_entitlement_does_not_turn_into_reconnect_prompt_when_expired(tmp_path: Path) -> None:
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
        supply_chain_entitlement_expires_at="2026-06-01T01:39:51+00:00",
        supply_chain_firewall=False,
        supply_chain_plan_id="free",
        workspace_id="workspace-1",
        now="2026-05-05T01:39:51+00:00",
    )

    entitlement = resolve_package_firewall_entitlement(store)

    assert entitlement == {
        "allowed": False,
        "reason": "paid_guard_cloud_required",
        "tier": "free",
        "upgrade_cta": "Upgrade to HOL Guard Cloud to run package firewall actions.",
    }
