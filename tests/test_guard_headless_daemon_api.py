"""Headless daemon API contract for Guard Cloud app actions."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import local_supply_chain as local_supply_chain_module
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.approval_gate import ApprovalGateError
from codex_plugin_scanner.guard.approval_gate import update_settings as update_approval_gate_settings
from codex_plugin_scanner.guard.cli.connect_flow import GuardOAuthTokenExchangeResult
from codex_plugin_scanner.guard.daemon import GuardDaemonServer
from codex_plugin_scanner.guard.daemon import server as daemon_server
from codex_plugin_scanner.guard.daemon.manager import load_guard_daemon_auth_token
from codex_plugin_scanner.guard.daemon.server import _headless_action_error_payload
from codex_plugin_scanner.guard.local_dashboard_session import LOCAL_DASHBOARD_SESSION_AUDIENCE
from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.runtime import runner as guard_runner_module
from codex_plugin_scanner.guard.shims import install_package_shims
from codex_plugin_scanner.guard.store import GuardStore


def _read_json_response_details(
    request: urllib.request.Request,
) -> tuple[int, dict[str, object], dict[str, str]]:
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            return (
                response.status,
                json.loads(response.read().decode("utf-8")),
                dict(response.headers.items()),
            )
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read().decode("utf-8")), dict(error.headers.items())


def _read_json_response(request: urllib.request.Request) -> tuple[int, dict[str, object]]:
    status, payload, _headers = _read_json_response_details(request)
    return status, payload


def _read_json_response_with_headers(
    request: urllib.request.Request,
) -> tuple[int, dict[str, object], dict[str, str]]:
    return _read_json_response_details(request)


def _request(
    port: int,
    path: str,
    *,
    method: str = "POST",
    payload: dict[str, object] | None = None,
    token: str | None = None,
    authorization_token: str | None = None,
    dashboard_session_token: str | None = None,
    origin: str | None = "https://hol.org",
    referer: str | None = None,
    extra_headers: dict[str, str] | None = None,
) -> urllib.request.Request:
    data = json.dumps(payload or {}).encode("utf-8") if method != "GET" else None
    headers = {
        "Content-Type": "application/json",
    }
    if origin is not None:
        headers["Origin"] = origin
    if referer is not None:
        headers["Referer"] = referer
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
        headers["X-Guard-Dashboard-Session"] = token
    if authorization_token is not None:
        headers["Authorization"] = f"Bearer {authorization_token}"
    if dashboard_session_token is not None:
        headers["X-Guard-Dashboard-Session"] = dashboard_session_token
    if extra_headers is not None:
        headers.update(extra_headers)
    return urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=data,
        headers=headers,
        method=method,
    )


def _dashboard_token(auth_token: str) -> str:
    payload_json = json.dumps(
        {
            "aud": LOCAL_DASHBOARD_SESSION_AUDIENCE,
            "version": "guard-local-daemon-session.v1",
            "expires_at": datetime(2099, 1, 1, tzinfo=timezone.utc).isoformat(),
            "surface": "approval-center",
        },
        separators=(",", ":"),
    )
    payload = base64.urlsafe_b64encode(payload_json.encode("utf-8")).decode("ascii").rstrip("=")
    signature = hmac.new(auth_token.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).digest()
    encoded_signature = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    return f"gld1.{payload}.{encoded_signature}"


def _dashboard_token_with_claims(auth_token: str, claims: dict[str, object]) -> str:
    payload_json = json.dumps(
        {
            "aud": LOCAL_DASHBOARD_SESSION_AUDIENCE,
            "version": "guard-local-daemon-session.v1",
            "expires_at": datetime(2099, 1, 1, tzinfo=timezone.utc).isoformat(),
            **claims,
        },
        separators=(",", ":"),
    )
    payload = base64.urlsafe_b64encode(payload_json.encode("utf-8")).decode("ascii").rstrip("=")
    signature = hmac.new(auth_token.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).digest()
    encoded_signature = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    return f"gld1.{payload}.{encoded_signature}"


def _remote_once_request(
    request_id: str,
    *,
    policy_action: str = "require-reapproval",
    recommended_scope: str = "artifact",
) -> GuardApprovalRequest:
    return GuardApprovalRequest(
        request_id=request_id,
        harness="codex",
        artifact_id=f"codex:project:{request_id}",
        artifact_name="Remote once request",
        artifact_type="tool_action_request",
        artifact_hash=f"hash-{request_id}",
        publisher=None,
        policy_action=policy_action,
        recommended_scope=recommended_scope,
        changed_fields=("shell_command",),
        source_scope="project",
        config_path="/workspace/repo/.guard/config.toml",
        workspace="/workspace/repo",
        launch_target="cat /workspace/repo/.npmrc",
        review_command=f"hol-guard approvals approve {request_id}",
        approval_url=f"http://127.0.0.1:5474/approvals/{request_id}",
        action_envelope_json={
            "action_type": "shell_command",
            "command": "cat /workspace/repo/.npmrc",
            "tool_name": "Bash",
        },
    )


def _dashboard_token_for(store: GuardStore) -> str:
    auth_token = load_guard_daemon_auth_token(store.guard_home)
    assert auth_token is not None
    return _dashboard_token(auth_token)


def _install_local_package_shim(store: GuardStore, home_dir: Path, manager: str) -> None:
    install_package_shims(
        HarnessContext(
            home_dir=home_dir,
            workspace_dir=None,
            guard_home=store.guard_home,
        ),
        managers=(manager,),
    )


def test_headless_capabilities_endpoint_reports_safe_action_contract(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = _dashboard_token_for(store)
        status, payload = _read_json_response(
            _request(daemon.port, "/v1/capabilities", method="GET", token=token),
        )
    finally:
        daemon.stop()

    assert status == 200
    assert payload["auth_state"] == "dashboard_session"
    assert payload["headless_api"]["operations"] == [
        "install",
        "repair",
        "remove",
        "status",
        "scan",
        "policy_sync",
    ]
    assert payload["package_firewall_api"]["operations"] == [
        "status",
        "connect",
        "install",
        "repair",
        "test",
        "audit",
        "sync",
        "remove",
    ]
    assert payload["package_firewall_api"]["routes"]["connect"] == "/v1/supply-chain/package-shims/connect"
    assert payload["package_firewall_api"]["routes"]["status"] == "/v1/supply-chain/package-shims"
    assert "codex" in payload["supported_harnesses"]
    assert payload["safe_failure_reasons"]["unsupported"] == "Harness is not supported by this daemon."
    codex_item = next(item for item in payload["items"] if item["harness"] == "codex")
    assert codex_item["display_name"] == "Codex"
    assert codex_item["headless_actions"] == ["install", "repair", "remove", "status", "scan"]
    assert codex_item["status"] in {"inactive", "observed", "protected"}


def test_supply_chain_package_firewall_status_reports_connect_gate_when_cloud_is_not_connected(
    tmp_path: Path,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = _dashboard_token_for(store)
        status, payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/supply-chain/package-shims",
                method="GET",
                token=token,
            ),
        )
    finally:
        daemon.stop()

    assert status == 200
    assert payload["operation"] == "status"
    assert payload["entitlement"] == {
        "allowed": False,
        "reason": "guard_cloud_connect_required",
        "tier": "unknown",
        "upgrade_cta": "Connect HOL Guard Cloud to check package firewall access and run package firewall actions.",
    }
    assert "npm" in payload["supported_managers"]
    assert payload["connect_flow"]["state"] == "idle"
    assert payload["actions"] == {
        "install": "connect_required",
        "repair": "disabled",
        "test": "connect_required",
        "audit": "connect_required",
        "sync": "connect_required",
        "remove": "disabled",
    }


def test_supply_chain_package_firewall_install_requires_cloud_connect_first(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = _dashboard_token_for(store)
        status, payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/supply-chain/package-shims/install",
                token=token,
                payload={"managers": ["npm"]},
            ),
        )
    finally:
        daemon.stop()

    assert status == 403
    assert payload["error"] == "guard_cloud_connect_required"
    assert payload["operation"] == "install"
    assert payload["entitlement"]["tier"] == "unknown"
    assert payload["available_actions"] == ["status", "connect", "education", "cli_fallback"]


def test_supply_chain_package_firewall_connect_repairs_local_auth_and_unlocks_paid_access(
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
    oauth_payload = store.get_sync_payload("oauth_local_credentials")
    assert isinstance(oauth_payload, dict)
    oauth_payload["credentials_sha256"] = "pbkdf2-sha256$" + ("0" * 64)
    store.set_sync_payload("oauth_local_credentials", oauth_payload, "2026-06-05T01:40:00+00:00")

    class _FakeSession:
        authorize_url = "https://hol.org/mock-authorize"
        redirect_uri = "http://127.0.0.1:53111/oauth/callback"
        pkce_verifier = "pkce-verifier"
        dpop_key_material = type(
            "KeyMaterial",
            (),
            {
                "private_key_pem": "private-key-new",
                "public_jwk": {"kty": "EC", "crv": "P-256", "x": "x-value-new", "y": "y-value-new"},
                "public_jwk_thumbprint": "thumbprint-new",
            },
        )()

        def wait_for_callback(self, _timeout_seconds: float):
            return type("Callback", (), {"code": "auth-code-1"})()

        def close(self) -> None:
            return None

    monkeypatch.setattr(daemon_server, "start_guard_browser_session", lambda **_kwargs: _FakeSession())
    monkeypatch.setattr(daemon_server.webbrowser, "open", lambda _url: False)
    monkeypatch.setattr(
        daemon_server,
        "exchange_guard_authorization_code",
        lambda **_kwargs: GuardOAuthTokenExchangeResult(
            access_token="access-token-1",
            refresh_token="refresh-token-new",
            expires_in=300,
            scope="guard:runtime.sync guard:offline_access",
            token_type="Bearer",
            grant_id="grant-new",
            machine_id="machine-new",
            supply_chain_entitlement={
                "supply_chain_entitlement_expires_at": "2026-07-05T01:39:51+00:00",
                "supply_chain_firewall": True,
                "supply_chain_plan_id": "team",
            },
            workspace_id="workspace-1",
        ),
    )

    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = _dashboard_token_for(store)
        status, payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/supply-chain/package-shims/connect",
                token=token,
                payload={},
            ),
        )
        assert status == 202
        assert payload["state"] == "running"
        assert payload["authorize_url"] == "https://hol.org/mock-authorize"
        for _ in range(20):
            status, refreshed = _read_json_response(
                _request(
                    daemon.port,
                    "/v1/supply-chain/package-shims",
                    method="GET",
                    token=token,
                ),
            )
            if refreshed["entitlement"]["allowed"] is True:
                assert status == 200
                assert refreshed["entitlement"]["reason"] == "paid_oauth_entitlement_active"
                assert refreshed["connect_flow"] is None
                break
            time.sleep(0.1)
        else:
            raise AssertionError("package firewall status never unlocked after local connect repair")
    finally:
        daemon.stop()

    assert store.get_oauth_local_credential_health()["state"] == "healthy"


def test_guard_cloud_connect_starts_local_browser_flow_for_insights_share(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = _dashboard_token_for(store)
        status, payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/cloud/connect",
                method="GET",
                token=token,
            ),
        )
        assert status == 200
        assert payload["connect_required"] is True
        assert payload["connect_flow"]["state"] == "idle"
        assert payload["connect_flow"]["action_label"] == "Connect Guard Cloud"

        class _FakeSession:
            authorize_url = "https://hol.org/mock-authorize"
            redirect_uri = "http://127.0.0.1:53111/oauth/callback"
            pkce_verifier = "pkce-verifier"
            dpop_key_material = type(
                "KeyMaterial",
                (),
                {
                    "private_key_pem": "private-key-new",
                    "public_jwk": {"kty": "EC", "crv": "P-256", "x": "x-value-new", "y": "y-value-new"},
                    "public_jwk_thumbprint": "thumbprint-new",
                },
            )()

            def wait_for_callback(self, _timeout_seconds: float):
                return type("Callback", (), {"code": "auth-code-1"})()

            def close(self) -> None:
                return None

        monkeypatch.setattr(daemon_server, "start_guard_browser_session", lambda **_kwargs: _FakeSession())
        monkeypatch.setattr(daemon_server.webbrowser, "open", lambda _url: True)
        monkeypatch.setattr(
            daemon_server,
            "exchange_guard_authorization_code",
            lambda **_kwargs: GuardOAuthTokenExchangeResult(
                access_token="access-token-1",
                refresh_token="refresh-token-new",
                expires_in=300,
                scope="guard:runtime.sync guard:offline_access",
                token_type="Bearer",
                grant_id="grant-new",
                machine_id="machine-new",
                supply_chain_entitlement={},
                workspace_id="workspace-1",
            ),
        )

        status, payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/cloud/connect",
                token=token,
                payload={},
            ),
        )
        assert status == 202
        assert payload["connect_required"] is True
        assert payload["connect_flow"]["state"] == "running"
        assert payload["connect_flow"]["authorize_url"] == "https://hol.org/mock-authorize"

        for _ in range(20):
            status, refreshed = _read_json_response(
                _request(
                    daemon.port,
                    "/v1/cloud/connect",
                    method="GET",
                    token=token,
                ),
            )
            if refreshed["connect_required"] is False:
                assert status == 200
                assert refreshed["connect_flow"] is None
                break
            time.sleep(0.1)
        else:
            raise AssertionError("cloud connect never completed for insights share")
    finally:
        daemon.stop()

    assert store.get_cloud_sync_profile() is not None


def test_supply_chain_package_firewall_status_reports_reconnect_gate_for_expired_cloud_auth(
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
    monkeypatch.setattr(
        local_supply_chain_module,
        "sync_local_guard_cloud_proof",
        lambda _store: (_ for _ in ()).throw(RuntimeError("cloud auth still expired")),
    )
    monkeypatch.setattr(
        local_supply_chain_module,
        "sync_supply_chain_bundle",
        lambda _store: (_ for _ in ()).throw(RuntimeError("bundle refresh blocked")),
    )
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = _dashboard_token_for(store)
        status, payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/supply-chain/package-shims",
                method="GET",
                token=token,
            ),
        )
    finally:
        daemon.stop()

    assert status == 200
    assert payload["entitlement"] == {
        "allowed": False,
        "reason": "guard_cloud_reconnect_required",
        "tier": "unknown",
        "upgrade_cta": "Reconnect HOL Guard Cloud to refresh package firewall access.",
    }
    assert payload["actions"]["install"] == "reconnect_required"
    assert payload["actions"]["repair"] == "disabled"
    assert payload["actions"]["remove"] == "disabled"


def test_supply_chain_package_firewall_install_requires_reconnect_when_cloud_auth_expired(
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
    monkeypatch.setattr(
        local_supply_chain_module,
        "sync_local_guard_cloud_proof",
        lambda _store: (_ for _ in ()).throw(RuntimeError("cloud auth still expired")),
    )
    monkeypatch.setattr(
        local_supply_chain_module,
        "sync_supply_chain_bundle",
        lambda _store: (_ for _ in ()).throw(RuntimeError("bundle refresh blocked")),
    )
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = _dashboard_token_for(store)
        status, payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/supply-chain/package-shims/install",
                token=token,
                payload={"managers": ["npm"]},
            ),
        )
    finally:
        daemon.stop()

    assert status == 403
    assert payload["error"] == "guard_cloud_reconnect_required"
    assert payload["entitlement"]["tier"] == "unknown"


def test_supply_chain_package_firewall_status_self_heals_connected_cloud_auth_without_cached_entitlement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    seed_connected_oauth_without_entitlement,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    seed_connected_oauth_without_entitlement(store)
    calls: list[str] = []

    def fake_sync_local_guard_cloud_proof(current_store: GuardStore) -> dict[str, object]:
        assert current_store is store
        calls.append("proof")
        current_store.record_latest_guard_connect_sync_success(
            sync_payload={"synced_at": "2026-06-05T01:41:00+00:00", "receipts_stored": 1},
            now="2026-06-05T01:41:00+00:00",
        )
        return {"synced_at": "2026-06-05T01:41:00+00:00", "receipts_stored": 1}

    def fake_sync_supply_chain_bundle(current_store: GuardStore) -> dict[str, object]:
        assert current_store is store
        calls.append("bundle")
        current_store.set_sync_payload(
            "supply_chain_bundle_entitlement",
            {
                "bundle_version": "bundle-version-test",
                "key_id": "bundle-key-test",
                "policy_hash": "policy-hash-test",
                "tier": "pro",
                "workspace_id": "workspace-1",
            },
            "2026-06-05T01:41:05+00:00",
        )
        return {"bundle_version": "bundle-version-test", "tier": "pro"}

    monkeypatch.setattr(local_supply_chain_module, "sync_local_guard_cloud_proof", fake_sync_local_guard_cloud_proof)
    monkeypatch.setattr(local_supply_chain_module, "sync_supply_chain_bundle", fake_sync_supply_chain_bundle)
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = _dashboard_token_for(store)
        status, payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/supply-chain/package-shims",
                method="GET",
                token=token,
            ),
        )
    finally:
        daemon.stop()

    assert status == 200
    assert calls == ["proof", "bundle"]
    assert payload["entitlement"] == {
        "allowed": True,
        "reason": "paid_entitlement_active",
        "tier": "pro",
        "upgrade_cta": None,
    }
    assert payload["actions"]["install"] == "available"


def test_supply_chain_package_firewall_install_self_heals_retry_required_cloud_auth(
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

    def fake_sync_local_guard_cloud_proof(current_store: GuardStore) -> dict[str, object]:
        assert current_store is store
        current_store.record_latest_guard_connect_sync_success(
            sync_payload={"synced_at": "2026-06-05T01:41:00+00:00", "receipts_stored": 1},
            now="2026-06-05T01:41:00+00:00",
        )
        return {"synced_at": "2026-06-05T01:41:00+00:00", "receipts_stored": 1}

    def fake_sync_supply_chain_bundle(current_store: GuardStore) -> dict[str, object]:
        assert current_store is store
        current_store.set_sync_payload(
            "supply_chain_bundle_entitlement",
            {
                "bundle_version": "bundle-version-test",
                "key_id": "bundle-key-test",
                "policy_hash": "policy-hash-test",
                "tier": "pro",
                "workspace_id": "workspace-1",
            },
            "2026-06-05T01:41:05+00:00",
        )
        return {"bundle_version": "bundle-version-test", "tier": "pro"}

    monkeypatch.setattr(local_supply_chain_module, "sync_local_guard_cloud_proof", fake_sync_local_guard_cloud_proof)
    monkeypatch.setattr(local_supply_chain_module, "sync_supply_chain_bundle", fake_sync_supply_chain_bundle)

    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = _dashboard_token_for(store)
        status, payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/supply-chain/package-shims/install",
                token=token,
                payload={"managers": ["npm"]},
            ),
        )
    finally:
        daemon.stop()

    assert status == 200
    assert payload["status"] == "completed"
    assert payload["entitlement"] == {
        "allowed": True,
        "reason": "paid_entitlement_active",
        "tier": "pro",
        "upgrade_cta": None,
    }
    assert payload["result"]["installed_managers"] == ["npm"]


def test_supply_chain_package_firewall_status_accepts_paid_oauth_entitlement(tmp_path: Path) -> None:
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
        supply_chain_entitlement_expires_at="2026-07-05T01:39:51+00:00",
        supply_chain_firewall=True,
        supply_chain_plan_id="pro",
        workspace_id="workspace-1",
        now="2026-06-05T01:39:51+00:00",
    )
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = _dashboard_token_for(store)
        status, payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/supply-chain/package-shims",
                method="GET",
                token=token,
            ),
        )
    finally:
        daemon.stop()

    assert status == 200
    assert payload["entitlement"] == {
        "allowed": True,
        "reason": "paid_oauth_entitlement_active",
        "tier": "pro",
        "upgrade_cta": None,
    }
    assert payload["actions"] == {
        "install": "available",
        "repair": "disabled",
        "test": "available",
        "audit": "available",
        "sync": "available",
        "remove": "disabled",
    }


def test_supply_chain_package_firewall_open_shell_endpoint_returns_activation_launch_status(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    monkeypatch.setattr(
        daemon_server,
        "_open_package_firewall_activation_shell",
        lambda: (200, {"status": "opened", "message": "Opened a new Terminal window with a fresh shell session."}),
    )
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = _dashboard_token_for(store)
        status, payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/supply-chain/package-shims/open-shell",
                token=token,
                payload={},
            ),
        )
    finally:
        daemon.stop()

    assert status == 200
    assert payload["status"] == "opened"
    assert "fresh shell session" in payload["message"]


def test_supply_chain_package_firewall_paid_install_and_test_roundtrip(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "home"
    home_dir.mkdir()
    monkeypatch.setenv("HOME", str(home_dir))
    monkeypatch.setenv("SHELL", "/bin/zsh")
    store = GuardStore(tmp_path / "guard-home")
    store.set_sync_credentials(
        "https://hol.org/api/guard/receipts/sync",
        "cloud-token",
        "2026-05-27T16:00:00.000Z",
        workspace_id="workspace-1",
    )
    store.set_sync_payload(
        "supply_chain_bundle_entitlement",
        {"tier": "premium", "workspace_id": "workspace-1"},
        "2026-05-27T16:00:00.000Z",
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
                payload={"managers": ["npm", "pip"]},
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
        runtime_status, runtime_payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/runtime",
                method="GET",
                token=token,
            ),
        )
        test_status, test_payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/supply-chain/package-shims/test",
                token=token,
                payload={"managers": ["npm"]},
            ),
        )
    finally:
        daemon.stop()

    assert install_status == 200
    assert install_payload["operation"] == "install"
    assert install_payload["status"] == "completed"
    assert install_payload["result"]["installed_managers"] == ["npm", "pip"]
    assert install_payload["result"]["profile"]["changed"] is True
    assert install_payload["result"]["activation_state"] == "restart_required"
    assert install_payload["receipt"]["operation"] == "install"
    assert status_status == 200
    assert status_payload["package_shims"]["path_status"] == "restart_required"
    assert status_payload["package_shims"]["shell_profile_configured"] is True
    assert status_payload["package_shims"]["restart_shell_required"] is True
    assert runtime_status == 200
    assert runtime_payload["supply_chain"]["package_manager_protection"]["path_status"] == "restart_required"
    assert runtime_payload["supply_chain"]["package_manager_protection"]["shell_profile_configured"] is True
    assert str(store.guard_home / "package-shims" / "bin") in (home_dir / ".zshrc").read_text(encoding="utf-8")
    assert test_status == 200
    assert test_payload["operation"] == "test"
    assert test_payload["status"] == "completed"
    assert test_payload["result"]["tested_managers"] == ["npm"]
    assert test_payload["result"]["blocked_execution"] is False
    assert test_payload["result"]["path_repair_required"] == ["npm"]
    assert test_payload["result"]["intercept_proved"] is False
    assert test_payload["result"]["manager_results"] == [
        {
            "evaluator_invoked": False,
            "intercept_ran": False,
            "manager": "npm",
            "skipped_reason": "path_inactive",
        },
    ]


def test_supply_chain_audit_scans_workspace_manifests(tmp_path: Path) -> None:
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir()
    (workspace_dir / "package.json").write_text(
        json.dumps({"name": "demo", "version": "1.0.0"}),
        encoding="utf-8",
    )
    store = GuardStore(tmp_path / "guard-home")
    store.set_sync_credentials(
        "https://hol.org/api/guard/receipts/sync",
        "cloud-token",
        "2026-05-27T16:00:00.000Z",
        workspace_id="workspace-1",
    )
    store.set_sync_payload(
        "supply_chain_bundle_entitlement",
        {"tier": "premium", "workspace_id": "workspace-1"},
        "2026-05-27T16:00:00.000Z",
    )
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = _dashboard_token_for(store)
        audit_status, audit_payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/supply-chain/audit",
                token=token,
                payload={"workspace_dir": str(workspace_dir)},
            ),
        )
    finally:
        daemon.stop()

    assert audit_status == 200
    assert audit_payload["operation"] == "audit"
    assert audit_payload["status"] == "completed"
    assert audit_payload["result"]["manifest_paths"] == ["package.json"]
    assert "supply_chain" in audit_payload["result"]


def test_supply_chain_package_firewall_status_exposes_local_recovery_when_connect_is_missing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "home"
    home_dir.mkdir()
    monkeypatch.setenv("HOME", str(home_dir))
    monkeypatch.setenv("SHELL", "/bin/zsh")
    store = GuardStore(tmp_path / "guard-home")
    _install_local_package_shim(store, home_dir, "npm")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = _dashboard_token_for(store)
        status, payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/supply-chain/package-shims",
                method="GET",
                token=token,
            ),
        )
    finally:
        daemon.stop()

    assert status == 200
    assert payload["entitlement"]["reason"] == "guard_cloud_connect_required"
    assert payload["actions"]["install"] == "connect_required"
    assert payload["actions"]["repair"] == "available"
    assert payload["actions"]["remove"] == "available"


def test_supply_chain_package_firewall_repair_runs_without_guard_cloud_connect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "home"
    home_dir.mkdir()
    monkeypatch.setenv("HOME", str(home_dir))
    monkeypatch.setenv("SHELL", "/bin/zsh")
    store = GuardStore(tmp_path / "guard-home")
    _install_local_package_shim(store, home_dir, "npm")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = _dashboard_token_for(store)
        status, payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/supply-chain/package-shims/repair",
                token=token,
                payload={"managers": ["npm"]},
            ),
        )
    finally:
        daemon.stop()

    assert status == 200
    assert payload["entitlement"]["reason"] == "guard_cloud_connect_required"
    assert payload["result"]["activation_state"] == "restart_required"
    assert payload["result"]["profile"]["changed"] is True


def test_supply_chain_package_firewall_remove_runs_without_guard_cloud_connect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "home"
    home_dir.mkdir()
    monkeypatch.setenv("HOME", str(home_dir))
    monkeypatch.setenv("SHELL", "/bin/zsh")
    store = GuardStore(tmp_path / "guard-home")
    _install_local_package_shim(store, home_dir, "npm")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = _dashboard_token_for(store)
        status, payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/supply-chain/package-shims/remove",
                token=token,
                payload={"managers": ["npm"]},
            ),
        )
    finally:
        daemon.stop()

    assert status == 200
    assert payload["entitlement"]["reason"] == "guard_cloud_connect_required"
    assert payload["result"]["removed_managers"] == ["npm"]


def test_audit_package_shim_path_remediation_requires_approval_gate_proof(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    store.set_sync_payload(
        "supply_chain_bundle_entitlement",
        {"tier": "premium", "workspace_id": "workspace-1"},
        "2026-05-27T16:00:00.000Z",
    )
    update_approval_gate_settings(
        store.guard_home,
        {
            "enabled": True,
            "new_password": "local-password",
            "confirm_password": "local-password",
        },
    )
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = _dashboard_token_for(store)
        status, payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/audit/remediations/package_shim_path",
                token=token,
                payload={"manager": "pnpm"},
            ),
        )
    finally:
        daemon.stop()

    assert status == 403
    assert payload["error"] == "approval_gate_required"


def test_audit_package_shim_path_remediation_updates_profile_with_gate_proof(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home_dir = tmp_path / "home"
    home_dir.mkdir()
    monkeypatch.setenv("HOME", str(home_dir))
    monkeypatch.setenv("SHELL", "/bin/zsh")
    store = GuardStore(tmp_path / "guard-home")
    store.set_sync_payload(
        "supply_chain_bundle_entitlement",
        {"tier": "premium", "workspace_id": "workspace-1"},
        "2026-05-27T16:00:00.000Z",
    )
    update_approval_gate_settings(
        store.guard_home,
        {
            "enabled": True,
            "new_password": "local-password",
            "confirm_password": "local-password",
        },
    )
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = _dashboard_token_for(store)
        status, payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/audit/remediations/package_shim_path",
                token=token,
                payload={"manager": "pnpm", "approval_password": "local-password"},
            ),
        )
    finally:
        daemon.stop()

    profile_path = home_dir / ".zshrc"
    shim_path = store.guard_home / "package-shims" / "bin" / "pnpm"
    assert status == 200
    assert payload["operation"] == "package_shim_path"
    assert payload["receipt"]["operation"] == "package_shim_path"
    assert shim_path.exists()
    assert str(store.guard_home / "package-shims" / "bin") in profile_path.read_text(encoding="utf-8")
    result = payload["result"]
    assert isinstance(result, dict)
    assert result["manager"] == "pnpm"
    assert result["profile"]["changed"] is True


def test_supply_chain_package_firewall_rejects_duplicate_managers(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    store.set_sync_payload(
        "supply_chain_bundle_entitlement",
        {"tier": "premium", "workspace_id": "workspace-1"},
        "2026-05-27T16:00:00.000Z",
    )
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = _dashboard_token_for(store)
        status, payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/supply-chain/package-shims/install",
                token=token,
                payload={"managers": ["npm", "npm"]},
            ),
        )
    finally:
        daemon.stop()

    assert status == 400
    assert payload["error"] == "duplicate_manager"


def test_supply_chain_dashboard_session_claims_scope_action_and_managers(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    store.set_sync_credentials(
        "https://hol.org/api/guard/receipts/sync",
        "cloud-token",
        "2026-05-27T16:00:00.000Z",
        workspace_id="workspace-1",
    )
    store.set_sync_payload(
        "supply_chain_bundle_entitlement",
        {"tier": "premium", "workspace_id": "workspace-1"},
        "2026-05-27T16:00:00.000Z",
    )
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        auth_token = load_guard_daemon_auth_token(store.guard_home)
        assert auth_token is not None
        token = _dashboard_token_with_claims(
            auth_token,
            {
                "action_path": "package_shims_install",
                "allowed_action_paths": ["package_shims_install"],
                "managers": ["npm"],
                "workspace_id": "workspace-1",
            },
        )
        allowed_status, allowed_payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/supply-chain/package-shims/install",
                dashboard_session_token=token,
                payload={"managers": ["npm"], "workspace_id": "workspace-1"},
            ),
        )
        denied_status, denied_payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/supply-chain/package-shims/install",
                dashboard_session_token=token,
                payload={"managers": ["pip"], "workspace_id": "workspace-1"},
            ),
        )
    finally:
        daemon.stop()

    assert allowed_status == 200
    assert allowed_payload["operation"] == "install"
    assert denied_status == 401
    assert denied_payload["error"] == "unauthorized"


def test_action_scoped_dashboard_session_requires_exact_read_paths_and_matching_nonce(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        auth_token = load_guard_daemon_auth_token(store.guard_home)
        assert auth_token is not None
        token = _dashboard_token_with_claims(
            auth_token,
            {
                "action_path": "connect",
                "allowed_read_paths": ["/v1/runtime"],
                "nonce": "runtime-read-nonce",
            },
        )
        allowed_status, allowed_payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/runtime",
                method="GET",
                dashboard_session_token=token,
                extra_headers={"X-Guard-Dashboard-Nonce": "runtime-read-nonce"},
            ),
        )
        wrong_path_status, wrong_path_payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/inventory",
                method="GET",
                dashboard_session_token=token,
                extra_headers={"X-Guard-Dashboard-Nonce": "runtime-read-nonce"},
            ),
        )
        wrong_nonce_status, wrong_nonce_payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/runtime",
                method="GET",
                dashboard_session_token=token,
                extra_headers={"X-Guard-Dashboard-Nonce": "wrong-nonce"},
            ),
        )
        implicit_read_token = _dashboard_token_with_claims(
            auth_token,
            {
                "action_path": "connect",
            },
        )
        implicit_read_status, implicit_read_payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/runtime",
                method="GET",
                dashboard_session_token=implicit_read_token,
            ),
        )
    finally:
        daemon.stop()

    assert allowed_status == 200
    assert isinstance(allowed_payload, dict)
    assert wrong_path_status == 401
    assert wrong_path_payload["error"] == "unauthorized"
    assert wrong_nonce_status == 401
    assert wrong_nonce_payload["error"] == "unauthorized"
    assert implicit_read_status == 401
    assert implicit_read_payload["error"] == "unauthorized"


def test_headless_capabilities_rejects_dashboard_session_from_guard_token_header(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = _dashboard_token_for(store)
        status, payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/capabilities",
                method="GET",
                extra_headers={"X-Guard-Token": token},
            ),
        )
    finally:
        daemon.stop()

    assert status == 401
    assert payload["error"] == "unauthorized"


def test_cloud_app_handoff_get_requires_auth_before_legacy_local_page_branch(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        auth_token = load_guard_daemon_auth_token(store.guard_home)
        assert auth_token is not None
        status, payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/apps/codex/cloud?action=connect",
                method="GET",
                origin=None,
                referer="https://hol.org/guard/apps/codex",
            ),
        )
    finally:
        daemon.stop()

    assert status == 401
    assert payload["error"] == "unauthorized"
    serialized = json.dumps(payload)
    assert "handoffToken" not in serialized
    assert "dashboardSessionToken" not in serialized
    assert "guard-token" not in serialized
    assert auth_token not in serialized


def test_cloud_app_handoff_start_rejects_legacy_handoff_url(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        auth_token = load_guard_daemon_auth_token(store.guard_home)
        assert auth_token is not None
        status, payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/apps/codex/cloud/start",
                payload={"action": "connect"},
                origin="https://hol.org",
                token=_dashboard_token_for(store),
            ),
        )
    finally:
        daemon.stop()

    assert status == 410
    assert payload["error"] == "legacy_cloud_handoff_disabled"
    assert auth_token not in json.dumps(payload)


def test_cloud_app_handoff_start_does_not_save_raw_sync_credentials(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        status, payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/apps/codex/cloud/start",
                payload={
                    "action": "connect",
                    "sync_url": "https://hol.org/api/guard/receipts/sync",
                    "sync_token": "guard-runtime-token",
                    "sync_workspace_id": "workspace-123",
                },
                origin="https://hol.org",
                token=_dashboard_token_for(store),
            ),
        )
    finally:
        daemon.stop()

    assert status == 410
    assert payload["error"] == "legacy_cloud_handoff_disabled"
    assert "guard-runtime-token" not in json.dumps(payload)
    assert store.get_sync_credentials() is None


def test_cloud_app_handoff_navigation_requires_auth_before_legacy_sync_query_handling(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    path = (
        "/v1/apps/codex/cloud?action=connect&workspaceId=workspace-123"
        "&syncUrl=https%3A%2F%2Fhol.org%2Fapi%2Fguard%2Freceipts%2Fsync"
        "&syncToken=guard-runtime-token&syncWorkspaceId=workspace-123"
    )
    daemon.start()
    try:
        status, payload = _read_json_response(
            _request(
                daemon.port,
                path,
                method="GET",
                origin=None,
                extra_headers={
                    "Sec-Fetch-Mode": "navigate",
                    "Sec-Fetch-Dest": "document",
                    "Sec-Fetch-Site": "cross-site",
                },
            ),
        )
    finally:
        daemon.stop()

    assert status == 401
    assert payload["error"] == "unauthorized"
    assert "guard-runtime-token" not in json.dumps(payload)
    assert store.get_sync_credentials() is None


def test_cloud_app_handoff_complete_rejects_legacy_handoff_token(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        auth_token = load_guard_daemon_auth_token(store.guard_home)
        assert auth_token is not None
        status, payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/apps/codex/cloud/complete",
                payload={"handoff_token": "gch1.legacy.token"},
                origin=f"http://127.0.0.1:{daemon.port}",
            ),
        )
    finally:
        daemon.stop()

    assert status == 410
    assert payload["error"] == "legacy_cloud_handoff_disabled"
    assert auth_token not in json.dumps(payload)


def test_headless_app_operations_write_receipts_without_cli_copy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", lambda: home)
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = _dashboard_token_for(store)
        for path, operation in (
            ("/v1/apps/connect", "install"),
            ("/v1/apps/repair", "repair"),
            ("/v1/apps/status", "status"),
            ("/v1/apps/test", "scan"),
            ("/v1/apps/disconnect", "remove"),
        ):
            status, payload = _read_json_response(
                _request(
                    daemon.port,
                    path,
                    token=token,
                    payload={
                        "harness": "opencode",
                        "operation": operation,
                        "workspace_id": "workspace-1",
                        "confirmation_phrase": "disconnect-opencode",
                    },
                ),
            )
            assert status == 200
            assert payload["receipt"]["status"] == "completed"
            assert payload["receipt"]["operation"] == operation
            assert payload["state"]["receipt_summary"]["id"] == payload["receipt"]["id"]
            assert payload["state"]["receipt_summary"]["operation"] == operation
            assert "npx" not in json.dumps(payload)
            if operation == "install":
                assert payload["state"]["outcome"] == "app_connected"
                assert payload["state"]["app_status"] == "protected"
            if operation == "remove":
                assert payload["state"]["outcome"] == "app_disconnected"
                assert payload["state"]["app_status"] == "inactive"
            if operation == "scan":
                assert payload["state"]["outcome"] == "proof_passed"
                assert payload["state"]["proof_status"] == "passed"
    finally:
        daemon.stop()

    receipts = store.list_receipts(limit=20, harness="opencode")
    receipt_operations = {receipt["artifact_name"] for receipt in receipts}
    assert {
        "Headless install",
        "Headless repair",
        "Headless status",
        "Headless scan",
        "Headless remove",
    }.issubset(receipt_operations)


def test_headless_app_scan_syncs_receipt_to_cloud_when_connected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    store.set_sync_credentials(
        "https://hol.org/api/guard/receipts/sync",
        "cloud-token",
        "2026-05-23T17:18:00.000Z",
        workspace_id="workspace-1",
    )
    sync_calls: list[str] = []
    sync_finished = threading.Event()
    store.record_guard_connect_pairing_completed(
        sync_url="https://hol.org/api/guard/receipts/sync",
        allowed_origin="https://hol.org",
        now="2026-05-23T17:18:20.000Z",
        request_id="connect-1",
    )

    def fake_sync_local_guard_cloud_proof(current_store: GuardStore) -> dict[str, object]:
        assert current_store is store
        sync_calls.append("runtime")
        sync_calls.append("receipts")
        sync_finished.set()
        summary = {
            "synced_at": "2026-05-23T17:18:40.061Z",
            "receipts_stored": 1,
            "runtime_session_synced_at": "2026-05-23T17:18:35.000Z",
            "runtime_session_id": "runtime-session-1",
            "runtime_sessions_visible": 1,
        }
        current_store.record_latest_guard_connect_sync_success(
            sync_payload=summary,
            now="2026-05-23T17:18:40.061Z",
        )
        return summary

    monkeypatch.setattr(daemon_server, "sync_local_guard_cloud_proof", fake_sync_local_guard_cloud_proof, raising=False)

    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = _dashboard_token_for(store)
        status, payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/apps/test",
                token=token,
                payload={
                    "harness": "opencode",
                    "operation": "scan",
                    "workspace_id": "workspace-1",
                },
            ),
        )
    finally:
        daemon.stop()

    assert status == 200
    assert payload["receipt"]["operation"] == "scan"
    assert payload["cloud_sync"] == {
        "status": "queued",
        "message": "Guard Cloud sync started.",
    }
    assert sync_finished.wait(timeout=2)
    assert sync_calls == ["runtime", "receipts"]
    latest_state = store.get_latest_guard_connect_state(now="2026-05-23T17:18:40.061Z")
    assert isinstance(latest_state, dict)
    assert latest_state["proof"]["runtime_session_id"] == "runtime-session-1"
    assert latest_state["proof"]["runtime_session_synced_at"] == "2026-05-23T17:18:35.000Z"


def test_headless_app_scan_does_not_spawn_unbounded_cloud_sync_threads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    store.set_sync_credentials(
        "https://hol.org/api/guard/receipts/sync",
        "cloud-token",
        "2026-05-23T17:18:00.000Z",
        workspace_id="workspace-1",
    )
    sync_calls: list[int] = []
    sync_started = threading.Event()
    sync_release = threading.Event()

    def blocking_sync_local_guard_cloud_proof(current_store: GuardStore) -> dict[str, object]:
        assert current_store is store
        sync_calls.append(1)
        sync_started.set()
        sync_release.wait(timeout=5)
        return {
            "synced_at": "2026-05-23T17:18:40.061Z",
            "receipts_stored": 1,
        }

    monkeypatch.setattr(
        daemon_server,
        "sync_local_guard_cloud_proof",
        blocking_sync_local_guard_cloud_proof,
        raising=False,
    )

    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = _dashboard_token_for(store)
        first_status, first_payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/apps/test",
                token=token,
                payload={
                    "harness": "opencode",
                    "operation": "scan",
                    "workspace_id": "workspace-1",
                },
            ),
        )
        assert sync_started.wait(timeout=2)
        second_status, second_payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/apps/test",
                token=token,
                payload={
                    "harness": "opencode",
                    "operation": "scan",
                    "workspace_id": "workspace-1",
                },
            ),
        )
    finally:
        sync_release.set()
        daemon.stop()

    assert first_status == 200
    assert first_payload["cloud_sync"] == {
        "status": "queued",
        "message": "Guard Cloud sync started.",
    }
    assert second_status == 200
    assert second_payload["cloud_sync"] == {
        "status": "in_progress",
        "message": "Guard Cloud sync already running.",
    }
    assert len(sync_calls) == 1


def test_headless_policy_sync_persists_policy_and_receipt(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = _dashboard_token_for(store)
        status, payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/policy/sync",
                token=token,
                payload={
                    "harness": "codex",
                    "operation": "policy_sync",
                    "workspace_id": "workspace-1",
                    "policy_memory": json.dumps(
                        {
                            "scope": "harness",
                            "action": "review",
                            "expires_at": "2099-01-01T00:00:00Z",
                            "reason": "Cloud policy memory",
                        }
                    ),
                },
            ),
        )
    finally:
        daemon.stop()

    assert status == 200
    assert payload["receipt"]["operation"] == "policy_sync"
    decisions = store.list_policy_decisions(harness="codex")
    assert decisions[0]["scope"] == "harness"
    assert decisions[0]["action"] == "review"
    assert decisions[0]["expires_at"] == "2099-01-01T00:00:00+00:00"
    assert store.list_receipts(limit=5, harness="codex")


def test_headless_policy_sync_accepts_policy_bundle_and_returns_bundle_metadata(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = _dashboard_token_for(store)
        bundle = {
            "contractVersion": "guard-policy-bundle.v1",
            "bundleVersion": "policy-2026-04-19.3",
            "bundleHash": "",
            "issuedAt": "2026-04-19T00:00:10+00:00",
            "expiresAt": None,
            "verifier": {
                "algorithm": "sha256",
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
            "rules": [
                {
                    "ruleId": "pkg-block",
                    "action": "block",
                    "reason": "Block risky package installs.",
                    "matcherFamilies": ["package-request"],
                    "scope": {
                        "agents": [],
                        "devices": [],
                        "ecosystems": ["npm"],
                        "environments": ["development"],
                        "harnesses": ["codex"],
                        "locations": [],
                    },
                }
            ],
            "acknowledgements": [],
        }
        bundle["bundleHash"] = guard_runner_module._computed_policy_bundle_hash(bundle)
        status, payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/policy/sync",
                token=token,
                payload={
                    "harness": "codex",
                    "operation": "policy_sync",
                    "policy_bundle": json.dumps(bundle),
                },
            ),
        )
    finally:
        daemon.stop()

    assert status == 200
    assert payload["bundle_version"] == "policy-2026-04-19.3"
    assert payload["bundle_hash"] == bundle["bundleHash"]
    assert store.get_sync_payload("policy_bundle")["bundleVersion"] == "policy-2026-04-19.3"
    assert store.resolve_policy("codex", "codex:project:package-request:abc", "hash") == "block"


def test_headless_policy_sync_rejects_unsupported_daemon_version(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = _dashboard_token_for(store)
        bundle = {
            "contractVersion": "guard-policy-bundle.v1",
            "bundleVersion": "policy-2026-04-19.4",
            "bundleHash": "",
            "issuedAt": "2026-04-19T00:00:10+00:00",
            "expiresAt": None,
            "minDaemonVersion": "999.0.0",
            "verifier": {
                "algorithm": "sha256",
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
        }
        bundle["bundleHash"] = guard_runner_module._computed_policy_bundle_hash(bundle)
        status, payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/policy/sync",
                token=token,
                payload={
                    "harness": "codex",
                    "operation": "policy_sync",
                    "policy_bundle": json.dumps(bundle),
                },
            ),
        )
    finally:
        daemon.stop()

    assert status == 400
    assert payload["error"] == "unsupported_daemon_version"


def test_headless_policy_sync_rejects_global_allow_and_missing_scope_targets(
    tmp_path: Path,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = _dashboard_token_for(store)
        global_status, global_payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/policy/sync",
                token=token,
                payload={
                    "harness": "codex",
                    "operation": "policy_sync",
                    "policy_memory": json.dumps({"scope": "global", "action": "allow"}),
                },
            ),
        )
        workspace_status, workspace_payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/policy/sync",
                token=token,
                payload={
                    "harness": "codex",
                    "operation": "policy_sync",
                    "policy_memory": json.dumps({"scope": "workspace", "action": "review"}),
                },
            ),
        )
        cloud_workspace_status, cloud_workspace_payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/policy/sync",
                token=token,
                payload={
                    "harness": "codex",
                    "operation": "policy_sync",
                    "workspace_id": "cloud-workspace-id",
                    "policy_memory": json.dumps({"scope": "workspace", "action": "review"}),
                },
            ),
        )
    finally:
        daemon.stop()

    assert global_status == 400
    assert global_payload["error"] == "broad_allow_requires_narrow_scope"
    assert workspace_status == 400
    assert workspace_payload["error"] == "missing_scope_target"
    assert cloud_workspace_status == 400
    assert cloud_workspace_payload["error"] == "missing_scope_target"
    assert store.list_policy_decisions(harness="codex") == []


def test_headless_policy_sync_rejects_empty_policy_memory(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = _dashboard_token_for(store)
        status, payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/policy/sync",
                token=token,
                payload={
                    "harness": "codex",
                    "operation": "policy_sync",
                },
            ),
        )
    finally:
        daemon.stop()

    assert status == 400
    assert payload["error"] == "missing_policy_memory"
    assert store.list_policy_decisions(harness="codex") == []


def test_headless_policy_sync_requires_explicit_scope_and_action(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = _dashboard_token_for(store)
        status, payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/policy/sync",
                token=token,
                payload={
                    "harness": "codex",
                    "operation": "policy_sync",
                    "policy_memory": json.dumps({"reason": "missing scope and action"}),
                },
            ),
        )
    finally:
        daemon.stop()

    assert status == 400
    assert payload["error"] == "missing_policy_fields"
    assert store.list_policy_decisions(harness="codex") == []


def test_headless_policy_sync_rejects_malformed_expiry(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = _dashboard_token_for(store)
        status, payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/policy/sync",
                token=token,
                payload={
                    "harness": "codex",
                    "operation": "policy_sync",
                    "policy_memory": json.dumps(
                        {
                            "scope": "harness",
                            "action": "review",
                            "expires_at": "9",
                        }
                    ),
                },
            ),
        )
    finally:
        daemon.stop()

    assert status == 400
    assert payload["error"] == "invalid_policy_expiry"
    assert store.list_policy_decisions(harness="codex") == []


def test_headless_api_rejects_missing_auth_and_bad_harness(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = _dashboard_token_for(store)
        auth_status, auth_payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/apps/status",
                payload={"harness": "codex", "operation": "status"},
                token=None,
            ),
        )
        bad_status, bad_payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/apps/status",
                token=token,
                payload={"harness": "not-real", "operation": "status"},
            ),
        )
    finally:
        daemon.stop()

    assert auth_status == 401
    assert auth_payload["error"] == "unauthorized"
    assert bad_status == 404
    assert bad_payload["status"] == "failed"
    assert bad_payload["error"]["code"] == "unknown_harness"
    assert bad_payload["error"]["retryable"] is False


def test_headless_remote_once_applies_pending_request_and_records_receipt(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    request = _remote_once_request("req-remote-once")
    store.add_approval_request(request, "2026-05-14T11:59:00+00:00")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = _dashboard_token_for(store)
        status, payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/requests/remote-once",
                token=token,
                payload={
                    "harness": "codex",
                    "operation": "remote_once",
                    "remote_once": json.dumps(
                        {
                            "receipt_id": "cloud-receipt-1",
                            "request_id": "req-remote-once",
                            "request_last_seen_at": "2026-05-14T11:59:00+00:00",
                            "request_policy_action": "require-reapproval",
                            "request_recommended_scope": "artifact",
                        }
                    ),
                },
            ),
        )
    finally:
        daemon.stop()

    assert status == 200
    assert payload["operation"] == "remote_once"
    assert payload["status"] == "completed"
    assert payload["resolved_request"]["request_id"] == "req-remote-once"
    assert payload["resolved_request"]["resolution_scope"] == "artifact"
    events = store.list_events(limit=5, event_name="approval.remote_once_applied")
    assert events[0]["payload"]["receipt_id"] == "cloud-receipt-1"
    # Remote-once must resolve the queued request without persisting an artifact policy.
    persisted_action = store.resolve_policy(
        "codex",
        request.artifact_id,
        artifact_hash=request.artifact_hash,
        workspace=request.workspace,
    )
    assert persisted_action is None


def test_headless_remote_once_rejects_stale_requests_and_replays(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    request = _remote_once_request("req-remote-replay")
    store.add_approval_request(request, "2026-05-14T11:59:00+00:00")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = _dashboard_token_for(store)
        stale_status, stale_payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/requests/remote-once",
                token=token,
                payload={
                    "harness": "codex",
                    "operation": "remote_once",
                    "remote_once": json.dumps(
                        {
                            "receipt_id": "cloud-receipt-stale",
                            "request_id": "req-remote-replay",
                            "request_last_seen_at": "2026-05-14T11:58:00+00:00",
                            "request_policy_action": "require-reapproval",
                            "request_recommended_scope": "artifact",
                        }
                    ),
                },
            ),
        )
        first_status, _first_payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/requests/remote-once",
                token=token,
                payload={
                    "harness": "codex",
                    "operation": "remote_once",
                    "remote_once": json.dumps(
                        {
                            "receipt_id": "cloud-receipt-replay",
                            "request_id": "req-remote-replay",
                            "request_last_seen_at": "2026-05-14T11:59:00+00:00",
                            "request_policy_action": "require-reapproval",
                            "request_recommended_scope": "artifact",
                        }
                    ),
                },
            ),
        )
        replay_status, replay_payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/requests/remote-once",
                token=token,
                payload={
                    "harness": "codex",
                    "operation": "remote_once",
                    "remote_once": json.dumps(
                        {
                            "receipt_id": "cloud-receipt-replay",
                            "request_id": "req-remote-replay",
                            "request_last_seen_at": "2026-05-14T11:59:00+00:00",
                            "request_policy_action": "require-reapproval",
                            "request_recommended_scope": "artifact",
                        }
                    ),
                },
            ),
        )
    finally:
        daemon.stop()

    assert stale_status == 409
    assert stale_payload["error"] == "remote_once_request_stale"
    assert first_status == 200
    assert replay_status == 409
    assert replay_payload["error"] == "remote_once_replayed"


def test_headless_remote_once_rejects_payload_scope_spoofing(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    request = _remote_once_request(
        "req-remote-spoof",
        policy_action="block",
        recommended_scope="workspace",
    )
    store.add_approval_request(request, "2026-05-14T11:59:00+00:00")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = _dashboard_token_for(store)
        status, payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/requests/remote-once",
                token=token,
                payload={
                    "harness": "codex",
                    "operation": "remote_once",
                    "remote_once": json.dumps(
                        {
                            "receipt_id": "cloud-receipt-spoof",
                            "request_id": "req-remote-spoof",
                            "request_last_seen_at": "2026-05-14T11:59:00+00:00",
                            "request_policy_action": "require-reapproval",
                            "request_recommended_scope": "artifact",
                        }
                    ),
                },
            ),
        )
    finally:
        daemon.stop()

    assert status == 409
    assert payload["error"] == "remote_once_not_permitted"


def test_headless_remote_once_keeps_claimed_receipts_consumed_after_gate_rejection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    request = _remote_once_request("req-remote-gate")
    store.add_approval_request(request, "2026-05-14T11:59:00+00:00")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    monkeypatch.setattr(
        daemon_server,
        "apply_approval_resolution",
        lambda **_kwargs: (_ for _ in ()).throw(
            ApprovalGateError(
                "approval_gate_interactive_required",
                "Approval password is required from an interactive terminal.",
            )
        ),
    )
    try:
        token = _dashboard_token_for(store)
        first_status, first_payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/requests/remote-once",
                token=token,
                payload={
                    "harness": "codex",
                    "operation": "remote_once",
                    "remote_once": json.dumps(
                        {
                            "receipt_id": "cloud-receipt-gate",
                            "request_id": "req-remote-gate",
                            "request_last_seen_at": "2026-05-14T11:59:00+00:00",
                            "request_policy_action": "require-reapproval",
                            "request_recommended_scope": "artifact",
                        }
                    ),
                },
            ),
        )
        second_status, second_payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/requests/remote-once",
                token=token,
                payload={
                    "harness": "codex",
                    "operation": "remote_once",
                    "remote_once": json.dumps(
                        {
                            "receipt_id": "cloud-receipt-gate",
                            "request_id": "req-remote-gate",
                            "request_last_seen_at": "2026-05-14T11:59:00+00:00",
                            "request_policy_action": "require-reapproval",
                            "request_recommended_scope": "artifact",
                        }
                    ),
                },
            ),
        )
    finally:
        daemon.stop()

    assert first_status == 403
    assert first_payload["error"] == "approval_gate_interactive_required"
    assert second_status == 409
    assert second_payload["error"] == "remote_once_replayed"


def test_headless_remote_once_keeps_claimed_receipts_consumed_after_apply_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = GuardStore(tmp_path / "guard-home")
    request = _remote_once_request("req-remote-unresolved")
    store.add_approval_request(request, "2026-05-14T11:59:00+00:00")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    monkeypatch.setattr(
        daemon_server,
        "apply_approval_resolution",
        lambda **_kwargs: {"resolved": False, "error": "unexpected"},
    )
    try:
        token = _dashboard_token_for(store)
        payload = {
            "harness": "codex",
            "operation": "remote_once",
            "remote_once": json.dumps(
                {
                    "receipt_id": "cloud-receipt-unresolved",
                    "request_id": "req-remote-unresolved",
                    "request_last_seen_at": "2026-05-14T11:59:00+00:00",
                    "request_policy_action": "require-reapproval",
                    "request_recommended_scope": "artifact",
                }
            ),
        }
        first_status, first_payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/requests/remote-once",
                token=token,
                payload=payload,
            ),
        )
        second_status, second_payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/requests/remote-once",
                token=token,
                payload=payload,
            ),
        )
    finally:
        daemon.stop()

    assert first_status == 409
    assert first_payload["error"] == "remote_once_apply_failed"
    assert second_status == 409
    assert second_payload["error"] == "remote_once_replayed"


def test_headless_api_rejects_forged_dashboard_session_token(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        status, payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/apps/status",
                payload={"harness": "codex", "operation": "status"},
                token="gld1.abcdefghijklmnop.qrstuvwxyz123456",
            ),
        )
    finally:
        daemon.stop()

    assert status == 401
    assert payload["error"] == "unauthorized"


def test_headless_api_uses_valid_bearer_session_when_session_header_is_bad(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = _dashboard_token_for(store)
        status, payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/apps/status",
                payload={"harness": "codex", "operation": "status"},
                authorization_token=token,
                dashboard_session_token="gld1.abcdefghijklmnop.qrstuvwxyz123456",
            ),
        )
    finally:
        daemon.stop()

    assert status == 200
    assert payload["receipt"]["operation"] == "status"


def test_headless_api_does_not_read_env_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    home = tmp_path / "home"
    env_path = home / ".agents" / "skills" / "x" / ".env"
    env_path.parent.mkdir(parents=True, exist_ok=True)
    env_path.write_text("SECRET=value\n", encoding="utf-8")
    monkeypatch.setattr(Path, "home", lambda: home)
    original_read_text = Path.read_text

    def guarded_read_text(path: Path, *args: object, **kwargs: object) -> str:
        if path.name == ".env":
            raise AssertionError("headless daemon API must not read .env files")
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", guarded_read_text)
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = _dashboard_token_for(store)
        status, payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/apps/test",
                token=token,
                payload={"harness": "codex", "operation": "scan"},
            ),
        )
    finally:
        daemon.stop()

    assert status == 200
    assert payload["receipt"]["operation"] == "scan"
    assert payload["state"]["outcome"] == "proof_failed"
    assert payload["state"]["proof_status"] == "failed"


def test_headless_api_rejects_missing_harness_with_structured_error(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home")
    daemon = GuardDaemonServer(store, host="127.0.0.1", port=0)
    daemon.start()
    try:
        token = _dashboard_token_for(store)
        status, payload = _read_json_response(
            _request(
                daemon.port,
                "/v1/apps/connect",
                token=token,
                payload={"operation": "install"},
            ),
        )
    finally:
        daemon.stop()

    assert status == 400
    assert payload["status"] == "failed"
    assert payload["error"]["code"] == "missing_harness"
    assert payload["error"]["retryable"] is False


def test_headless_generic_action_error_omits_unstructured_detail() -> None:
    status, payload = _headless_action_error_payload(
        operation="repair",
        error_code="unexpected daemon blowup",
    )

    assert status == 400
    assert payload == {
        "status": "failed",
        "error": {
            "code": "repair_failed",
            "message": "Guard could not finish the repair.",
            "retryable": True,
        },
    }
