"""Tests for clearing revoked Guard Cloud OAuth sign-in before reconnect."""

from __future__ import annotations

from contextlib import contextmanager
import json
import urllib.error

import pytest

from codex_plugin_scanner.guard.cli.connect_flow import run_guard_connect_repair_command
from codex_plugin_scanner.guard.cli.oauth_client import generate_dpop_key_pair
from codex_plugin_scanner.guard.runtime import runner as guard_runner_module
from codex_plugin_scanner.guard.store import GuardStore


def _store_with_oauth_credentials(tmp_path) -> GuardStore:
    store = GuardStore(tmp_path / "guard-home")
    dpop_key_material = generate_dpop_key_pair()
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="refresh-token-1",
        dpop_private_key_pem=dpop_key_material.private_key_pem,
        dpop_public_jwk=dpop_key_material.public_jwk,
        dpop_public_jwk_thumbprint=dpop_key_material.public_jwk_thumbprint,
        grant_id="grant-1",
        machine_id="machine-1",
        workspace_id="workspace-1",
        now="2026-06-01T00:00:00+00:00",
    )
    return store


def _invalid_grant_http_error() -> urllib.error.HTTPError:
    class _ErrorResponse:
        def read(self) -> bytes:
            return json.dumps(
                {
                    "error": "invalid_grant",
                    "error_description": "The grant is missing, expired, or already consumed.",
                }
            ).encode("utf-8")

        def close(self) -> None:
            return None

    return urllib.error.HTTPError(
        "https://hol.org/api/guard/oauth/token",
        400,
        "Bad Request",
        hdrs=None,
        fp=_ErrorResponse(),
    )


def test_prepare_guard_cloud_connect_authorization_clears_revoked_sign_in(tmp_path, monkeypatch) -> None:
    store = _store_with_oauth_credentials(tmp_path)

    def _fake_urlopen(request, timeout):
        raise _invalid_grant_http_error()

    monkeypatch.setattr(guard_runner_module.urllib.request, "urlopen", _fake_urlopen)

    result = guard_runner_module.prepare_guard_cloud_connect_authorization(store)

    assert result["cleared_stale_sign_in"] is True
    assert result["existing_sign_in_valid"] is False
    assert store.get_oauth_local_credentials(allow_primary=True) is None


def test_connect_repair_clears_revoked_sign_in_and_points_to_connect(tmp_path, monkeypatch) -> None:
    store = _store_with_oauth_credentials(tmp_path)

    def _fake_urlopen(request, timeout):
        raise _invalid_grant_http_error()

    monkeypatch.setattr(guard_runner_module.urllib.request, "urlopen", _fake_urlopen)

    payload = run_guard_connect_repair_command(
        store=store,
        sync_url="https://hol.org/api/guard/receipts/sync",
        connect_url="https://hol.org/guard/connect",
    )

    assert payload["cleared_stale_sign_in"] is True
    assert payload["recovery_command"] == "hol-guard connect"
    assert "Cleared expired Guard Cloud sign-in" in str(payload["repair_message"])


def test_invalid_grant_refresh_preserves_sign_in_until_explicit_repair(tmp_path, monkeypatch) -> None:
    store = _store_with_oauth_credentials(tmp_path)

    def _fake_urlopen(request, timeout):
        raise _invalid_grant_http_error()

    monkeypatch.setattr(guard_runner_module.urllib.request, "urlopen", _fake_urlopen)

    with pytest.raises(guard_runner_module.GuardSyncAuthorizationExpiredError) as error:
        guard_runner_module._resolve_guard_sync_auth_context(store)

    assert "hol-guard disconnect" in str(error.value)
    assert store.get_oauth_local_credentials(allow_primary=True) is not None


def test_prepare_guard_cloud_connect_authorization_tolerates_network_errors(tmp_path, monkeypatch) -> None:
    store = _store_with_oauth_credentials(tmp_path)

    def _fake_urlopen(request, timeout):
        raise OSError("network unreachable")

    monkeypatch.setattr(guard_runner_module.urllib.request, "urlopen", _fake_urlopen)

    result = guard_runner_module.prepare_guard_cloud_connect_authorization(store)

    assert result["cleared_stale_sign_in"] is False
    assert result["existing_sign_in_valid"] is True
    assert store.get_oauth_local_credentials(allow_primary=True) is not None


def test_prepare_guard_cloud_connect_authorization_refreshes_under_lock(tmp_path, monkeypatch) -> None:
    store = _store_with_oauth_credentials(tmp_path)
    lock_state = {"held": False}

    @contextmanager
    def _fake_refresh_lock(*, timeout_seconds: float = 30.0):
        del timeout_seconds
        assert lock_state["held"] is False
        lock_state["held"] = True
        try:
            yield
        finally:
            lock_state["held"] = False

    def _fake_resolve(_store, credentials, *, persist_recovered_secret: bool = False):
        del _store, persist_recovered_secret
        assert lock_state["held"] is True
        assert credentials["refresh_token"] == "refresh-token-1"
        return {
            "sync_url": "https://hol.org/api/guard/receipts/sync",
            "access_token": "access-token-1",
            "dpop_key_material": None,
        }

    monkeypatch.setattr(store, "hold_oauth_refresh_lock", _fake_refresh_lock)
    monkeypatch.setattr(
        guard_runner_module,
        "_resolve_guard_sync_auth_context_from_oauth_credentials",
        _fake_resolve,
    )

    result = guard_runner_module.prepare_guard_cloud_connect_authorization(store)

    assert result["cleared_stale_sign_in"] is False
    assert result["existing_sign_in_valid"] is True
    assert store.get_oauth_local_credentials(allow_primary=True) is not None


def test_prepare_guard_cloud_connect_authorization_tolerates_refresh_lock_timeout(
    tmp_path,
    monkeypatch,
) -> None:
    store = _store_with_oauth_credentials(tmp_path)

    @contextmanager
    def _fake_refresh_lock(*, timeout_seconds: float = 30.0):
        del timeout_seconds
        raise TimeoutError("refresh lock busy")
        yield

    monkeypatch.setattr(store, "hold_oauth_refresh_lock", _fake_refresh_lock)

    result = guard_runner_module.prepare_guard_cloud_connect_authorization(store)

    assert result["cleared_stale_sign_in"] is False
    assert result["existing_sign_in_valid"] is True
    assert store.get_oauth_local_credentials(allow_primary=True) is not None


def test_invalid_dpop_curve_refresh_uses_reconnect_message(tmp_path, monkeypatch) -> None:
    store = _store_with_oauth_credentials(tmp_path)

    def _raise_invalid_curve(**_kwargs):
        raise RuntimeError("Guard DPoP key must be a P-256 EC private key.")

    monkeypatch.setattr(guard_runner_module, "_sign_guard_dpop_proof", _raise_invalid_curve)

    with pytest.raises(guard_runner_module.GuardSyncAuthorizationExpiredError) as error:
        guard_runner_module._resolve_guard_sync_auth_context(store)

    assert "hol-guard connect" in str(error.value)


def test_resolve_guard_sync_auth_context_skips_primary_repair_for_package_eval(tmp_path, monkeypatch) -> None:
    store = _store_with_oauth_credentials(tmp_path)
    allow_primary_calls: list[bool] = []

    monkeypatch.setattr(
        store,
        "get_oauth_local_credential_health",
        lambda: {"configured": True, "state": "degraded"},
    )

    def _fake_get_oauth_local_credentials(*, allow_primary: bool = False):
        allow_primary_calls.append(allow_primary)
        return None

    monkeypatch.setattr(store, "get_oauth_local_credentials", _fake_get_oauth_local_credentials)
    monkeypatch.setattr(store, "get_recoverable_oauth_local_credentials", lambda: None)

    with pytest.raises(guard_runner_module.GuardSyncAuthorizationExpiredError):
        guard_runner_module._resolve_guard_sync_auth_context(store, allow_primary_repair=False)

    assert allow_primary_calls == [False]
