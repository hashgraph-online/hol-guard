"""Tests for clearing revoked Guard Cloud OAuth sign-in before reconnect."""

from __future__ import annotations

import json
import urllib.error
from contextlib import contextmanager
from datetime import datetime, timezone

import pytest

from codex_plugin_scanner.guard.cli.connect_flow import run_guard_connect_repair_command
from codex_plugin_scanner.guard.cli.oauth_client import generate_dpop_key_pair
from codex_plugin_scanner.guard.runtime import runner as guard_runner_module
from codex_plugin_scanner.guard.store import GuardStore


def _store_with_oauth_credentials(
    tmp_path,
    *,
    access_token: str | None = None,
    access_token_expires_at: str | None = None,
) -> GuardStore:
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
        access_token=access_token,
        access_token_expires_at=access_token_expires_at,
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

    assert "hol-guard connect" in str(error.value)
    assert "hol-guard disconnect" not in str(error.value)
    assert store.get_oauth_local_credentials(allow_primary=True) is not None


def test_upgraded_running_process_does_not_refresh_shared_oauth_grant(monkeypatch) -> None:
    refresh_attempted = False

    def _unexpected_urlopen(request, timeout):
        del request, timeout
        nonlocal refresh_attempted
        refresh_attempted = True
        raise AssertionError("stale runtime must not exchange the shared refresh token")

    loaded_identity = guard_runner_module._LOADED_HOL_GUARD_RUNTIME_PACKAGE_IDENTITY
    assert loaded_identity is not None
    monkeypatch.setattr(
        guard_runner_module,
        "_hol_guard_runtime_package_identity",
        lambda: (loaded_identity[0], "0" * 64),
    )
    monkeypatch.setattr(guard_runner_module.urllib.request, "urlopen", _unexpected_urlopen)

    with pytest.raises(guard_runner_module.GuardSyncNotAvailableError) as error:
        guard_runner_module._refresh_guard_oauth_access_token(
            token_endpoint="https://hol.org/api/guard/oauth/token",
            client_id="guard-local-daemon",
            refresh_token="refresh-token-1",
            dpop_key_material=generate_dpop_key_pair(),
        )

    assert error.value.retryable is True
    assert "Restart the agent application" in str(error.value)
    assert refresh_attempted is False


def test_missing_package_metadata_after_load_blocks_oauth_refresh(monkeypatch) -> None:
    loaded_identity = guard_runner_module._LOADED_HOL_GUARD_RUNTIME_PACKAGE_IDENTITY
    assert loaded_identity is not None
    monkeypatch.setattr(guard_runner_module, "_hol_guard_runtime_package_identity", lambda: None)

    assert guard_runner_module._guard_runtime_was_upgraded() is True


def test_missing_package_identity_at_startup_blocks_oauth_refresh(monkeypatch) -> None:
    monkeypatch.setattr(guard_runner_module, "_LOADED_HOL_GUARD_RUNTIME_PACKAGE_IDENTITY", None)

    assert guard_runner_module._guard_runtime_was_upgraded() is True


def test_runtime_source_identity_covers_non_runner_modules(tmp_path) -> None:
    package_root = tmp_path / "codex_plugin_scanner"
    runtime_root = package_root / "guard" / "runtime"
    runtime_root.mkdir(parents=True)
    (runtime_root / "runner.py").write_text("RUNNER = True\n", encoding="utf-8")
    adjacent_module = runtime_root / "oauth_support.py"
    adjacent_module.write_text("REVISION = 1\n", encoding="utf-8")

    initial_digest = guard_runner_module._hol_guard_runtime_source_sha256(package_root)
    adjacent_module.write_text("REVISION = 2\n", encoding="utf-8")

    assert guard_runner_module._hol_guard_runtime_source_sha256(package_root) != initial_digest


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


def test_resolve_guard_sync_auth_context_reuses_cached_access_token(tmp_path, monkeypatch) -> None:
    store = _store_with_oauth_credentials(
        tmp_path,
        access_token="cached-access-token",
        access_token_expires_at="2099-01-01T00:00:00+00:00",
    )

    def _unexpected_refresh(**_kwargs):
        raise AssertionError("refresh should not run while cached access token is still valid")

    monkeypatch.setattr(guard_runner_module, "_refresh_guard_oauth_access_token", _unexpected_refresh)

    auth_context = guard_runner_module._resolve_guard_sync_auth_context(store)

    assert auth_context["access_token"] == "cached-access-token"
    assert auth_context["sync_url"] == "https://hol.org/api/guard/receipts/sync"


def test_refresh_guard_oauth_access_token_prefers_jwt_expiry_claim(monkeypatch) -> None:
    expiry = datetime(2099, 1, 1, tzinfo=timezone.utc)
    access_token = ".".join(
        (
            guard_runner_module._encode_jwt_segment({"alg": "ES256"}),
            guard_runner_module._encode_jwt_segment({"exp": int(expiry.timestamp())}),
            "signature",
        )
    )

    class _Response:
        def read(self) -> bytes:
            return json.dumps(
                {
                    "access_token": access_token,
                    "refresh_token": "refresh-token-2",
                    "token_type": "Bearer",
                }
            ).encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:
            return None

    monkeypatch.setattr(
        guard_runner_module.urllib.request,
        "urlopen",
        lambda request, timeout: _Response(),
    )

    refreshed = guard_runner_module._refresh_guard_oauth_access_token(
        token_endpoint="https://hol.org/api/guard/oauth/token",
        client_id="guard-local-daemon",
        refresh_token="refresh-token-1",
        dpop_key_material=generate_dpop_key_pair(),
    )

    assert refreshed["access_token"] == access_token
    assert refreshed["access_token_expires_at"] == expiry.isoformat()


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


def test_refresh_guard_oauth_access_token_extracts_cloud_user_profile(monkeypatch) -> None:
    """Token refresh should extract cloud_user_profile from guard_local_entitlement in the response."""
    access_token = ".".join(
        (
            guard_runner_module._encode_jwt_segment({"alg": "ES256"}),
            guard_runner_module._encode_jwt_segment({"exp": 9999999999}),
            "signature",
        )
    )

    class _Response:
        def read(self) -> bytes:
            return json.dumps(
                {
                    "access_token": access_token,
                    "refresh_token": "refresh-token-2",
                    "token_type": "Bearer",
                    "guard_local_entitlement": {
                        "plan_id": "team",
                        "supply_chain_firewall": True,
                        "user_profile": {
                            "email": "user@hol.org",
                            "display_name": "Test User",
                            "avatar_url": "https://hol.org/avatar.png",
                        },
                    },
                }
            ).encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:
            return None

    monkeypatch.setattr(
        guard_runner_module.urllib.request,
        "urlopen",
        lambda request, timeout: _Response(),
    )

    refreshed = guard_runner_module._refresh_guard_oauth_access_token(
        token_endpoint="https://hol.org/api/guard/oauth/token",
        client_id="guard-local-daemon",
        refresh_token="refresh-token-1",
        dpop_key_material=generate_dpop_key_pair(),
    )

    assert refreshed["cloud_user_profile"] == {
        "email": "user@hol.org",
        "display_name": "Test User",
        "avatar_url": "https://hol.org/avatar.png",
    }


def test_refresh_guard_oauth_access_token_returns_none_cloud_user_profile_when_absent(monkeypatch) -> None:
    """Token refresh should return None for cloud_user_profile when entitlement lacks user_profile."""
    access_token = ".".join(
        (
            guard_runner_module._encode_jwt_segment({"alg": "ES256"}),
            guard_runner_module._encode_jwt_segment({"exp": 9999999999}),
            "signature",
        )
    )

    class _Response:
        def read(self) -> bytes:
            return json.dumps(
                {
                    "access_token": access_token,
                    "refresh_token": "refresh-token-2",
                    "token_type": "Bearer",
                }
            ).encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:
            return None

    monkeypatch.setattr(
        guard_runner_module.urllib.request,
        "urlopen",
        lambda request, timeout: _Response(),
    )

    refreshed = guard_runner_module._refresh_guard_oauth_access_token(
        token_endpoint="https://hol.org/api/guard/oauth/token",
        client_id="guard-local-daemon",
        refresh_token="refresh-token-1",
        dpop_key_material=generate_dpop_key_pair(),
    )

    assert refreshed["cloud_user_profile"] is None


def test_prepare_guard_cloud_connect_authorization_persists_refreshed_cloud_user_profile(tmp_path, monkeypatch) -> None:
    """Token refresh should persist cloud_user_profile into stored OAuth credentials."""
    store = _store_with_oauth_credentials(tmp_path)

    access_token = ".".join(
        (
            guard_runner_module._encode_jwt_segment({"alg": "ES256"}),
            guard_runner_module._encode_jwt_segment({"exp": 9999999999}),
            "signature",
        )
    )

    class _Response:
        def read(self) -> bytes:
            return json.dumps(
                {
                    "access_token": access_token,
                    "refresh_token": "refresh-token-2",
                    "token_type": "Bearer",
                    "guard_local_entitlement": {
                        "plan_id": "team",
                        "supply_chain_firewall": True,
                        "user_profile": {
                            "email": "user@hol.org",
                            "display_name": "Test User",
                            "avatar_url": "https://hol.org/avatar.png",
                        },
                    },
                }
            ).encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:
            return None

    monkeypatch.setattr(
        guard_runner_module.urllib.request,
        "urlopen",
        lambda request, timeout: _Response(),
    )

    guard_runner_module.prepare_guard_cloud_connect_authorization(store)

    credentials = store.get_oauth_local_credentials(allow_primary=True)
    assert credentials is not None
    profile = credentials.get("cloud_user_profile")
    assert isinstance(profile, dict)
    assert profile["email"] == "user@hol.org"
    assert profile["display_name"] == "Test User"
    assert profile["avatar_url"] == "https://hol.org/avatar.png"


def test_prepare_guard_cloud_connect_authorization_clears_stale_cloud_user_profile(tmp_path, monkeypatch) -> None:
    """When refresh response has guard_local_entitlement but no user_profile, clear stale profile."""
    store = _store_with_oauth_credentials(tmp_path)
    # Seed existing cloud_user_profile in credentials
    dpop_key_material = generate_dpop_key_pair()
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="refresh-token-1",
        dpop_private_key_pem=dpop_key_material.private_key_pem,
        dpop_public_jwk=dpop_key_material.public_jwk,
        dpop_public_jwk_thumbprint=dpop_key_material.public_jwk_thumbprint,
        grant_id="grant-1",
        now=datetime.now(timezone.utc).isoformat(),
        cloud_user_profile={
            "email": "old@hol.org",
            "display_name": "Old User",
            "avatar_url": "https://hol.org/old.png",
        },
    )

    access_token = ".".join(
        (
            guard_runner_module._encode_jwt_segment({"alg": "ES256"}),
            guard_runner_module._encode_jwt_segment({"exp": 9999999999}),
            "signature",
        )
    )

    class _Response:
        def read(self) -> bytes:
            return json.dumps(
                {
                    "access_token": access_token,
                    "refresh_token": "refresh-token-2",
                    "token_type": "Bearer",
                    "guard_local_entitlement": {
                        "plan_id": "team",
                        "supply_chain_firewall": True,
                    },
                }
            ).encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:
            return None

    monkeypatch.setattr(
        guard_runner_module.urllib.request,
        "urlopen",
        lambda request, timeout: _Response(),
    )

    guard_runner_module.prepare_guard_cloud_connect_authorization(store)

    credentials = store.get_oauth_local_credentials(allow_primary=True)
    assert credentials is not None
    # Profile should be cleared (not preserved) because entitlement was present but lacked user_profile
    profile = credentials.get("cloud_user_profile")
    assert profile is None
