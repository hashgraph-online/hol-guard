"""Regression tests: transient refresh-token failures must not wipe Guard Cloud sign-in.

Reproduces the production failure where a single transient `invalid_grant`
response (rotation race against another local process, edge 400s) flowed into
the daemon repair path and deleted all local OAuth material, forcing users to
rerun `hol-guard connect` while review items stopped syncing.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse

import pytest

from codex_plugin_scanner.guard.cli.oauth_client import generate_dpop_key_pair
from codex_plugin_scanner.guard.runtime import runner as guard_runner_module
from codex_plugin_scanner.guard.store import GuardStore
from tests.support.network import stub_authenticated_urlopen


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


def _allow_refresh(monkeypatch: pytest.MonkeyPatch) -> None:
    """Disable the runtime-upgrade guard so refresh reaches the network stub."""
    monkeypatch.setattr(guard_runner_module, "_guard_runtime_was_upgraded", lambda: False)
    monkeypatch.setattr(guard_runner_module.time, "sleep", lambda _seconds: None)


class _SuccessResponse:
    def __init__(self, access_token: str) -> None:
        self._access_token = access_token

    def read(self) -> bytes:
        return json.dumps(
            {
                "access_token": self._access_token,
                "token_type": "DPoP",
                "expires_in": 300,
            }
        ).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None


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


def _transient_invalid_grant_then_success(access_token: str):
    state = {"calls": 0}

    def _fake_urlopen(_request, timeout):
        state["calls"] += 1
        if state["calls"] == 1:
            raise _invalid_grant_http_error()
        return _SuccessResponse(access_token)

    return _fake_urlopen, state


def test_transient_invalid_grant_does_not_wipe_sign_in_via_daemon_repair(tmp_path, monkeypatch) -> None:
    """One flaky invalid_grant must not delete local OAuth credentials."""
    store = _store_with_oauth_credentials(tmp_path)
    _fake_urlopen, state = _transient_invalid_grant_then_success("access-token-2")
    stub_authenticated_urlopen(monkeypatch, _fake_urlopen)
    _allow_refresh(monkeypatch)

    repair = guard_runner_module.repair_guard_cloud_connect_storage(store)

    assert repair["cleared_stale_sign_in"] is False
    assert repair["existing_sign_in_valid"] is True
    assert store.get_oauth_local_credentials(allow_primary=True) is not None
    assert state["calls"] == 0


def test_sync_auth_context_recovers_from_transient_invalid_grant(tmp_path, monkeypatch) -> None:
    """A single invalid_grant hiccup must be retried, not surfaced as auth-expired."""
    store = _store_with_oauth_credentials(tmp_path)
    _fake_urlopen, state = _transient_invalid_grant_then_success("access-token-2")
    stub_authenticated_urlopen(monkeypatch, _fake_urlopen)
    _allow_refresh(monkeypatch)

    auth_context = guard_runner_module._resolve_guard_sync_auth_context(store)

    assert auth_context["access_token"] == "access-token-2"
    assert state["calls"] >= 2


def test_persistent_invalid_grant_still_clears_sign_in(tmp_path, monkeypatch) -> None:
    """Genuinely revoked grants must still be cleared on the reconnect pre-check path after bounded refresh retries."""
    store = _store_with_oauth_credentials(tmp_path)
    calls = {"count": 0}

    def _always_invalid_grant(_request, timeout):
        calls["count"] += 1
        raise _invalid_grant_http_error()

    stub_authenticated_urlopen(monkeypatch, _always_invalid_grant)
    _allow_refresh(monkeypatch)

    repair = guard_runner_module.prepare_guard_cloud_connect_authorization(store)

    assert repair["cleared_stale_sign_in"] is True
    assert store.get_oauth_local_credentials(allow_primary=True) is None
    assert calls["count"] == 2


def test_sync_auth_context_raises_after_persistent_invalid_grant(tmp_path, monkeypatch) -> None:
    store = _store_with_oauth_credentials(tmp_path)

    def _always_invalid_grant(_request, timeout):
        raise _invalid_grant_http_error()

    stub_authenticated_urlopen(monkeypatch, _always_invalid_grant)
    _allow_refresh(monkeypatch)

    with pytest.raises(guard_runner_module.GuardSyncAuthorizationExpiredError):
        guard_runner_module._resolve_guard_sync_auth_context(store)


def test_invalid_grant_retry_uses_reloaded_credentials(tmp_path, monkeypatch) -> None:
    """Refresh retry must read rotated credentials persisted by another process."""
    store = _store_with_oauth_credentials(tmp_path)
    seen_tokens: list[str] = []

    def _fake_urlopen(_request, timeout):
        form = dict(urllib.parse.parse_qsl(_request.data.decode("utf-8")))
        seen_tokens.append(form["refresh_token"])
        if len(seen_tokens) == 1:
            raise _invalid_grant_http_error()
        return _SuccessResponse("access-token-3")

    stub_authenticated_urlopen(monkeypatch, _fake_urlopen)
    _allow_refresh(monkeypatch)

    # Simulate peer-process rotation between attempts: change stored refresh token.
    initial = store.get_oauth_local_credentials(allow_primary=True)
    assert initial is not None
    initial["refresh_token"] = "refresh-token-2"
    # Patch store read used by the reloader to return the rotated credentials.
    original_get = GuardStore.get_oauth_local_credentials

    def _patched_get(self, *args, **kwargs):
        if self is store:
            return initial
        return original_get(self, *args, **kwargs)

    monkeypatch.setattr(GuardStore, "get_oauth_local_credentials", _patched_get)

    refreshed = guard_runner_module._refresh_guard_oauth_access_token(
        token_endpoint="https://hol.org/api/guard/oauth/token",
        client_id="guard-local-daemon",
        refresh_token="refresh-token-1",
        dpop_key_material=guard_runner_module._oauth_dpop_key_material(initial),
        credential_reloader=lambda: (
            initial["refresh_token"],
            guard_runner_module._oauth_dpop_key_material(initial),
        ),
    )

    assert refreshed["access_token"] == "access-token-3"
    assert seen_tokens == ["refresh-token-1", "refresh-token-2"]


def test_invalid_grant_retry_persists_and_returns_effective_credentials(tmp_path, monkeypatch) -> None:
    """After reloader swaps credentials mid-retry, persistence + return MUST use the newer snapshot.

    CodeRabbit #2714: before this fix the resolver persisted `oauth_credentials`
    (stale dpop_key) and returned `dpop_key_material` (stale), even when the
    reloader supplied newer material on the retry leg — leaving signed sync
    requests with an outdated key after peer rotation.
    """
    store = _store_with_oauth_credentials(tmp_path)
    initial = store.get_oauth_local_credentials(allow_primary=True)
    assert initial is not None
    initial_dpop = guard_runner_module._oauth_dpop_key_material(initial)
    seen_tokens: list[str] = []

    def _fake_urlopen(_request, timeout):
        form = dict(urllib.parse.parse_qsl(_request.data.decode("utf-8")))
        seen_tokens.append(form["refresh_token"])
        if len(seen_tokens) == 1:
            raise _invalid_grant_http_error()
        return _SuccessResponse("access-token-3")

    stub_authenticated_urlopen(monkeypatch, _fake_urlopen)
    _allow_refresh(monkeypatch)

    rotated = dict(initial)
    rotated["refresh_token"] = "refresh-token-2"
    rotated_dpop_pair = generate_dpop_key_pair()
    rotated["dpop_private_key_pem"] = rotated_dpop_pair.private_key_pem
    rotated["dpop_public_jwk"] = rotated_dpop_pair.public_jwk
    rotated["dpop_public_jwk_thumbprint"] = rotated_dpop_pair.public_jwk_thumbprint
    rotated_dpop = guard_runner_module._oauth_dpop_key_material(rotated)
    original_get = GuardStore.get_oauth_local_credentials
    call_count = {"n": 0}

    def _patched_get(self, *args, **kwargs):
        # The reloader's reads mimic a peer having rotated credentials in the
        # store between the first (failed) and second (successful) attempts.
        if self is store:
            call_count["n"] += 1
            return rotated
        return original_get(self, *args, **kwargs)

    monkeypatch.setattr(GuardStore, "get_oauth_local_credentials", _patched_get)

    context = guard_runner_module._resolve_guard_sync_auth_context_from_oauth_credentials(
        store,
        initial,
        force_refresh=True,
        persist_recovered_secret=False,
    )

    # Return context must carry the reloaded DPoP material (used to sign
    # subsequent sync requests). dataclass — compare by value, not identity.
    actual = context["dpop_key_material"]
    assert actual == rotated_dpop
    assert actual != initial_dpop

    # Persistence must record the rotated credentials, not the stale initial.
    monkeypatch.setattr(GuardStore, "get_oauth_local_credentials", original_get)
    persisted = original_get(store, allow_primary=True)
    assert persisted is not None
    # `_persist_rotated_oauth_refresh_token` stamps the new refresh_token from
    # the refresh response over whichever credentials dict it received — so
    # the persisted dict MUST be derived from `rotated`, not `initial`.
    assert persisted.get("dpop_private_key_pem") == rotated.get("dpop_private_key_pem")
    assert persisted.get("dpop_public_jwk_thumbprint") == rotated.get("dpop_public_jwk_thumbprint")
    assert seen_tokens == ["refresh-token-1", "refresh-token-2"]
