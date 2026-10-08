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
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime

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


def _rate_limited_http_error(retry_after: str) -> urllib.error.HTTPError:
    import email.message

    class _ErrorResponse:
        def read(self) -> bytes:
            return json.dumps(
                {
                    "error": "invalid_grant",
                    "error_description": "Refresh token is not recognized; re-authorize the client.",
                }
            ).encode("utf-8")

        def close(self) -> None:
            return None

    headers = email.message.Message()
    headers["Retry-After"] = retry_after
    return urllib.error.HTTPError(
        "https://hol.org/api/guard/oauth/token",
        429,
        "Too Many Requests",
        hdrs=headers,
        fp=_ErrorResponse(),
    )


def _oauth_circuit_state(store: GuardStore) -> dict[str, object]:
    payload = store.get_sync_payload("guard_oauth_refresh_circuit")
    assert isinstance(payload, dict)
    return payload


def test_dead_grant_marks_needs_reauthorization_and_stops_refresh(tmp_path, monkeypatch) -> None:
    """Two invalid_grant responses flip the binding to needs-reauthorization.

    After that, every caller must fast-fail locally — no third token request —
    and exactly one notification is delivered through the existing path.
    """
    store = _store_with_oauth_credentials(tmp_path)
    calls = {"count": 0}

    def _always_invalid_grant(_request, timeout):
        calls["count"] += 1
        raise _invalid_grant_http_error()

    stub_authenticated_urlopen(monkeypatch, _always_invalid_grant)
    _allow_refresh(monkeypatch)
    notifications: list[object] = []
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.desktop_notifications.notify_pending_approval_once",
        lambda notification: notifications.append(notification) or True,
    )

    with pytest.raises(guard_runner_module.GuardSyncAuthorizationExpiredError):
        guard_runner_module._resolve_guard_sync_auth_context(store)
    assert calls["count"] == 2

    state = _oauth_circuit_state(store)
    assert state["needs_reauthorization"] is True
    assert state["notice_sent"] is True
    assert state["consecutive_failures"] == 1
    assert len(notifications) == 1
    next_allowed = guard_runner_module._parse_iso_timestamp(str(state["next_refresh_allowed_at"]))
    assert next_allowed is not None

    with pytest.raises(guard_runner_module.GuardSyncAuthorizationExpiredError):
        guard_runner_module._resolve_guard_sync_auth_context(store)
    with pytest.raises(guard_runner_module.GuardSyncAuthorizationExpiredError):
        guard_runner_module._resolve_guard_sync_auth_context(store)
    assert calls["count"] == 2
    assert len(notifications) == 1


def test_circuit_probe_extends_backoff_geometrically(tmp_path, monkeypatch) -> None:
    """Each failed probe doubles the backoff, and the notice is sent once."""
    store = _store_with_oauth_credentials(tmp_path)
    credentials = store.get_oauth_local_credentials(allow_primary=True)
    assert credentials is not None
    fingerprint = guard_runner_module._oauth_refresh_circuit_fingerprint(
        str(credentials["refresh_token"]),
        guard_runner_module._oauth_refresh_circuit_salt(store),
    )
    past = "2026-06-01T00:00:00+00:00"
    store.set_sync_payload(
        "guard_oauth_refresh_circuit",
        {
            "refresh_token_fingerprint": fingerprint,
            "consecutive_failures": 1,
            "needs_reauthorization": True,
            "notice_sent": True,
            "backoff_seconds": 30.0,
            "next_refresh_allowed_at": past,
            "last_error_at": past,
        },
        past,
    )
    calls = {"count": 0}

    def _always_invalid_grant(_request, timeout):
        calls["count"] += 1
        raise _invalid_grant_http_error()

    stub_authenticated_urlopen(monkeypatch, _always_invalid_grant)
    _allow_refresh(monkeypatch)
    notifications: list[object] = []
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.desktop_notifications.notify_pending_approval_once",
        lambda notification: notifications.append(notification) or True,
    )

    with pytest.raises(guard_runner_module.GuardSyncAuthorizationExpiredError):
        guard_runner_module._resolve_guard_sync_auth_context(store)

    assert calls["count"] == 2
    state = _oauth_circuit_state(store)
    assert state["consecutive_failures"] == 2
    assert state["backoff_seconds"] == 60.0
    assert len(notifications) == 0

    with pytest.raises(guard_runner_module.GuardSyncAuthorizationExpiredError):
        guard_runner_module._resolve_guard_sync_auth_context(store)
    assert calls["count"] == 2


def test_rate_limited_refresh_honors_retry_after(tmp_path, monkeypatch) -> None:
    """A 429 from the token endpoint parks refresh attempts for Retry-After."""
    store = _store_with_oauth_credentials(tmp_path)
    calls = {"count": 0}

    def _always_rate_limited(_request, timeout):
        calls["count"] += 1
        raise _rate_limited_http_error("120")

    stub_authenticated_urlopen(monkeypatch, _always_rate_limited)
    _allow_refresh(monkeypatch)

    with pytest.raises(RuntimeError, match="rate limited"):
        guard_runner_module._resolve_guard_sync_auth_context(store)
    assert calls["count"] == 1

    state = _oauth_circuit_state(store)
    assert state["needs_reauthorization"] is False
    next_allowed = guard_runner_module._parse_iso_timestamp(str(state["next_refresh_allowed_at"]))
    assert next_allowed is not None
    assert (next_allowed - datetime.now(timezone.utc)).total_seconds() > 60

    with pytest.raises(RuntimeError, match="rate limited"):
        guard_runner_module._resolve_guard_sync_auth_context(store)
    assert calls["count"] == 1


def test_rate_limited_refresh_honors_http_date_retry_after(tmp_path, monkeypatch) -> None:
    """An HTTP-date Retry-After header parks refresh for the requested delay."""
    store = _store_with_oauth_credentials(tmp_path)
    calls = {"count": 0}
    http_date = format_datetime(datetime.now(timezone.utc) + timedelta(seconds=120), usegmt=True)

    def _always_rate_limited(_request, timeout):
        calls["count"] += 1
        raise _rate_limited_http_error(http_date)

    stub_authenticated_urlopen(monkeypatch, _always_rate_limited)
    _allow_refresh(monkeypatch)

    with pytest.raises(RuntimeError, match="rate limited"):
        guard_runner_module._resolve_guard_sync_auth_context(store)
    assert calls["count"] == 1

    state = _oauth_circuit_state(store)
    assert int(str(state["backoff_seconds"])) > 60


def test_rate_limited_refresh_respects_long_server_retry_after(tmp_path, monkeypatch) -> None:
    """A server Retry-After beyond the dead-grant cap is honored, not truncated."""
    store = _store_with_oauth_credentials(tmp_path)

    def _always_rate_limited(_request, timeout):
        raise _rate_limited_http_error("900")

    stub_authenticated_urlopen(monkeypatch, _always_rate_limited)
    _allow_refresh(monkeypatch)

    with pytest.raises(RuntimeError, match="rate limited"):
        guard_runner_module._resolve_guard_sync_auth_context(store)

    state = _oauth_circuit_state(store)
    assert state["backoff_seconds"] == 900


def test_rate_limit_circuit_fingerprints_reloaded_token(tmp_path, monkeypatch) -> None:
    """A 429 on a peer-reloaded refresh token records that token's fingerprint."""
    store = _store_with_oauth_credentials(tmp_path)
    initial = store.get_oauth_local_credentials(allow_primary=True)
    assert initial is not None
    rotated = dict(initial)
    rotated["refresh_token"] = "refresh-token-2"

    seen_tokens: list[str] = []

    def _fake_urlopen(_request, timeout):
        form = dict(urllib.parse.parse_qsl(_request.data.decode("utf-8")))
        seen_tokens.append(form["refresh_token"])
        if len(seen_tokens) == 1:
            raise _invalid_grant_http_error()
        raise _rate_limited_http_error("120")

    stub_authenticated_urlopen(monkeypatch, _fake_urlopen)
    _allow_refresh(monkeypatch)

    original_get = GuardStore.get_oauth_local_credentials

    def _patched_get(self, *args, **kwargs):
        if self is store:
            return rotated
        return original_get(self, *args, **kwargs)

    monkeypatch.setattr(GuardStore, "get_oauth_local_credentials", _patched_get)

    with pytest.raises(RuntimeError, match="rate limited"):
        guard_runner_module._resolve_guard_sync_auth_context_from_oauth_credentials(
            store,
            initial,
            force_refresh=True,
            persist_recovered_secret=False,
        )

    assert seen_tokens == ["refresh-token-1", "refresh-token-2"]
    state = _oauth_circuit_state(store)
    assert state["refresh_token_fingerprint"] == guard_runner_module._oauth_refresh_circuit_fingerprint(
        "refresh-token-2", guard_runner_module._oauth_refresh_circuit_salt(store)
    )


def test_fresh_peer_credentials_clear_needs_reauthorization(tmp_path, monkeypatch) -> None:
    """A peer that re-paired (new refresh token) clears the circuit on sight."""
    store = _store_with_oauth_credentials(tmp_path)
    calls = {"count": 0}

    def _invalid_grant_then_success(_request, timeout):
        calls["count"] += 1
        if calls["count"] <= 2:
            raise _invalid_grant_http_error()
        return _SuccessResponse("access-token-5")

    stub_authenticated_urlopen(monkeypatch, _invalid_grant_then_success)
    _allow_refresh(monkeypatch)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.desktop_notifications.notify_pending_approval_once",
        lambda notification: True,
    )

    with pytest.raises(guard_runner_module.GuardSyncAuthorizationExpiredError):
        guard_runner_module._resolve_guard_sync_auth_context(store)
    assert calls["count"] == 2
    assert _oauth_circuit_state(store)["needs_reauthorization"] is True

    # A peer process re-pairs: the stored refresh token changes under the lock.
    credentials = store.get_oauth_local_credentials(allow_primary=True)
    assert credentials is not None
    store.set_oauth_local_credentials(
        issuer=str(credentials["issuer"]),
        client_id=str(credentials["client_id"]),
        refresh_token="refresh-token-2",
        dpop_private_key_pem=str(credentials["dpop_private_key_pem"]),
        dpop_public_jwk=credentials["dpop_public_jwk"],
        dpop_public_jwk_thumbprint=str(credentials["dpop_public_jwk_thumbprint"]),
        grant_id=str(credentials["grant_id"]),
        machine_id=str(credentials["machine_id"]),
        workspace_id=str(credentials["workspace_id"]),
        now="2026-06-01T00:05:00+00:00",
    )

    auth_context = guard_runner_module._resolve_guard_sync_auth_context(store, force_refresh=True)
    assert auth_context["access_token"] == "access-token-5"
    assert calls["count"] == 3
    assert "needs_reauthorization" not in _oauth_circuit_state(store)


def test_profile_fallback_uses_effective_credentials_after_peer_reload(tmp_path, monkeypatch) -> None:
    """Peer-rotated credentials carrying a newer cloud_user_profile must not be
    overwritten by the resolver's stale local snapshot when the refresh
    response has neither an entitlement nor a profile."""
    store = _store_with_oauth_credentials(tmp_path)
    initial = store.get_oauth_local_credentials(allow_primary=True)
    assert initial is not None
    initial["cloud_user_profile"] = {"name": "stale"}

    rotated = dict(initial)
    rotated["refresh_token"] = "refresh-token-2"
    rotated["cloud_user_profile"] = {"name": "fresh-peer"}

    seen_tokens: list[str] = []

    class _ProfileLessResponse:
        def read(self) -> bytes:
            return json.dumps(
                {
                    "access_token": "access-token-9",
                    "token_type": "DPoP",
                    "expires_in": 300,
                }
            ).encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb) -> None:
            return None

    def _fake_urlopen(_request, timeout):
        form = dict(urllib.parse.parse_qsl(_request.data.decode("utf-8")))
        seen_tokens.append(form["refresh_token"])
        if len(seen_tokens) == 1:
            raise _invalid_grant_http_error()
        return _ProfileLessResponse()

    stub_authenticated_urlopen(monkeypatch, _fake_urlopen)
    _allow_refresh(monkeypatch)

    original_get = GuardStore.get_oauth_local_credentials

    def _patched_get(self, *args, **kwargs):
        if self is store:
            return rotated
        return original_get(self, *args, **kwargs)

    monkeypatch.setattr(GuardStore, "get_oauth_local_credentials", _patched_get)

    context = guard_runner_module._resolve_guard_sync_auth_context_from_oauth_credentials(
        store,
        initial,
        force_refresh=True,
        persist_recovered_secret=False,
    )

    assert context["access_token"] == "access-token-9"

    monkeypatch.setattr(GuardStore, "get_oauth_local_credentials", original_get)
    persisted = original_get(store, allow_primary=True)
    assert persisted is not None
    assert persisted.get("cloud_user_profile") == {"name": "fresh-peer"}
    assert seen_tokens == ["refresh-token-1", "refresh-token-2"]
