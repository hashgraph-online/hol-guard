"""Cached OAuth expiry parsing stays stable across supported Python versions."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from codex_plugin_scanner.guard.cli.oauth_client import generate_dpop_key_pair
from codex_plugin_scanner.guard.runtime import runner
from codex_plugin_scanner.guard.store import GuardStore

_NOW = datetime(2026, 9, 18, 12, 0, 0, tzinfo=timezone.utc)
_FUTURE_Z = "2099-01-01T00:00:00Z"
_FUTURE_OFFSET = "2099-01-01T00:00:00+00:00"
_TOKEN = "synthetic-cached-access"


class _FixedDateTime(datetime):
    @classmethod
    def now(cls, tz=None):
        return _NOW.astimezone(tz) if tz is not None else _NOW.replace(tzinfo=None)


class _RefreshReached(RuntimeError):
    pass


def _credentials_store(tmp_path, expires_at):
    store = GuardStore(tmp_path / "guard-home")
    key = generate_dpop_key_pair()
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="synthetic-refresh",
        dpop_private_key_pem=key.private_key_pem,
        dpop_public_jwk=key.public_jwk,
        dpop_public_jwk_thumbprint=key.public_jwk_thumbprint,
        grant_id="synthetic-grant",
        machine_id=store.get_or_create_installation_id(),
        device_id=key.public_jwk_thumbprint,
        workspace_id="workspace-alpha",
        access_token=_TOKEN,
        access_token_expires_at=expires_at,
        now=_NOW.isoformat(),
    )
    credentials = store.get_oauth_local_credentials(allow_primary=True)
    assert credentials is not None
    assert credentials.get("access_token_expires_at") == expires_at
    return store, credentials, key


def _refresh_boundary(monkeypatch):
    calls = []
    failure = _RefreshReached("Refresh boundary reached before any network access.")

    def stop_refresh(**_kwargs):
        calls.append("refresh")
        raise failure

    # Scope the clock to this module; retain the interpreter's real ISO parser.
    monkeypatch.setattr(runner, "datetime", _FixedDateTime)
    # Do not replace authentication, issuer validation, DPoP parsing or cache logic.
    monkeypatch.setattr(runner, "_refresh_guard_oauth_access_token", stop_refresh)
    return calls, failure


@pytest.mark.parametrize(
    "expiry",
    [_FUTURE_Z, _FUTURE_OFFSET, "2026-09-18T12:01:01+00:00"],
    ids=["future-z", "future-offset", "outside-refresh-skew"],
)
def test_cached_access_token_accepts_equivalent_utc_expiry(expiry):
    assert runner._cached_oauth_access_token(
        {"access_token": _TOKEN, "access_token_expires_at": expiry}, now=_NOW
    ) == _TOKEN


@pytest.mark.parametrize(
    "expiry",
    [
        "not-a-timestamp",
        "2026-09-18T11:59:59+00:00",
        "2026-09-18T12:00:00+00:00",
        "2026-09-18T12:00:59+00:00",
        "2026-09-18T12:01:00+00:00",
        None,
    ],
    ids=["malformed", "expired", "expires-now", "inside-skew", "at-skew", "missing"],
)
def test_cached_access_token_keeps_expiry_and_skew_refusals(expiry):
    assert runner._cached_oauth_access_token(
        {"access_token": _TOKEN, "access_token_expires_at": expiry}, now=_NOW
    ) is None


@pytest.mark.parametrize("expiry", [_FUTURE_Z, _FUTURE_OFFSET], ids=["future-z", "future-offset"])
def test_real_oauth_resolver_uses_unexpired_cache_before_refresh(tmp_path, monkeypatch, expiry):
    store, credentials, key = _credentials_store(tmp_path, expiry)
    calls, _failure = _refresh_boundary(monkeypatch)

    context = runner._resolve_guard_sync_auth_context_from_oauth_credentials(store, credentials)

    assert context["access_token"] == _TOKEN
    assert context["sync_url"] == "https://hol.org/api/guard/receipts/sync"
    assert context["dpop_key_material"] == key
    assert calls == []
    persisted = store.get_oauth_local_credentials(allow_primary=True)
    assert persisted is not None
    assert persisted["access_token_expires_at"] == expiry
    assert persisted["workspace_id"] == credentials["workspace_id"]
    assert persisted["grant_id"] == credentials["grant_id"]


@pytest.mark.parametrize(
    "expiry,force_refresh",
    [
        ("not-a-timestamp", False),
        ("2026-09-18T11:59:59+00:00", False),
        ("2026-09-18T12:00:59+00:00", False),
        ("2026-09-18T12:01:00+00:00", False),
        (None, False),
        (_FUTURE_Z, True),
        (_FUTURE_OFFSET, True),
    ],
    ids=["malformed", "expired", "inside-skew", "at-skew", "missing", "force-z", "force-offset"],
)
def test_real_oauth_resolver_keeps_required_refresh_boundary(tmp_path, monkeypatch, expiry, force_refresh):
    store, credentials, _key = _credentials_store(tmp_path, expiry)
    calls, failure = _refresh_boundary(monkeypatch)

    with pytest.raises(_RefreshReached) as caught:
        runner._resolve_guard_sync_auth_context_from_oauth_credentials(
            store, credentials, force_refresh=force_refresh
        )

    assert caught.value is failure
    assert calls == ["refresh"]
