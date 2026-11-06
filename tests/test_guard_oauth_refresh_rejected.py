"""Regression tests: a rejected refresh request must park refresh without wiping sign-in.

A daemon whose refresh request the token endpoint rejects with an error other
than `invalid_grant` (for example `invalid_request`) used to skip the refresh
circuit, so every sync, poll and hook caller retried the token endpoint at once.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from codex_plugin_scanner.guard.runtime import runner as guard_runner_module
from tests.support.network import stub_authenticated_urlopen
from tests.test_guard_oauth_refresh_resilience import (
    _allow_refresh,
    _oauth_circuit_state,
    _oauth_error_http_error,
    _store_with_oauth_credentials,
)


def _invalid_request_http_error():
    return _oauth_error_http_error("invalid_request", "The authorization request is incomplete or malformed.")


def _count_rejected_requests(monkeypatch: pytest.MonkeyPatch) -> dict[str, int]:
    calls = {"count": 0}

    def _always_invalid_request(_request, timeout):
        calls["count"] += 1
        raise _invalid_request_http_error()

    stub_authenticated_urlopen(monkeypatch, _always_invalid_request)
    _allow_refresh(monkeypatch)
    return calls


def _record_notifications(monkeypatch: pytest.MonkeyPatch) -> list[object]:
    notifications: list[object] = []
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.desktop_notifications.notify_pending_approval_once",
        lambda notification: notifications.append(notification) or True,
    )
    return notifications


def _expire_circuit_backoff(store) -> None:
    state = _oauth_circuit_state(store)
    state["next_refresh_allowed_at"] = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
    store.set_sync_payload("guard_oauth_refresh_circuit", state, guard_runner_module._now())


def test_rejected_refresh_request_backs_off_without_wiping_sign_in(tmp_path, monkeypatch) -> None:
    """The fast-fail keeps the reauthorization error, so sign-in cleanup keeps the credentials."""
    store = _store_with_oauth_credentials(tmp_path)
    calls = _count_rejected_requests(monkeypatch)
    notifications = _record_notifications(monkeypatch)

    with pytest.raises(guard_runner_module.GuardSyncAuthorizationExpiredError):
        guard_runner_module._resolve_guard_sync_auth_context(store)
    assert calls["count"] == 1

    state = _oauth_circuit_state(store)
    assert state["needs_reauthorization"] is True
    assert state["failure_kind"] == "rejected"
    assert notifications == []

    for _ in range(3):
        with pytest.raises(guard_runner_module.GuardSyncAuthorizationExpiredError) as error:
            guard_runner_module._resolve_guard_sync_auth_context(store)
        assert str(error.value) != guard_runner_module._guard_oauth_reconnect_after_revoked_message()
    assert calls["count"] == 1

    assert guard_runner_module.clear_revoked_guard_oauth_sign_in(store) is False
    assert store.get_oauth_local_credentials(allow_primary=True) is not None
    assert calls["count"] == 1


def test_rejected_refresh_notifies_after_the_next_probe_is_rejected(tmp_path, monkeypatch) -> None:
    store = _store_with_oauth_credentials(tmp_path)
    calls = _count_rejected_requests(monkeypatch)
    notifications = _record_notifications(monkeypatch)

    with pytest.raises(guard_runner_module.GuardSyncAuthorizationExpiredError):
        guard_runner_module._resolve_guard_sync_auth_context(store)
    assert notifications == []

    _expire_circuit_backoff(store)
    with pytest.raises(guard_runner_module.GuardSyncAuthorizationExpiredError):
        guard_runner_module._resolve_guard_sync_auth_context(store)
    assert calls["count"] == 2
    assert len(notifications) == 1
    assert _oauth_circuit_state(store)["notice_sent"] is True


def test_rate_limit_keeps_rejected_failure_kind(tmp_path, monkeypatch) -> None:
    """A 429 during a rejected backoff must not turn the state into a revoked grant."""
    store = _store_with_oauth_credentials(tmp_path)
    _count_rejected_requests(monkeypatch)
    _record_notifications(monkeypatch)

    with pytest.raises(guard_runner_module.GuardSyncAuthorizationExpiredError):
        guard_runner_module._resolve_guard_sync_auth_context(store)
    guard_runner_module._oauth_refresh_circuit_record_rate_limit(
        store=store,
        refresh_token="refresh-token-1",
        retry_after_seconds=60,
        now=datetime.now(timezone.utc),
    )

    state = _oauth_circuit_state(store)
    assert state["failure_kind"] == "rejected"
    assert state["needs_reauthorization"] is True
    with pytest.raises(guard_runner_module.GuardSyncAuthorizationExpiredError) as error:
        guard_runner_module._resolve_guard_sync_auth_context(store)
    assert str(error.value) != guard_runner_module._guard_oauth_reconnect_after_revoked_message()
    assert guard_runner_module.clear_revoked_guard_oauth_sign_in(store) is False


def test_local_dpop_signing_failure_does_not_park_refresh(tmp_path, monkeypatch) -> None:
    store = _store_with_oauth_credentials(tmp_path)
    calls = _count_rejected_requests(monkeypatch)

    def _broken_signer(**_kwargs):
        raise ValueError("signing key unavailable")

    monkeypatch.setattr(guard_runner_module, "_sign_guard_dpop_proof", _broken_signer)

    with pytest.raises(guard_runner_module.GuardSyncAuthorizationExpiredError):
        guard_runner_module._resolve_guard_sync_auth_context(store)
    assert calls["count"] == 0
    assert store.get_sync_payload("guard_oauth_refresh_circuit") is None
