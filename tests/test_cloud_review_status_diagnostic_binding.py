"""Passive status cannot disclose worker history from an unscoped queue."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from codex_plugin_scanner.guard.runtime.cloud_review_status import cloud_review_status
from codex_plugin_scanner.guard.runtime.exact_cloud_review import enable_exact_cloud_review
from tests.guard_exact_cloud_review_support import connected_exact_review_store
from tests.test_cloud_review_status_readiness import _observation
from tests.test_cloud_review_status_storage import _snapshot


@pytest.mark.parametrize("evidence", ["disconnected", "missing", "source", "binding", "stale", "current"])
def test_worker_diagnostics_never_inherit_unscoped_queue_history(tmp_path, evidence):
    store = connected_exact_review_store(tmp_path)
    enable_exact_cloud_review(store)
    store.set_sync_payload(
        "guard_command_queue_state",
        {
            "last_error": "foreign-worker-error-canary",
            "exact_review_route_error": "foreign-route-error-canary",
            "last_poll_at": "2026-01-01T00:00:00Z",
            "last_result_at": "2026-01-01T00:00:01Z",
            "state": "foreign-state-canary",
        },
        "2026-01-01T00:00:00Z",
    )
    now = datetime.now(timezone.utc)
    observation = _observation(store, now)
    source = "unconnected-profile" if evidence == "disconnected" else "default"
    if evidence == "missing":
        observation = None
    elif evidence == "source":
        observation["source"] = "other-profile"
    elif evidence == "binding":
        observation["connection_binding_id"] = "sha256:" + "0" * 64
    elif evidence == "stale":
        observation["observed_at"] = (now - timedelta(seconds=6)).isoformat()
    before = _snapshot(store)

    result = cloud_review_status(store.guard_home, source=source, worker_observation=observation, now=now)

    assert _snapshot(store) == before
    assert result["connected"] is (evidence != "disconnected")
    assert result["delivery_ready"] is (
        True if evidence == "current" else False if evidence == "disconnected" else None
    )
    assert result["worker"]["running"] is (True if evidence == "current" else None)
    assert result["diagnostics"]["worker"] == {
        "last_delivery_error": None,
        "exact_review_route_error": None,
        "last_poll_at": None,
        "last_result_at": None,
        "state": "unavailable",
    }
    assert "foreign-" not in json.dumps(result)
    assert "2026-01-01" not in json.dumps(result)


@pytest.mark.parametrize("state", ["idle", "error"])
@pytest.mark.parametrize("switch_account", [False, True])
def test_delivery_state_requires_current_attempt_identity_not_last_delivery(tmp_path, state, switch_account):
    from tests.guard_oauth_token_support import oauth_binding_access_token

    store = connected_exact_review_store(tmp_path)
    binding = store.get_review_event_oauth_binding()
    delivery_binding = {key: value for key, value in binding.items() if key != "oauth_source"}
    delivered_at = "2026-01-01T00:00:00Z"
    store.set_sync_payload(
        "guard_cloud_review_sync_state",
        {
            "state": state,
            "last_error": "foreign-attempt-error-canary",
            "last_delivery_at": delivered_at,
            "last_delivery_binding": delivery_binding,
        },
        delivered_at,
    )
    if switch_account:
        credentials = store.get_oauth_local_credentials()
        replacement = {
            key: credentials[key]
            for key in (
                "issuer",
                "client_id",
                "refresh_token",
                "dpop_private_key_pem",
                "dpop_public_jwk",
                "dpop_public_jwk_thumbprint",
                "machine_id",
                "device_id",
                "workspace_id",
                "runtime_id",
                "access_token_expires_at",
            )
        }
        replacement["grant_id"] = "replacement-grant"
        replacement["access_token"] = oauth_binding_access_token(
            device_id=replacement["device_id"],
            grant_id="replacement-grant",
            machine_id=replacement["machine_id"],
            workspace_id=replacement["workspace_id"],
        )
        store.set_oauth_local_credentials(**replacement, now=datetime.now(timezone.utc).isoformat())
        assert store.get_review_event_oauth_binding() != binding
    before = _snapshot(store)

    status = cloud_review_status(store)

    assert _snapshot(store) == before
    assert status["connected"] is True
    assert status["delivery_state"] == "unknown"
    assert status["last_synced_at"] == (None if switch_account else delivered_at)
    assert "foreign-attempt" not in json.dumps(status)
