"""CLI and settings share read-only consent, connection and delivery evidence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli import commands_dispatch_cloud_review as cli
from codex_plugin_scanner.guard.daemon.cloud_review_settings import cloud_review_settings_status
from codex_plugin_scanner.guard.runtime.exact_cloud_review import (
    EXACT_CLOUD_REVIEW_CAPABILITY_STATE_KEY,
    EXACT_CLOUD_REVIEW_REVOCATION_STATE_KEY,
    enable_exact_cloud_review,
)
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_exact_cloud_review_support import add_review_request, connected_exact_review_store, review_request


def _cli_status(store: GuardStore, capsys: pytest.CaptureFixture[str]) -> dict[str, object]:
    assert (
        cli._run_guard_cloud_review_command(
            argparse.Namespace(cloud_review_command="status", json=True), guard_home=store.guard_home, store=store
        )
        == 0
    )
    return json.loads(capsys.readouterr().out)


@pytest.mark.parametrize("state", ["disconnected", "connected", "enabled", "recovery"])
def test_cli_and_settings_return_same_explicit_status(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], state: str
) -> None:
    store = GuardStore(tmp_path / "guard-home") if state == "disconnected" else connected_exact_review_store(tmp_path)
    if state in {"enabled", "recovery"}:
        enable_exact_cloud_review(store)
        add_review_request(store, review_request("pending-status"))
    if state == "recovery":
        store.set_sync_payload(
            "guard_cloud_review_settings_recovery",
            {"binding": store.get_review_event_oauth_binding(), "error": "pending_request_requeue_failed"},
            "2026-09-17T00:00:00Z",
        )

    local = _cli_status(store, capsys)
    dashboard = cloud_review_settings_status(store)

    for key in (
        "connected",
        "enabled",
        "consent_enabled",
        "delivery_ready",
        "reason",
        "expires_at",
        "workspace_id",
        "source",
        "pending_uploads",
        "held_events",
        "isolated_events",
        "activation_error",
        "recovery_state",
        "last_synced_at",
        "delivery_state",
    ):
        assert key in local and key in dashboard, key
        assert local[key] == dashboard[key], key
    assert local["connected"] is (state != "disconnected")
    assert local["consent_enabled"] is (state in {"enabled", "recovery"})
    if state == "enabled":
        assert local["delivery_ready"] is None
        assert local["delivery_readiness_reason"] == "worker_status_unavailable"
    else:
        assert local["delivery_ready"] is False
    assert "refresh-token" not in json.dumps(local)


def test_status_does_not_mutate_consent_when_connection_binding_drifts(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    store = connected_exact_review_store(tmp_path)
    enable_exact_cloud_review(store)
    consent = store.get_sync_payload(EXACT_CLOUD_REVIEW_CAPABILITY_STATE_KEY)
    credentials = store.get_sync_payload("oauth_local_credentials")
    credentials["grant_id"] = "changed-grant"
    store.set_sync_payload("oauth_local_credentials", credentials, "2026-09-17T00:00:00Z")
    before = store.get_sync_payload(EXACT_CLOUD_REVIEW_REVOCATION_STATE_KEY)
    events = store.list_events(event_name="cloud_review.exact_capability_revoked")

    result = _cli_status(store, capsys)
    settings = cloud_review_settings_status(store)

    assert result["enabled"] is False
    assert settings["enabled"] is False
    assert result["reason"] == "cloud_review_capability_binding_mismatch"
    assert store.get_sync_payload(EXACT_CLOUD_REVIEW_REVOCATION_STATE_KEY) == before
    assert store.get_sync_payload(EXACT_CLOUD_REVIEW_CAPABILITY_STATE_KEY) == consent
    assert store.list_events(event_name="cloud_review.exact_capability_revoked") == events


def test_cli_status_keeps_delivery_timestamp_bound_to_current_identity(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    store = connected_exact_review_store(tmp_path)
    enable_exact_cloud_review(store)
    binding = store.get_review_event_oauth_binding()
    wrong_binding = {key: value for key, value in binding.items() if key != "oauth_source"}
    wrong_binding["workspace_id"] = "other-workspace"
    store.set_sync_payload(
        "guard_cloud_review_sync_state",
        {"state": "idle", "last_delivery_at": "2026-09-17T00:00:00Z", "last_delivery_binding": wrong_binding},
        "2026-09-17T00:00:00Z",
    )

    status = _cli_status(store, capsys)

    assert "last_synced_at" in status
    assert status["last_synced_at"] is None
    assert status["delivery_ready"] is None


@pytest.mark.parametrize("enabled", [False, True])
def test_both_status_surfaces_leave_persisted_state_unchanged(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], enabled: bool
) -> None:
    store = connected_exact_review_store(tmp_path)
    if enabled:
        enable_exact_cloud_review(store)
    add_review_request(store, review_request("read-only-status"))
    with store._connect() as connection:
        before = tuple(connection.iterdump())

    _cli_status(store, capsys)
    cloud_review_settings_status(store)

    with store._connect() as connection:
        assert tuple(connection.iterdump()) == before
