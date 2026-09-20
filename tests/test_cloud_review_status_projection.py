"""HGP-165: CLI and settings share one Cloud Review status projection."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.daemon.cloud_review_settings import cloud_review_settings_status
from codex_plugin_scanner.guard.runtime.cloud_review_status import cloud_review_status
from tests.guard_exact_cloud_review_support import connected_exact_review_store


def test_cli_and_settings_share_connection_and_consent_states(tmp_path: Path) -> None:
    store = connected_exact_review_store(tmp_path)
    projected = cloud_review_status(store)
    settings = cloud_review_settings_status(store)
    for key in (
        "connected",
        "consent_enabled",
        "enabled",
        "reason",
        "workspace_id",
        "held_events",
        "isolated_events",
        "delivery_state",
    ):
        assert projected[key] == settings[key]
    assert projected["connected"] is True
    assert projected["enabled"] is False
    assert "policy_applied" not in projected
    assert projected["disconnected"] is False
