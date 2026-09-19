"""HGP-166: enable/disable lifecycle converges without erasing policy."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.daemon.cloud_review_settings import (
    change_cloud_review_settings,
    cloud_review_settings_status,
)
from codex_plugin_scanner.guard.models import PolicyDecision
from codex_plugin_scanner.guard.runtime.exact_cloud_review import (
    disable_exact_cloud_review,
    enable_exact_cloud_review,
    exact_cloud_review_status,
)
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_exact_cloud_review_support import connected_exact_review_store
from tests.test_guard_cloud_review_settings import _payload, _refresh


def test_enable_disable_survives_restart_and_keeps_policy(tmp_path: Path) -> None:
    store = connected_exact_review_store(tmp_path)
    store.upsert_policy(
        PolicyDecision(
            harness="codex",
            scope="artifact",
            action="allow",
            artifact_id="codex:project:keep-me",
            reason="reusable",
            source="local",
        ),
        "2026-07-18T00:00:00Z",
    )
    enabled = change_cloud_review_settings(store, _payload(), refresh_workers=_refresh)
    assert enabled["enabled"] is True
    restarted = GuardStore(store.guard_home)
    assert cloud_review_settings_status(restarted)["enabled"] is True
    failed_workers = change_cloud_review_settings(
        restarted,
        _payload(),
        refresh_workers=lambda: {"running": False, "sync_running": False},
    )
    assert failed_workers["enabled"] is True
    assert failed_workers["activation_error"] == "worker_refresh_failed"
    disable_exact_cloud_review(restarted)
    assert exact_cloud_review_status(restarted)["enabled"] is False
    after = GuardStore(store.guard_home)
    assert after.list_policy_decisions()
    assert any(row["artifact_id"] == "codex:project:keep-me" for row in after.list_policy_decisions())


def test_repeated_enable_does_not_drop_consent(tmp_path: Path) -> None:
    store = connected_exact_review_store(tmp_path)
    first = enable_exact_cloud_review(store)
    second = enable_exact_cloud_review(store)
    assert first["operation"] == second["operation"]
    assert exact_cloud_review_status(store)["enabled"] is True
