"""HGP-164: Cloud Review CLI readiness requires both workers."""

from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli import commands_dispatch_cloud_review as cloud_review_dispatch
from codex_plugin_scanner.guard.runtime.cloud_review_worker_readiness import project_cloud_review_worker_refresh
from tests.guard_exact_cloud_review_support import connected_exact_review_store


def test_busy_daemon_is_saved_not_enabled(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = connected_exact_review_store(tmp_path)
    monkeypatch.setattr(
        cloud_review_dispatch,
        "_refresh_cloud_review_worker",
        lambda _guard_home: {"status": "refreshed", "running": False, "sync_running": False},
    )
    connected = cloud_review_dispatch.apply_connect_time_cloud_review_consent(
        args=argparse.Namespace(enable_cloud_review=True),
        store=store,
        guard_home=store.guard_home,
        payload={"status": "connected"},
        exit_code=0,
    )
    cloud_review = connected["cloud_review"]
    assert cloud_review["capability_enabled"] is True
    assert cloud_review["enabled"] is False
    assert cloud_review["reason"] == "worker_retry_required"
    assert cloud_review["activation_status"] == "saved_retry_required"


def test_both_workers_running_are_ready() -> None:
    projection = project_cloud_review_worker_refresh({"status": "refreshed", "running": True, "sync_running": True})
    assert projection["enabled"] is True
    assert projection["delivery_ready"] is True
    assert projection["reason"] is None


def test_partial_worker_is_not_ready() -> None:
    projection = project_cloud_review_worker_refresh({"status": "refreshed", "running": True, "sync_running": False})
    assert projection["enabled"] is False
    assert projection["capability_saved"] is True
