"""Saved consent does not imply that both delivery workers actually started."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli import commands_dispatch_cloud_review as cli
from codex_plugin_scanner.guard.runtime.exact_cloud_review import exact_cloud_review_status
from tests.guard_exact_cloud_review_support import connected_exact_review_store


@pytest.mark.parametrize(
    "workers", [{}, {"running": True}, {"sync_running": True}, {"running": True, "sync_running": False}]
)
def test_connect_reports_saved_consent_when_daemon_returns_incomplete_readiness(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, workers: dict[str, object]
) -> None:
    store = connected_exact_review_store(tmp_path)
    monkeypatch.setattr(cli, "_refresh_cloud_review_worker", lambda _home: {"status": "refreshed", **workers})
    result = cli.apply_connect_time_cloud_review_consent(
        args=argparse.Namespace(enable_cloud_review=True),
        store=store,
        guard_home=store.guard_home,
        payload={"status": "connected"},
        exit_code=0,
    )
    review = result["cloud_review"]
    assert isinstance(review, dict)
    assert review["capability_enabled"] is True
    assert review["enabled"] is False
    assert review["reason"] == "worker_retry_required"
    assert exact_cloud_review_status(store)["enabled"] is True


def test_cli_enable_returns_retry_required_when_sync_worker_is_stopped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    store = connected_exact_review_store(tmp_path)
    monkeypatch.setattr(
        cli,
        "_refresh_cloud_review_worker",
        lambda _home: {"status": "refreshed", "running": True, "sync_running": False},
    )
    result = cli._run_guard_cloud_review_command(
        argparse.Namespace(cloud_review_command="enable", expires_in_days=30, json=True),
        guard_home=store.guard_home,
        store=store,
    )
    payload = json.loads(capsys.readouterr().out)
    assert result == 2
    assert payload["status"] == "enabled_worker_retry_required"
    assert payload["capability_enabled"] is True
    assert payload["delivery_ready"] is False
    assert exact_cloud_review_status(store)["enabled"] is True


def test_connect_ready_requires_both_true_worker_booleans(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = connected_exact_review_store(tmp_path)
    monkeypatch.setattr(
        cli,
        "_refresh_cloud_review_worker",
        lambda _home: {"status": "refreshed", "running": True, "sync_running": True},
    )
    result = cli.apply_connect_time_cloud_review_consent(
        args=argparse.Namespace(enable_cloud_review=True),
        store=store,
        guard_home=store.guard_home,
        payload={"status": "connected"},
        exit_code=0,
    )
    review = result["cloud_review"]
    assert isinstance(review, dict)
    assert review["enabled"] is True
    assert review["reason"] is None
