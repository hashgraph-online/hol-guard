"""Unused expiry input cannot prevent recovery of valid existing consent."""

from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.cli import commands_dispatch_cloud_review as cli
from codex_plugin_scanner.guard.runtime.exact_cloud_review import (
    EXACT_CLOUD_REVIEW_CAPABILITY_STATE_KEY,
    enable_exact_cloud_review,
)
from tests.guard_exact_cloud_review_support import connected_exact_review_store


@pytest.mark.parametrize("days", [0, 366])
def test_valid_consent_delivery_retry_ignores_unused_expiry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], days: int
) -> None:
    store = connected_exact_review_store(tmp_path)
    enable_exact_cloud_review(store)
    original = store.get_sync_payload(EXACT_CLOUD_REVIEW_CAPABILITY_STATE_KEY)
    refreshed: list[Path] = []

    def refresh(home: Path) -> dict[str, object]:
        refreshed.append(home)
        return {"status": "refreshed", "running": True, "sync_running": True}

    monkeypatch.setattr(cli, "_refresh_cloud_review_worker", refresh)
    result = cli._run_guard_cloud_review_command(
        argparse.Namespace(cloud_review_command="enable", expires_in_days=days, renew=False, json=True),
        guard_home=store.guard_home,
        store=store,
    )
    assert result == 0
    assert refreshed == [store.guard_home]
    assert store.get_sync_payload(EXACT_CLOUD_REVIEW_CAPABILITY_STATE_KEY) == original
    capsys.readouterr()


@pytest.mark.parametrize("days", [0, 366])
@pytest.mark.parametrize("renew", [False, True])
def test_new_or_explicitly_renewed_consent_still_requires_valid_expiry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    days: int,
    renew: bool,
) -> None:
    store = connected_exact_review_store(tmp_path)
    if renew:
        enable_exact_cloud_review(store)
    original = store.get_sync_payload(EXACT_CLOUD_REVIEW_CAPABILITY_STATE_KEY)

    def unexpected_refresh(_home: Path) -> dict[str, object]:
        pytest.fail("Invalid new consent must not activate delivery")

    monkeypatch.setattr(cli, "_refresh_cloud_review_worker", unexpected_refresh)
    result = cli._run_guard_cloud_review_command(
        argparse.Namespace(cloud_review_command="enable", expires_in_days=days, renew=renew, json=True),
        guard_home=store.guard_home,
        store=store,
    )
    assert result == 2
    assert "cloud_review_capability_ttl_invalid" in capsys.readouterr().out
    assert store.get_sync_payload(EXACT_CLOUD_REVIEW_CAPABILITY_STATE_KEY) == original
