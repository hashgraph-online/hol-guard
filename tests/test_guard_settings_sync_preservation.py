"""Regression tests for preserving existing cloud-sync configuration."""

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.config import update_guard_settings


def test_existing_cloud_sync_can_be_resubmitted_without_entitlement(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    update_guard_settings(
        guard_home,
        {"sync": True, "security_level": "balanced"},
        cloud_sync_entitled=True,
    )

    updated = update_guard_settings(
        guard_home,
        {"sync": True, "security_level": "strict"},
        cloud_sync_entitled=False,
    )

    assert updated.security_level == "strict"
    assert updated.sync is True


def test_existing_cloud_sync_allows_local_mode_change_without_entitlement(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    update_guard_settings(
        guard_home,
        {"sync": True, "mode": "enforce", "security_level": "balanced"},
        cloud_sync_entitled=True,
    )

    observing = update_guard_settings(
        guard_home,
        {"sync": True, "mode": "observe"},
        cloud_sync_entitled=False,
    )
    assert observing.mode == "observe"
    assert observing.sync is True

    enforcing = update_guard_settings(
        guard_home,
        {"sync": True, "mode": "enforce"},
        cloud_sync_entitled=False,
    )
    assert enforcing.mode == "enforce"
    assert enforcing.sync is True


def test_new_cloud_sync_still_requires_a_paid_plan(tmp_path: Path) -> None:
    guard_home = tmp_path / "guard-home"
    local = update_guard_settings(
        guard_home,
        {"mode": "enforce"},
        cloud_sync_entitled=False,
    )
    assert local.sync is False

    with pytest.raises(ValueError, match="Cloud sync requires a paid team plan"):
        update_guard_settings(
            guard_home,
            {"sync": True, "mode": "observe"},
            cloud_sync_entitled=False,
        )
