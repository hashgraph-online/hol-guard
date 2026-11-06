"""Regression tests for preserving existing cloud-sync configuration."""

from pathlib import Path

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
