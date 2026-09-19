"""HGP-182: local Cloud Review recovery actions are idempotent."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon.cloud_review_settings import (
    CloudReviewSettingsError,
    change_cloud_review_settings,
    cloud_review_settings_status,
)
from tests.guard_exact_cloud_review_support import connected_exact_review_store


def _payload(action: str = "enable", **changes: object) -> dict[str, object]:
    return {
        "action": action,
        "confirm": f"cloud-review.{action}",
        "workspace_id": "workspace-1",
        "source": "default",
        **changes,
    }


def _refresh_workers() -> dict[str, bool]:
    return {"running": True, "sync_running": True}


def test_double_enable_and_retry_delivery_reuse_valid_consent(tmp_path: Path) -> None:
    store = connected_exact_review_store(tmp_path)
    first = change_cloud_review_settings(store, _payload(), refresh_workers=_refresh_workers)
    nonce = store.get_sync_payload("guard_exact_cloud_review_capability")
    assert isinstance(nonce, dict)
    second = change_cloud_review_settings(store, _payload(), refresh_workers=_refresh_workers)
    reused = store.get_sync_payload("guard_exact_cloud_review_capability")
    assert isinstance(reused, dict)
    assert reused["nonce"] == nonce["nonce"]
    retried = change_cloud_review_settings(store, _payload("retry_delivery"), refresh_workers=_refresh_workers)
    still = store.get_sync_payload("guard_exact_cloud_review_capability")
    assert isinstance(still, dict)
    assert still["nonce"] == nonce["nonce"]
    renewed = change_cloud_review_settings(store, _payload("renew_consent"), refresh_workers=_refresh_workers)
    rotated = store.get_sync_payload("guard_exact_cloud_review_capability")
    assert isinstance(rotated, dict)
    assert rotated["nonce"] != nonce["nonce"]
    status = cloud_review_settings_status(store)
    assert status["recovery_actions"]["retry_delivery"] == "cloud-review.retry_delivery"
    assert first["enabled"] is True
    assert second["enabled"] is True
    assert retried["enabled"] is True
    assert renewed["enabled"] is True


@pytest.mark.parametrize("existing_consent", [False, True])
def test_delivery_retry_never_issues_missing_or_expired_consent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, existing_consent: bool
) -> None:
    from codex_plugin_scanner.guard.daemon import cloud_review_settings as settings

    store = connected_exact_review_store(tmp_path)
    if existing_consent:
        change_cloud_review_settings(store, _payload(), refresh_workers=_refresh_workers)
    original = store.get_sync_payload("guard_exact_cloud_review_capability")
    monkeypatch.setattr(settings, "exact_cloud_review_status", lambda _store: {"enabled": False})
    refreshes = []
    with pytest.raises(CloudReviewSettingsError, match="Enable or renew"):
        change_cloud_review_settings(store, _payload("retry_delivery"), refresh_workers=lambda: refreshes.append(True))
    assert store.get_sync_payload("guard_exact_cloud_review_capability") == original
    assert refreshes == []
