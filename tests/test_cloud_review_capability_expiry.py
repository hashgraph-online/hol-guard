"""HGP-167: capability expiry is explained without claiming disconnect."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from codex_plugin_scanner.guard.runtime.cloud_review_status import cloud_review_status
from codex_plugin_scanner.guard.runtime.exact_cloud_review import enable_exact_cloud_review, exact_cloud_review_status
from tests.guard_exact_cloud_review_support import connected_exact_review_store


def test_before_at_and_after_expiry_reasons(tmp_path: Path) -> None:
    store = connected_exact_review_store(tmp_path)
    issued = "2026-07-18T00:00:00+00:00"
    capability = enable_exact_cloud_review(store, ttl_seconds=60, now=issued)
    assert str(capability["expires_at"]).startswith("2026-07-18T00:01:00")
    before = exact_cloud_review_status(store, now="2026-07-18T00:00:30+00:00")
    assert before["enabled"] is True
    assert before["reason"] is None
    after = exact_cloud_review_status(store, now="2026-07-18T00:01:01+00:00")
    assert after["enabled"] is False
    assert after["reason"] == "cloud_review_capability_expired"
    projected = cloud_review_status(store, now=datetime.fromisoformat("2026-07-18T00:01:01+00:00"))
    assert projected["consent_expired"] is True
    assert projected["disconnected"] is False
    assert projected["connected"] is True
    assert projected["recovery_action"] == "hol-guard cloud-review enable --renew"


def test_renewal_does_not_mark_disconnected(tmp_path: Path) -> None:
    store = connected_exact_review_store(tmp_path)
    enable_exact_cloud_review(store, ttl_seconds=1)
    now = datetime.now(timezone.utc) + timedelta(seconds=2)
    expired = cloud_review_status(store, now=now)
    assert expired["consent_expired"] is True
    assert expired["disconnected"] is False
    enable_exact_cloud_review(store, ttl_seconds=60)
    renewed = cloud_review_status(store)
    assert renewed["enabled"] is True
    assert renewed["consent_expired"] is False
