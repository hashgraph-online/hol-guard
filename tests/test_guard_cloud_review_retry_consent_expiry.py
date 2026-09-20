"""Retry delivery must not create consent when a verified capability expires."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone, tzinfo
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon import cloud_review_settings as settings
from codex_plugin_scanner.guard.runtime import cloud_review_status as review_status
from codex_plugin_scanner.guard.runtime import exact_cloud_review as exact
from codex_plugin_scanner.guard.stable_json import stable_json_serialize
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_exact_cloud_review_support import connected_exact_review_store

ISSUED_EVENT = "cloud_review.exact_capability_issued"


def _payload(action: str, **changes: object) -> dict[str, object]:
    return {
        "action": action,
        "confirm": f"cloud-review.{action}",
        "workspace_id": "workspace-1",
        "source": "default",
        **changes,
    }


def _snapshot(store: GuardStore) -> tuple[bytes, str, int]:
    capability = store.get_sync_payload(exact.EXACT_CLOUD_REVIEW_CAPABILITY_STATE_KEY)
    assert isinstance(capability, dict)
    nonce = capability.get("nonce")
    assert isinstance(nonce, str)
    return (
        stable_json_serialize(capability).encode("utf-8"),
        nonce,
        len(store.list_events(event_name=ISSUED_EVENT)),
    )


def _short_lived_consent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> tuple[GuardStore, list[datetime], list[datetime], datetime]:
    store = connected_exact_review_store(tmp_path)
    clock = [datetime.now(timezone.utc)]
    reads: list[datetime] = []

    class FrozenDateTime(datetime):
        @classmethod
        def now(cls, tz: tzinfo | None = None) -> FrozenDateTime:
            reads.append(clock[0])
            return cls.fromtimestamp(clock[0].timestamp(), tz=tz)

    # Only the clock changes: real signing, verification, binding and storage run.
    monkeypatch.setattr(exact, "datetime", FrozenDateTime)
    monkeypatch.setattr(review_status, "datetime", FrozenDateTime)
    monkeypatch.setattr(settings, "datetime", FrozenDateTime)
    issued = exact.enable_exact_cloud_review(store, issuer="local-dashboard", ttl_seconds=2)
    assert issued["enabled"] is True
    capability = store.get_sync_payload(exact.EXACT_CLOUD_REVIEW_CAPABILITY_STATE_KEY)
    assert isinstance(capability, dict)
    expires_at = capability.get("expiresAt")
    assert isinstance(expires_at, str)
    expiry = datetime.fromisoformat(expires_at)
    clock[0] = expiry - timedelta(seconds=1)
    reads.clear()
    assert _snapshot(store)[2] == 1
    return store, clock, reads, expiry


def _workers(refreshes: list[bool]) -> dict[str, bool]:
    refreshes.append(True)
    return {"running": True, "sync_running": True}


def test_retry_does_not_issue_consent_if_it_expires_between_real_checks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, clock, reads, expiry = _short_lived_consent(tmp_path, monkeypatch)
    before_bytes, before_nonce, before_issues = _snapshot(store)
    live_time = clock[0]
    real_status = settings.exact_cloud_review_status
    prechecks: list[bool] = []

    def checked_then_expired(target: GuardStore) -> dict[str, object]:
        current = real_status(target)
        assert current["enabled"] is True
        nonce_matches = current["nonce"] == before_nonce
        assert nonce_matches
        prechecks.append(True)
        # Advance only after the real outer verifier succeeds. The consent
        # helper keeps its own unmodified reference to the real status verifier.
        clock[0] = expiry
        return current

    monkeypatch.setattr(settings, "exact_cloud_review_status", checked_then_expired)
    refreshes: list[bool] = []
    rejection: str | None = None
    try:
        settings.change_cloud_review_settings(
            store, _payload("retry_delivery"), refresh_workers=lambda: _workers(refreshes),
        )
    except settings.CloudReviewSettingsError as error:
        rejection = error.code
    after_bytes, after_nonce, after_issues = _snapshot(store)
    # Report bounded facts together; never print the signed capability or nonce.
    observed = {
        "live_precheck": prechecks == [True],
        "clock_crossed_expiry": reads[:2] == [live_time, expiry],
        "signed_bytes_unchanged": after_bytes == before_bytes,
        "nonce_unchanged": after_nonce == before_nonce,
        "issued_event_delta": after_issues - before_issues,
        "rejection": rejection,
        "worker_refreshes": len(refreshes),
    }
    assert observed == {
        "live_precheck": True,
        "clock_crossed_expiry": True,
        "signed_bytes_unchanged": True,
        "nonce_unchanged": True,
        "issued_event_delta": 0,
        "rejection": "cloud_review_consent_required",
        "worker_refreshes": 0,
    }


def test_live_retry_keeps_the_real_signed_consent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, _, _, _ = _short_lived_consent(tmp_path, monkeypatch)
    before = _snapshot(store)
    refreshes: list[bool] = []
    result = settings.change_cloud_review_settings(
        store, _payload("retry_delivery"), refresh_workers=lambda: _workers(refreshes),
    )
    assert result["enabled"] is True
    state_unchanged = _snapshot(store) == before
    assert state_unchanged
    assert refreshes == [True]


def test_explicit_renewal_after_expiry_issues_one_new_signed_consent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, clock, _, expiry = _short_lived_consent(tmp_path, monkeypatch)
    before_bytes, before_nonce, before_issues = _snapshot(store)
    clock[0] = expiry
    expired = exact.exact_cloud_review_status(store)
    assert expired["enabled"] is False
    assert expired["reason"] == "cloud_review_capability_expired"
    refreshes: list[bool] = []
    result = settings.change_cloud_review_settings(
        store, _payload("renew_consent"), refresh_workers=lambda: _workers(refreshes),
    )
    after_bytes, after_nonce, after_issues = _snapshot(store)
    assert result["enabled"] is True
    signed_bytes_changed = after_bytes != before_bytes
    nonce_changed = after_nonce != before_nonce
    assert signed_bytes_changed
    assert nonce_changed
    assert after_issues == before_issues + 1
    assert refreshes == [True]


def test_retry_rejects_an_explicit_renew_flag_without_changing_consent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, _, _, _ = _short_lived_consent(tmp_path, monkeypatch)
    before = _snapshot(store)
    refreshes: list[bool] = []
    with pytest.raises(settings.CloudReviewSettingsError) as rejected:
        settings.change_cloud_review_settings(
            store, _payload("retry_delivery", renew_consent=True),
            refresh_workers=lambda: _workers(refreshes),
        )
    assert rejected.value.code == "invalid_consent_renewal"
    state_unchanged = _snapshot(store) == before
    assert state_unchanged
    assert refreshes == []
