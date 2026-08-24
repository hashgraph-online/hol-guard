# pyright: reportMissingImports=false

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime import exact_cloud_review_apply as exact_apply_module
from codex_plugin_scanner.guard.runtime.exact_cloud_review import (
    ExactCloudReviewError,
    apply_exact_cloud_review,
    disable_exact_cloud_review,
    enable_exact_cloud_review,
)
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_exact_cloud_review_support import (
    add_review_request as _add_request,
)
from tests.guard_exact_cloud_review_support import (
    connected_exact_review_store as _connected_store,
)
from tests.guard_exact_cloud_review_support import (
    remote_approval as _remote_approval,
)
from tests.guard_exact_cloud_review_support import (
    review_request as _request,
)


def test_exact_cloud_review_fails_closed_on_bad_revocation_and_concurrent_disable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _connected_store(tmp_path)
    oauth_missing = _request("exact-oauth-missing")
    _add_request(store, oauth_missing)
    enable_exact_cloud_review(store)
    oauth = store.get_sync_payload("oauth_local_credentials")
    assert isinstance(oauth, dict)
    verified = exact_apply_module._verified_capability

    def _verify_then_remove_oauth(store_arg: GuardStore, *, now: str | None = None) -> dict[str, object]:
        capability = verified(store_arg, now=now)
        store.delete_sync_payload("oauth_local_credentials")
        return capability

    monkeypatch.setattr(exact_apply_module, "_verified_capability", _verify_then_remove_oauth)
    with pytest.raises(ExactCloudReviewError, match="cloud_review_oauth_state_missing"):
        apply_exact_cloud_review(
            store,
            remote_approval=_remote_approval(store, oauth_missing.request_id, receipt_id="exact-oauth-missing"),
        )
    assert store.list_events(limit=1, event_name="cloud_review.exact_rejected")
    store.set_sync_payload("oauth_local_credentials", oauth, datetime.now(timezone.utc).isoformat())
    monkeypatch.setattr(exact_apply_module, "_verified_capability", verified)
    malformed = _request("exact-bad-revocation")
    _add_request(store, malformed)
    enable_exact_cloud_review(store)
    malformed_approval = _remote_approval(store, malformed.request_id, receipt_id="exact-bad-revocation")
    store.set_sync_payload(
        "guard_exact_cloud_review_revocation_v1",
        ["invalid"],
        datetime.now(timezone.utc).isoformat(),
    )
    with pytest.raises(ExactCloudReviewError, match="cloud_review_capability_revocation_invalid"):
        apply_exact_cloud_review(
            store,
            remote_approval=malformed_approval,
        )
    assert store.list_events(limit=1, event_name="cloud_review.exact_rejected")

    store.delete_sync_payload("guard_exact_cloud_review_revocation_v1")
    original_resolve: Callable[..., dict[str, object]] = store.resolve_one_request_with_signed_remote_exact_result
    rotating = _request("exact-oauth-rotation")
    _add_request(store, rotating)
    enable_exact_cloud_review(store)
    rotation_oauth_state = store.get_sync_payload("oauth_local_credentials")
    assert isinstance(rotation_oauth_state, dict)

    def _rotate_oauth_then_resolve(*args: object, **kwargs: object) -> dict[str, object]:
        store.set_sync_payload(
            "oauth_local_credentials",
            {**rotation_oauth_state, "credentials_sha256": "rotated-secret-fingerprint"},
            datetime.now(timezone.utc).isoformat(),
        )
        return original_resolve(*args, **kwargs)

    monkeypatch.setattr(store, "resolve_one_request_with_signed_remote_exact_result", _rotate_oauth_then_resolve)
    with pytest.raises(ExactCloudReviewError, match="remote_exact_oauth_changed"):
        apply_exact_cloud_review(
            store,
            remote_approval=_remote_approval(store, rotating.request_id, receipt_id="exact-oauth-rotation"),
        )
    rotating_row = store.get_approval_request(rotating.request_id)
    assert rotating_row is not None and rotating_row["status"] == "pending"
    store.set_sync_payload(
        "oauth_local_credentials",
        rotation_oauth_state,
        datetime.now(timezone.utc).isoformat(),
    )
    monkeypatch.setattr(store, "resolve_one_request_with_signed_remote_exact_result", original_resolve)

    missing_device = _request("exact-device-disappears")
    _add_request(store, missing_device)

    def _remove_device_then_resolve(*args: object, **kwargs: object) -> dict[str, object]:
        store.set_sync_payload(
            "oauth_local_credentials",
            {key: value for key, value in rotation_oauth_state.items() if key != "device_id"},
            datetime.now(timezone.utc).isoformat(),
        )
        return original_resolve(*args, **kwargs)

    monkeypatch.setattr(store, "resolve_one_request_with_signed_remote_exact_result", _remove_device_then_resolve)
    with pytest.raises(ExactCloudReviewError, match="remote_exact_oauth_changed"):
        apply_exact_cloud_review(
            store,
            remote_approval=_remote_approval(store, missing_device.request_id, receipt_id="exact-device-disappears"),
        )
    missing_device_row = store.get_approval_request(missing_device.request_id)
    assert missing_device_row is not None and missing_device_row["status"] == "pending"
    store.set_sync_payload("oauth_local_credentials", rotation_oauth_state, datetime.now(timezone.utc).isoformat())
    monkeypatch.setattr(store, "resolve_one_request_with_signed_remote_exact_result", original_resolve)

    previous_capability = store.get_sync_payload("guard_exact_cloud_review_capability_v1")
    assert isinstance(previous_capability, dict)
    original_replace = store.replace_exact_cloud_review_state
    raced_enable = False

    def _enable_before_disable(
        *,
        capability: dict[str, object] | None,
        revocation: dict[str, object] | None,
        now: str,
        event_name: str,
        event_payload: dict[str, object],
        expected_capability: object = None,
        require_expected_capability: bool = False,
    ) -> bool:
        nonlocal raced_enable
        if event_name == "cloud_review.exact_capability_revoked" and not raced_enable:
            raced_enable = True
            enable_exact_cloud_review(store)
        return original_replace(
            capability=capability,
            revocation=revocation,
            now=now,
            event_name=event_name,
            event_payload=event_payload,
            expected_capability=expected_capability,
            require_expected_capability=require_expected_capability,
        )

    monkeypatch.setattr(store, "replace_exact_cloud_review_state", _enable_before_disable)
    with pytest.raises(ExactCloudReviewError, match="cloud_review_capability_changed"):
        disable_exact_cloud_review(store)
    replacement_capability = store.get_sync_payload("guard_exact_cloud_review_capability_v1")
    assert isinstance(replacement_capability, dict)
    assert replacement_capability["nonce"] != previous_capability["nonce"]
    assert store.get_sync_payload("guard_exact_cloud_review_revocation_v1") is None
    monkeypatch.setattr(store, "replace_exact_cloud_review_state", original_replace)

    race = _request("exact-disable-race")
    _add_request(store, race)

    def _disable_then_resolve(*args: object, **kwargs: object) -> dict[str, object]:
        disable_exact_cloud_review(store)
        return original_resolve(*args, **kwargs)

    monkeypatch.setattr(store, "resolve_one_request_with_signed_remote_exact_result", _disable_then_resolve)
    with pytest.raises(ExactCloudReviewError, match="remote_exact_capability_changed"):
        apply_exact_cloud_review(
            store,
            remote_approval=_remote_approval(store, race.request_id, receipt_id="exact-disable-race"),
        )
    race_row = store.get_approval_request(race.request_id)
    assert race_row is not None and race_row["status"] == "pending"

    enable_exact_cloud_review(store)
    changed = _request("exact-request-cas")
    _add_request(store, changed)

    def _change_request_then_resolve(request_id: str, *args: object, **kwargs: object) -> dict[str, object]:
        with store._connect() as connection:
            connection.execute(
                "update approval_requests set raw_command_text = ? where request_id = ?",
                ("changed-after-signed-validation", request_id),
            )
        return original_resolve(request_id, *args, **kwargs)

    monkeypatch.setattr(store, "resolve_one_request_with_signed_remote_exact_result", _change_request_then_resolve)
    with pytest.raises(ExactCloudReviewError, match="remote_exact_request_stale"):
        apply_exact_cloud_review(
            store,
            remote_approval=_remote_approval(store, changed.request_id, receipt_id="exact-request-cas"),
        )
    changed_row = store.get_approval_request(changed.request_id)
    assert changed_row is not None and changed_row["status"] == "pending"
    assert store.has_exact_cloud_review_receipt("exact-request-cas") is False
