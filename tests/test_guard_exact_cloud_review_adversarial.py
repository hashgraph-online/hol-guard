# pyright: reportMissingImports=false

from __future__ import annotations

import sqlite3
from argparse import Namespace
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import store_exact_cloud_review as exact_store_module
from codex_plugin_scanner.guard.adapters.base import HarnessContext
from codex_plugin_scanner.guard.cli.commands_dispatch_cloud_review import provision_connect_time_exact_cloud_review
from codex_plugin_scanner.guard.cli.oauth_client import generate_dpop_key_pair
from codex_plugin_scanner.guard.runtime import exact_cloud_review_apply as exact_apply_module
from codex_plugin_scanner.guard.runtime.command_executors import execute_guard_command_job
from codex_plugin_scanner.guard.runtime.exact_cloud_review import (
    ExactCloudReviewError,
    apply_exact_cloud_review,
    disable_exact_cloud_review,
    enable_exact_cloud_review,
)
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_exact_cloud_review import _add_request, _connected_store, _job, _remote_approval, _request


def test_exact_cloud_review_uses_local_time_not_forged_queue_admission(tmp_path: Path) -> None:
    store = _connected_store(tmp_path)
    request = _request("exact-expired-receipt")
    _add_request(store, request)
    enable_exact_cloud_review(store)
    issued_at = datetime.now(timezone.utc).replace(microsecond=0)
    approval = _remote_approval(
        store,
        request.request_id,
        receipt_id="exact-expired-receipt",
        issued_at=issued_at,
        expires_at=issued_at + timedelta(minutes=5),
    )
    job = _job(
        store,
        approval,
        created_at=issued_at + timedelta(minutes=1),
        expires_at=issued_at + timedelta(hours=6),
    )

    result = execute_guard_command_job(
        job,
        context=HarnessContext(home_dir=tmp_path, workspace_dir=tmp_path, guard_home=store.guard_home),
        store=store,
        now=lambda: (issued_at + timedelta(minutes=6)).isoformat(),
    )

    assert result["failureCode"] == "remote_approval_expired"
    row = store.get_approval_request(request.request_id)
    assert row is not None and row["status"] == "pending"


def test_exact_cloud_review_receipt_expiry_boundary_and_strict_wire(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _connected_store(tmp_path)
    current = datetime.now(timezone.utc).replace(microsecond=0)
    accepted = _request("exact-boundary-accepted")
    rejected = _request("exact-boundary-rejected")
    legacy = _request("exact-wire-legacy")
    transaction_expired = _request("exact-transaction-expired")
    capability_expired = _request("exact-capability-expired")
    for request in (accepted, rejected, legacy, transaction_expired, capability_expired):
        _add_request(store, request)
    enable_exact_cloud_review(store, now=current.isoformat(), ttl_seconds=600)
    expires_at = current + timedelta(minutes=5)

    apply_exact_cloud_review(
        store,
        remote_approval=_remote_approval(
            store,
            accepted.request_id,
            receipt_id="exact-boundary-accepted",
            issued_at=current,
            expires_at=expires_at,
        ),
        now=(expires_at - timedelta(microseconds=1)).isoformat(),
    )
    with pytest.raises(ExactCloudReviewError, match="remote_approval_expired"):
        apply_exact_cloud_review(
            store,
            remote_approval=_remote_approval(
                store,
                rejected.request_id,
                receipt_id="exact-boundary-rejected",
                issued_at=current,
                expires_at=expires_at,
            ),
            now=expires_at.isoformat(),
        )
    with pytest.raises(ExactCloudReviewError, match="remote_exact_decision_invalid"):
        apply_exact_cloud_review(
            store,
            remote_approval=_remote_approval(
                store,
                legacy.request_id,
                receipt_id="exact-wire-legacy",
                decision="allow",
            ),
        )
    monkeypatch.setattr(
        exact_store_module.StoreExactCloudReviewMixin,
        "_exact_transaction_now",
        staticmethod(lambda: expires_at.isoformat()),
    )
    with pytest.raises(ExactCloudReviewError, match="remote_approval_expired"):
        apply_exact_cloud_review(
            store,
            remote_approval=_remote_approval(
                store,
                transaction_expired.request_id,
                receipt_id="exact-transaction-expired",
                issued_at=current,
                expires_at=expires_at,
            ),
            now=(current + timedelta(seconds=1)).isoformat(),
        )
    enable_exact_cloud_review(store, now=current.isoformat(), ttl_seconds=300)
    with pytest.raises(ExactCloudReviewError, match="cloud_review_capability_expired"):
        apply_exact_cloud_review(
            store,
            remote_approval=_remote_approval(
                store,
                capability_expired.request_id,
                receipt_id="exact-capability-expired",
                issued_at=current,
                expires_at=current + timedelta(minutes=10),
            ),
            now=(current + timedelta(seconds=1)).isoformat(),
        )


def test_exact_cloud_review_rejects_stale_requests_and_durable_binding_drift(tmp_path: Path) -> None:
    store = _connected_store(tmp_path)
    stale = _request("exact-stale-request")
    store.add_approval_request(stale, "2020-01-01T00:00:00+00:00")
    enable_exact_cloud_review(store)
    with pytest.raises(ExactCloudReviewError, match="remote_exact_request_expired"):
        apply_exact_cloud_review(
            store,
            remote_approval=_remote_approval(store, stale.request_id, receipt_id="exact-stale-request"),
        )

    fresh = _request("exact-binding-drift")
    _add_request(store, fresh)
    enable_exact_cloud_review(store)
    capability = store.get_sync_payload("guard_exact_cloud_review_capability_v1")
    assert isinstance(capability, dict)
    dpop = generate_dpop_key_pair()
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="replacement-refresh-token",
        dpop_private_key_pem=dpop.private_key_pem,
        dpop_public_jwk=dpop.public_jwk,
        dpop_public_jwk_thumbprint=dpop.public_jwk_thumbprint,
        grant_id="grant-2",
        machine_id="machine-2",
        device_id=dpop.public_jwk_thumbprint,
        workspace_id="workspace-2",
        now=datetime.now(timezone.utc).isoformat(),
    )
    with pytest.raises(ExactCloudReviewError, match="cloud_review_capability_binding_mismatch"):
        apply_exact_cloud_review(
            store,
            remote_approval=_remote_approval(store, fresh.request_id, receipt_id="exact-binding-drift"),
        )
    restored_dpop = generate_dpop_key_pair()
    store.set_oauth_local_credentials(
        issuer="https://hol.org",
        client_id="guard-local-daemon",
        refresh_token="restored-refresh-token",
        dpop_private_key_pem=restored_dpop.private_key_pem,
        dpop_public_jwk=restored_dpop.public_jwk,
        dpop_public_jwk_thumbprint="device-default",
        grant_id="grant-1",
        machine_id=str(store.get_device_metadata()["installation_id"]),
        device_id="device-default",
        workspace_id="workspace-1",
        now=datetime.now(timezone.utc).isoformat(),
    )
    store.set_sync_payload("guard_exact_cloud_review_capability_v1", capability, datetime.now(timezone.utc).isoformat())
    with pytest.raises(ExactCloudReviewError, match="cloud_review_capability_revoked"):
        apply_exact_cloud_review(
            store,
            remote_approval=_remote_approval(store, fresh.request_id, receipt_id="exact-binding-restore"),
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
    store.set_sync_payload(
        "guard_exact_cloud_review_revocation_v1",
        ["invalid"],
        datetime.now(timezone.utc).isoformat(),
    )
    with pytest.raises(ExactCloudReviewError, match="cloud_review_capability_revocation_invalid"):
        apply_exact_cloud_review(
            store,
            remote_approval=_remote_approval(store, malformed.request_id, receipt_id="exact-bad-revocation"),
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
    rotation = apply_exact_cloud_review(
        store,
        remote_approval=_remote_approval(store, rotating.request_id, receipt_id="exact-oauth-rotation"),
    )
    assert rotation.request_id == rotating.request_id
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


def test_exact_cloud_review_reuses_durable_remote_receipt_ledger(tmp_path: Path) -> None:
    store = _connected_store(tmp_path)
    request = _request("exact-shared-receipt-ledger")
    _add_request(store, request)
    enable_exact_cloud_review(store)
    apply_exact_cloud_review(
        store,
        remote_approval=_remote_approval(store, request.request_id, receipt_id="exact-shared-receipt"),
    )
    with sqlite3.connect(store.path) as connection:
        row = connection.execute(
            "select request_id from guard_remote_once_receipts where receipt_id = ?",
            ("exact-shared-receipt",),
        ).fetchone()
    assert row == (request.request_id,)


def test_connect_time_consent_provisions_exact_review_only_after_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _connected_store(tmp_path)
    monkeypatch.setattr(
        "codex_plugin_scanner.guard.cli.commands_dispatch_cloud_review._refresh_cloud_review_worker",
        lambda _guard_home: {"running": True, "status": "refreshed"},
    )

    enabled = provision_connect_time_exact_cloud_review(
        args=Namespace(enable_exact_cloud_review=True),
        store=store,
        guard_home=store.guard_home,
        payload={"status": "connected"},
        exit_code=0,
    )
    failed = provision_connect_time_exact_cloud_review(
        args=Namespace(enable_exact_cloud_review=True),
        store=store,
        guard_home=store.guard_home,
        payload={"status": "error"},
        exit_code=1,
    )

    enabled_review = enabled.get("exact_cloud_review")
    assert isinstance(enabled_review, dict)
    assert enabled_review.get("enabled") is True
    worker = enabled_review.get("worker")
    assert isinstance(worker, dict) and worker.get("running") is True
    assert failed.get("exact_cloud_review") == {"enabled": False, "reason": "connect_not_completed"}
