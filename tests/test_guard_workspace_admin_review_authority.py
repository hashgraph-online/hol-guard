"""HGP-177: delegated workspace-admin review is separate from personal consent."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.daemon.cloud_review_settings import cloud_review_settings_status
from codex_plugin_scanner.guard.review_contracts import payload_hash_for_remote_approval_envelope
from codex_plugin_scanner.guard.runtime.exact_cloud_review import (
    ExactCloudReviewError,
    apply_exact_cloud_review,
)
from tests.guard_exact_cloud_review_support import (
    add_review_request,
    connected_exact_review_store,
    remote_approval,
    review_request,
)
from tests.guard_review_signing_helpers import sign_review_payload


def test_expired_step_up_and_other_workspace_and_immutable_block(tmp_path: Path) -> None:
    store = connected_exact_review_store(tmp_path)
    status = cloud_review_settings_status(store)
    assert status["personal_consent_required_for_managed_admin_review"] is False
    assert status["enabled"] is False
    request = review_request("admin-expired-step-up")
    add_review_request(store, request)
    past = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(minutes=1)
    with pytest.raises(ExactCloudReviewError, match="remote_exact_step_up_required"):
        apply_exact_cloud_review(
            store,
            remote_approval=remote_approval(
                store,
                request.request_id,
                receipt_id="admin-expired",
                authority="workspace_admin_mfa",
                step_up_challenge_id="step-up-old",
                step_up_expires_at=past,
            ),
        )

    foreign = remote_approval(
        store,
        request.request_id,
        receipt_id="admin-other-workspace",
        authority="workspace_admin_mfa",
        step_up_challenge_id="step-up-1",
    )
    foreign["workspaceId"] = "workspace-other"
    with pytest.raises(ExactCloudReviewError):
        apply_exact_cloud_review(store, remote_approval=foreign)

    blocked = review_request("admin-immutable")
    add_review_request(store, blocked)
    with store._connect() as connection:
        connection.execute(
            "update approval_requests set policy_action = 'block' where request_id = ?",
            (blocked.request_id,),
        )
    with pytest.raises(ExactCloudReviewError, match="remote_exact_not_permitted"):
        apply_exact_cloud_review(
            store,
            remote_approval=remote_approval(
                store,
                blocked.request_id,
                receipt_id="admin-immutable-receipt",
                authority="workspace_admin_mfa",
                step_up_challenge_id="step-up-1",
            ),
        )
    pending = store.get_approval_request(request.request_id)
    assert pending is not None and pending["status"] == "pending"


@pytest.mark.parametrize("expiry", [None, "", "invalid", True, 1, [], {}, "2026-01-01T00:00:00Z"])
def test_admin_receipt_requires_valid_future_step_up_expiry(tmp_path: Path, expiry: object) -> None:
    store = connected_exact_review_store(tmp_path)
    request = review_request("admin-invalid-expiry")
    add_review_request(store, request)
    approval = remote_approval(
        store,
        request.request_id,
        receipt_id="invalid-expiry-receipt",
        authority="workspace_admin_mfa",
        step_up_challenge_id="challenge-1",
    )
    approval["stepUpExpiresAt"] = expiry
    approval["payloadHash"] = payload_hash_for_remote_approval_envelope(approval)
    approval["signature"] = sign_review_payload(approval)
    with pytest.raises(ExactCloudReviewError, match="remote_exact_step_up_required"):
        apply_exact_cloud_review(store, remote_approval=approval)
    assert store.get_approval_request(request.request_id)["status"] == "pending"
    assert store.has_exact_cloud_review_receipt("invalid-expiry-receipt") is False


def test_admin_receipt_cannot_omit_step_up_expiry(tmp_path: Path) -> None:
    store = connected_exact_review_store(tmp_path)
    request = review_request("admin-missing-expiry")
    add_review_request(store, request)
    approval = remote_approval(
        store,
        request.request_id,
        receipt_id="missing-expiry-receipt",
        authority="workspace_admin_mfa",
        step_up_challenge_id="challenge-1",
    )
    del approval["stepUpExpiresAt"]
    approval["payloadHash"] = payload_hash_for_remote_approval_envelope(approval)
    approval["signature"] = sign_review_payload(approval)
    with pytest.raises(ExactCloudReviewError, match="remote_exact_step_up_required"):
        apply_exact_cloud_review(store, remote_approval=approval)


def test_admin_atomic_check_uses_earlier_authority_deadline(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = connected_exact_review_store(tmp_path)
    request = review_request("admin-expiry-boundary")
    add_review_request(store, request)
    step_up_expiry = datetime.now(timezone.utc).replace(microsecond=0) + timedelta(minutes=1)
    approval = remote_approval(
        store,
        request.request_id,
        receipt_id="expiry-boundary-receipt",
        authority="workspace_admin_mfa",
        step_up_challenge_id="challenge-1",
        step_up_expires_at=step_up_expiry,
    )
    resolve = store.resolve_one_request_with_signed_remote_exact_result
    deadlines = []

    def capture_deadline(*args, **kwargs):
        deadlines.append(kwargs["receipt_expires_at"])
        return resolve(*args, **kwargs)

    monkeypatch.setattr(store, "resolve_one_request_with_signed_remote_exact_result", capture_deadline)
    apply_exact_cloud_review(store, remote_approval=approval)
    assert deadlines == [step_up_expiry.isoformat()]
