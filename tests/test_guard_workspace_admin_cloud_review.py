from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.command_queue import command_queue_enabled, command_queue_should_poll
from codex_plugin_scanner.guard.runtime.exact_cloud_review import (
    EXACT_CLOUD_REVIEW_OPERATION,
    ExactCloudReviewError,
    apply_exact_cloud_review,
    authorize_exact_cloud_review_job,
    disable_exact_cloud_review,
    enable_exact_cloud_review,
    exact_cloud_review_operations,
)
from tests.guard_exact_cloud_review_support import (
    add_review_request as _add_request,
)
from tests.guard_exact_cloud_review_support import (
    connected_exact_review_store as _connected_store,
)
from tests.guard_exact_cloud_review_support import (
    exact_review_job as _job,
)
from tests.guard_exact_cloud_review_support import (
    remote_approval as _remote_approval,
)
from tests.guard_exact_cloud_review_support import (
    review_request as _request,
)


def test_workspace_admin_mfa_review_applies_without_local_cloud_review_enablement(tmp_path: Path) -> None:
    store = _connected_store(tmp_path)
    request = _request("admin-mfa-target")
    _add_request(store, request)

    resolution = apply_exact_cloud_review(
        store,
        remote_approval=_remote_approval(
            store,
            request.request_id,
            receipt_id="admin-mfa-receipt",
            authority="workspace_admin_mfa",
            step_up_challenge_id="step-up-1",
        ),
        expected_harness="codex",
    )

    row = store.get_approval_request(request.request_id)
    assert resolution.request_id == request.request_id
    assert row is not None and row["status"] == "resolved"
    assert row["reason"] == "Guard Cloud signed team-admin review"
    assert exact_cloud_review_operations(store) == (EXACT_CLOUD_REVIEW_OPERATION,)
    assert command_queue_enabled(store) is False
    assert command_queue_should_poll(store) is True


def test_workspace_admin_mfa_review_requires_cloud_step_up(tmp_path: Path) -> None:
    store = _connected_store(tmp_path)
    request = _request("admin-mfa-missing-step-up")
    _add_request(store, request)

    with pytest.raises(ExactCloudReviewError, match="remote_exact_step_up_required"):
        apply_exact_cloud_review(
            store,
            remote_approval=_remote_approval(
                store,
                request.request_id,
                receipt_id="admin-mfa-no-step-up",
                authority="workspace_admin_mfa",
            ),
        )


def test_workspace_admin_mfa_review_rejects_operator_role(tmp_path: Path) -> None:
    store = _connected_store(tmp_path)
    request = _request("admin-mfa-operator")
    _add_request(store, request)

    with pytest.raises(ExactCloudReviewError, match="remote_exact_reviewer_not_authorized"):
        apply_exact_cloud_review(
            store,
            remote_approval=_remote_approval(
                store,
                request.request_id,
                receipt_id="admin-mfa-operator-receipt",
                authority="workspace_admin_mfa",
                reviewer_role="operator",
                step_up_challenge_id="step-up-1",
            ),
        )


def test_workspace_admin_mfa_job_authorizes_without_local_enablement(tmp_path: Path) -> None:
    store = _connected_store(tmp_path)
    request = _request("admin-mfa-job")
    _add_request(store, request)
    approval = _remote_approval(
        store,
        request.request_id,
        receipt_id="admin-mfa-job-receipt",
        authority="workspace_admin_mfa",
        step_up_challenge_id="step-up-1",
    )
    job = _job(store, approval)
    authorized = authorize_exact_cloud_review_job(store, job)
    assert authorized.operation == EXACT_CLOUD_REVIEW_OPERATION
    assert authorized.requires_local_approval is False


def test_workspace_admin_mfa_review_honors_local_cloud_review_revocation(tmp_path: Path) -> None:
    store = _connected_store(tmp_path)
    request = _request("admin-mfa-revoked")
    _add_request(store, request)
    enable_exact_cloud_review(store)
    disable_exact_cloud_review(store)
    assert exact_cloud_review_operations(store) == ()
    with pytest.raises(ExactCloudReviewError, match="cloud_review_capability_revoked"):
        apply_exact_cloud_review(
            store,
            remote_approval=_remote_approval(
                store,
                request.request_id,
                receipt_id="admin-mfa-revoked-receipt",
                authority="workspace_admin_mfa",
                step_up_challenge_id="step-up-1",
            ),
        )
