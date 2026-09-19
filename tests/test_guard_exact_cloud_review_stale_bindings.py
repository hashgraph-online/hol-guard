"""HGP-175: stale bindings reject late Cloud exact decisions."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.exact_cloud_review import (
    ExactCloudReviewError,
    apply_exact_cloud_review,
    enable_exact_cloud_review,
)
from tests.guard_exact_cloud_review_support import (
    add_review_request,
    connected_exact_review_store,
    remote_approval,
    review_request,
)


def test_changed_command_and_harness_reject_stale_or_wrong_target(tmp_path: Path) -> None:
    store = connected_exact_review_store(tmp_path)
    request = review_request("stale-bind")
    add_review_request(store, request)
    enable_exact_cloud_review(store)
    approval = remote_approval(store, request.request_id, receipt_id="stale-bind-receipt")
    with store._connect() as connection:
        connection.execute(
            "update approval_requests set artifact_hash = ?, action_envelope_json = ? where request_id = ?",
            (
                "hash-changed",
                '{"action_type":"shell_command","command":"echo changed"}',
                request.request_id,
            ),
        )
    with pytest.raises(ExactCloudReviewError, match="remote_exact_request_stale"):
        apply_exact_cloud_review(store, remote_approval=approval, expected_harness="codex")
    pending = store.get_approval_request(request.request_id)
    assert pending is not None and pending["status"] == "pending"

    other = review_request("stale-harness", harness="claude-code")
    add_review_request(store, other)
    with pytest.raises(ExactCloudReviewError, match="remote_exact_harness_mismatch"):
        apply_exact_cloud_review(
            store,
            remote_approval=remote_approval(store, other.request_id, receipt_id="stale-harness-receipt"),
            expected_harness="codex",
        )


def test_non_pending_status_rejects_late_decision(tmp_path: Path) -> None:
    store = connected_exact_review_store(tmp_path)
    request = review_request("already-local")
    add_review_request(store, request)
    enable_exact_cloud_review(store)
    store.resolve_request_with_signed_remote_compat_result(
        request.request_id,
        receipt_id="local-compat",
        resolution_action="allow",
        resolution_scope="artifact",
        reason="local",
        resolved_at="2026-09-17T12:00:00+00:00",
    )
    with pytest.raises(ExactCloudReviewError, match="remote_exact_request_not_pending"):
        apply_exact_cloud_review(
            store,
            remote_approval=remote_approval(store, request.request_id, receipt_id="already-local-receipt"),
        )
