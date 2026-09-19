"""HGP-176: replay rejection across crash and concurrent reviewers."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.exact_cloud_review import (
    ExactCloudReviewError,
    apply_exact_cloud_review,
    enable_exact_cloud_review,
)
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_exact_cloud_review_support import (
    add_review_request,
    connected_exact_review_store,
    remote_approval,
    review_request,
)


def test_restart_and_second_reviewer_cannot_replay_or_create_memory(tmp_path: Path) -> None:
    store = connected_exact_review_store(tmp_path)
    request = review_request("crash-replay")
    add_review_request(store, request)
    enable_exact_cloud_review(store)
    approval = remote_approval(store, request.request_id, receipt_id="crash-replay-receipt")
    apply_exact_cloud_review(store, remote_approval=approval)
    policies = store.list_policy_decisions()
    reopened = GuardStore(store.guard_home)
    with pytest.raises(ExactCloudReviewError, match="remote_exact_replayed"):
        apply_exact_cloud_review(reopened, remote_approval=approval)
    block = remote_approval(store, request.request_id, receipt_id="crash-replay-block", decision="block")
    with pytest.raises(ExactCloudReviewError, match="remote_exact_request_not_pending|remote_exact_replayed"):
        apply_exact_cloud_review(reopened, remote_approval=block)
    assert reopened.list_policy_decisions() == policies
    assert reopened.get_sync_payload("guard_review_memory_registry") is None
    row = reopened.get_approval_request(request.request_id)
    assert row is not None and row["status"] == "resolved"
