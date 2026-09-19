"""HGP-181: disable/revocation race with a leased exact decision."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.exact_cloud_review import (
    ExactCloudReviewError,
    apply_exact_cloud_review,
    disable_exact_cloud_review,
    enable_exact_cloud_review,
)
from tests.guard_exact_cloud_review_support import (
    add_review_request,
    connected_exact_review_store,
    remote_approval,
    review_request,
)


def test_revoked_capability_cannot_commit_leased_decision(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = connected_exact_review_store(tmp_path)
    first = review_request("applied-before-revoke")
    leased = review_request("leased-after-revoke")
    add_review_request(store, first)
    add_review_request(store, leased)
    enable_exact_cloud_review(store)
    applied = apply_exact_cloud_review(
        store,
        remote_approval=remote_approval(store, first.request_id, receipt_id="applied-before"),
    )
    approval = remote_approval(store, leased.request_id, receipt_id="leased-after")
    original = store.resolve_one_request_with_signed_remote_exact_result

    def _revoke_then_commit(*args: object, **kwargs: object):
        disable_exact_cloud_review(store)
        return original(*args, **kwargs)

    monkeypatch.setattr(store, "resolve_one_request_with_signed_remote_exact_result", _revoke_then_commit)
    with pytest.raises(ExactCloudReviewError, match="cloud_review_capability_revoked|remote_exact_capability_changed"):
        apply_exact_cloud_review(store, remote_approval=approval)
    history = store.get_approval_request(first.request_id)
    assert history is not None and history["status"] == "resolved"
    assert history["request_id"] == applied.request_id
    pending = store.get_approval_request(leased.request_id)
    assert pending is not None and pending["status"] == "pending"
