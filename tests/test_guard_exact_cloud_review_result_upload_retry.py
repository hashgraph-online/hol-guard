"""HGP-179: result-upload failure retries delivery without a second apply."""

from __future__ import annotations

from pathlib import Path

import pytest

from codex_plugin_scanner.guard.runtime.command_queue import _retry_pending_result
from codex_plugin_scanner.guard.runtime.exact_cloud_review import apply_exact_cloud_review, enable_exact_cloud_review
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_exact_cloud_review_support import (
    add_review_request,
    connected_exact_review_store,
    remote_approval,
    review_request,
)


def test_pending_result_retry_keeps_original_application(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = connected_exact_review_store(tmp_path)
    request = review_request("result-upload")
    add_review_request(store, request)
    enable_exact_cloud_review(store)
    approval = remote_approval(store, request.request_id, receipt_id="result-upload-receipt")
    resolution = apply_exact_cloud_review(store, remote_approval=approval)
    applied_at = store.get_approval_request(request.request_id)["resolved_at"]
    payload = {
        "applicationStatus": "applied",
        "applicationUpdatedAt": applied_at,
        "continuationStatus": "manual_retry_required",
        "localRequestId": resolution.request_id,
        "receiptId": resolution.receipt_id,
    }
    posted: list[dict[str, object]] = []

    def _post(_auth: object, job: dict[str, object], result: dict[str, object]) -> None:
        posted.append(result)

    monkeypatch.setattr("codex_plugin_scanner.guard.runtime.command_queue._post_result", _post)
    state = {
        "pending_result": {
            "job": {"id": "job-1", "createdAt": "2026-09-17T12:00:00+00:00"},
            "payload": payload,
        },
        "state": "result_pending",
    }
    assert _retry_pending_result(store, {"sync_url": "https://hol.org"}, state) is True
    restarted = GuardStore(store.guard_home)
    row = restarted.get_approval_request(request.request_id)
    assert row is not None and row["status"] == "resolved"
    assert row["resolved_at"] == applied_at
    assert posted == [payload]
    with pytest.raises(Exception, match="remote_exact_replayed"):
        apply_exact_cloud_review(restarted, remote_approval=approval)
