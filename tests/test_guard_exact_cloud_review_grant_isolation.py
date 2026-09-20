"""HGP-174: exact Cloud Review stays isolated from reusable grants."""

from __future__ import annotations

from pathlib import Path

from codex_plugin_scanner.guard.runtime.exact_cloud_review import (
    apply_exact_cloud_review,
    enable_exact_cloud_review,
)
from tests.guard_exact_cloud_review_support import (
    add_review_request,
    connected_exact_review_store,
    remote_approval,
    review_request,
)


def test_second_identical_operation_stays_policy_governed(tmp_path: Path) -> None:
    store = connected_exact_review_store(tmp_path)
    first = review_request("exact-first")
    add_review_request(store, first)
    enable_exact_cloud_review(store)
    policies_before = store.list_policy_decisions()
    apply_exact_cloud_review(
        store,
        remote_approval=remote_approval(store, first.request_id, receipt_id="exact-first-receipt"),
        expected_harness="codex",
    )
    later = review_request("exact-later")
    add_review_request(store, later)
    later_row = store.get_approval_request(later.request_id)
    assert later_row is not None and later_row["status"] == "pending"
    assert store.list_policy_decisions() == policies_before
    assert store.get_sync_payload("guard_review_memory_registry") is None
    lookup = store.resolve_policy_decision_lookup(
        harness=later.harness,
        artifact_id=later.artifact_id,
        artifact_hash=later.artifact_hash,
        workspace=later.workspace,
        publisher=later.publisher,
        now=later_row["created_at"],
        consume_one_shot=False,
    )
    assert lookup["decision"] is None or lookup["decision"].get("request_id") != later.request_id
