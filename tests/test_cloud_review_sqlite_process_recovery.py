"""HGP-172: durable Cloud Review recovery after SQLite and process failure."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from codex_plugin_scanner.guard.policy_activation_failure import classify_policy_activation_failure
from codex_plugin_scanner.guard.runtime.cloud_review_sync_worker import (
    start_cloud_sync_sync_worker,
    stop_cloud_sync_sync_worker,
)
from codex_plugin_scanner.guard.runtime.exact_cloud_review import (
    ExactCloudReviewError,
    apply_exact_cloud_review,
    enable_exact_cloud_review,
    exact_cloud_review_status,
)
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_exact_cloud_review_support import (
    add_review_request,
    connected_exact_review_store,
    remote_approval,
    review_request,
)
from tests.test_guard_cloud_review_sqlite_recovery import _prepare, _recover


def test_process_restart_preserves_pending_identity(tmp_path: Path) -> None:
    store = connected_exact_review_store(tmp_path)
    enable_exact_cloud_review(store)
    add_review_request(store, review_request("alive-after-restart"))
    identity = store.get_or_create_installation_id()
    worker = start_cloud_sync_sync_worker(store, poll_interval=0.2)
    stop_cloud_sync_sync_worker(worker)
    restarted = GuardStore(store.guard_home)
    assert restarted.get_or_create_installation_id() == identity
    assert exact_cloud_review_status(restarted)["enabled"] is True
    pending = restarted.get_approval_request("alive-after-restart")
    assert pending is not None
    assert pending["status"] == "pending"


def test_sqlite_recovery_does_not_replay_consumed_receipt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _prepare(tmp_path)
    _recover(store, monkeypatch)
    restarted = GuardStore(store.guard_home)
    assert restarted.has_exact_cloud_review_receipt("consumed-receipt")
    proof = remote_approval(restarted, "recover-pending", receipt_id="consumed-receipt")
    with pytest.raises(ExactCloudReviewError) as error:
        apply_exact_cloud_review(restarted, remote_approval=proof, expected_harness="codex")
    assert error.value.code == "remote_exact_replayed"
    later = remote_approval(restarted, "recover-pending", receipt_id="fresh-after-recovery")
    result = apply_exact_cloud_review(restarted, remote_approval=later, expected_harness="codex")
    assert result.resolved_request["status"] == "resolved"


def test_locked_db_classification_stays_storage() -> None:
    status = classify_policy_activation_failure(sqlite3.OperationalError("database is locked"))
    assert status["applied"] is False
    assert status["failure_kind"] == "storage"
