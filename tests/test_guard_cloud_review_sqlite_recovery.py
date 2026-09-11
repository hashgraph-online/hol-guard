from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import sqlite_cloud_review_recovery as recovery
from codex_plugin_scanner.guard import store_connection_schema
from codex_plugin_scanner.guard.runtime.exact_cloud_review import (
    apply_exact_cloud_review,
    disable_exact_cloud_review,
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


def _prepare(tmp_path: Path) -> GuardStore:
    store = connected_exact_review_store(tmp_path)
    enable_exact_cloud_review(store)
    add_review_request(store, review_request("recover-pending"))
    with sqlite3.connect(store.path) as connection:
        connection.execute(
            "insert into guard_exact_cloud_review_receipts values (?, ?, ?)",
            ("consumed-receipt", "resolved-request", datetime.now(timezone.utc).isoformat()),
        )
    return store


def _recover(store: GuardStore, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(store, "_store_is_proven_unusable", lambda _error: True)
    monkeypatch.setattr(store_connection_schema, "restore_readable_sqlite_store", lambda **_kwargs: False)
    assert store._recover_fatal_sqlite_store(sqlite3.DatabaseError("database disk image is malformed"))


def test_recovery_preserves_identity_consent_pending_events_and_replay_barrier(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _prepare(tmp_path)
    identity = store.get_or_create_installation_id()
    capability = store.get_sync_payload("guard_exact_cloud_review_capability")
    now = datetime.now(timezone.utc).isoformat()
    before = store.list_ready_review_events(now=now, limit=100)
    _recover(store, monkeypatch)
    restarted = GuardStore(store.guard_home)
    assert restarted.get_or_create_installation_id() == identity
    assert restarted.get_sync_payload("guard_exact_cloud_review_capability") == capability
    assert exact_cloud_review_status(restarted)["enabled"] is True
    assert restarted.has_exact_cloud_review_receipt("consumed-receipt")
    assert restarted.get_approval_request("recover-pending")["status"] == "pending"
    assert restarted.list_ready_review_events(now=now, limit=100) == before
    proof = remote_approval(restarted, "recover-pending", receipt_id="after-recovery")
    result = apply_exact_cloud_review(restarted, remote_approval=proof, expected_harness="codex")
    assert result.resolved_request["status"] == "resolved"


def test_recovery_does_not_resurrect_revoked_consent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = _prepare(tmp_path)
    disable_exact_cloud_review(store)
    revocation = store.get_sync_payload("guard_exact_cloud_review_revocation")
    _recover(store, monkeypatch)
    assert exact_cloud_review_status(store)["enabled"] is False
    assert store.get_sync_payload("guard_exact_cloud_review_revocation") == revocation
    assert store.has_exact_cloud_review_receipt("consumed-receipt")


@pytest.mark.parametrize(
    "table", ["sync_state", "guard_exact_cloud_review_receipts", "guard_review_outbox_request_sequences"]
)
def test_incomplete_recovery_never_restores_authority(tmp_path: Path, table: str) -> None:
    store = _prepare(tmp_path)
    with sqlite3.connect(store.path) as connection:
        connection.execute(f'drop table "{table}"')
    destination = GuardStore(tmp_path / "new")
    assert recovery.salvage_cloud_review_state(source=store.path, destination=destination.path) is False
    assert destination.get_sync_payload("oauth_local_credentials") is None
    assert destination.get_sync_payload("guard_exact_cloud_review_capability") is None
    assert destination.get_approval_request("recover-pending") is None


def test_partial_replay_copy_rolls_back_everything(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    source = _prepare(tmp_path)
    destination = GuardStore(tmp_path / "new")
    identity = destination.get_or_create_installation_id()
    copy = recovery._copy_complete_table

    def fail_after_receipts(src: sqlite3.Connection, dst: sqlite3.Connection, table: str) -> None:
        copy(src, dst, table)
        if table == "guard_exact_cloud_review_receipts":
            raise sqlite3.DatabaseError("database disk image is malformed")

    monkeypatch.setattr(recovery, "_copy_complete_table", fail_after_receipts)
    assert not recovery.salvage_cloud_review_state(source=source.path, destination=destination.path)
    assert destination.get_or_create_installation_id() == identity
    assert destination.get_sync_payload("oauth_local_credentials") is None
    assert not destination.has_exact_cloud_review_receipt("consumed-receipt")


def test_recovery_refuses_nonempty_destination(tmp_path: Path) -> None:
    source = _prepare(tmp_path)
    destination = connected_exact_review_store(tmp_path / "different")
    identity = destination.get_or_create_installation_id()
    assert not recovery.salvage_cloud_review_state(source=source.path, destination=destination.path)
    assert destination.get_or_create_installation_id() == identity
    assert destination.get_sync_payload("guard_exact_cloud_review_capability") is None
