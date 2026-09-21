from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import sqlite_cloud_review_recovery as recovery
from codex_plugin_scanner.guard import store_connection_schema
from codex_plugin_scanner.guard.review_event_wake import review_event_wake_signal
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
    signal = review_event_wake_signal(store.path)
    generation = signal.generation()
    _recover(store, monkeypatch)
    assert signal.generation() > generation
    restarted = GuardStore(store.guard_home)
    assert restarted.get_or_create_installation_id() == identity
    assert restarted.get_sync_payload("guard_exact_cloud_review_capability") == capability
    assert exact_cloud_review_status(restarted)["enabled"] is True
    assert restarted.has_exact_cloud_review_receipt("consumed-receipt")
    pending_request = restarted.get_approval_request("recover-pending")
    assert pending_request is not None
    assert pending_request["status"] == "pending"
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


def test_committed_connection_changes_wake_delivery_but_unrelated_state_does_not(tmp_path: Path) -> None:
    store = connected_exact_review_store(tmp_path)
    signal = review_event_wake_signal(store.path)
    payload = store.get_sync_payload("oauth_local_credentials")
    assert isinstance(payload, dict)
    generation = signal.generation()
    store.set_sync_payload("oauth_local_credentials", payload, datetime.now(timezone.utc).isoformat())
    assert signal.generation() > generation
    generation = signal.generation()
    store.set_sync_payload("unrelated-sync-counter", {"count": 1}, datetime.now(timezone.utc).isoformat())
    assert signal.generation() == generation


@pytest.mark.parametrize("missing_column", ["guard_version", "dedupe_count", "action_envelope_json"])
def test_prior_schema_only_defaults_known_presentation_columns(
    tmp_path: Path, missing_column: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = _prepare(tmp_path)
    with sqlite3.connect(source.path) as connection:
        triggers = connection.execute(
            "select name from sqlite_master where type = 'trigger' and tbl_name = 'approval_requests'"
        ).fetchall()
        for (name,) in triggers:
            connection.execute('drop trigger "' + name.replace('"', '""') + '"')
        connection.execute(f'alter table approval_requests drop column "{missing_column}"')
    _recover(source, monkeypatch)
    destination = GuardStore(source.guard_home)
    assert source._last_sqlite_recovery_details is not None
    recovered = source._last_sqlite_recovery_details["cloud_review"]
    assert recovered is (missing_column != "action_envelope_json")
    if recovered:
        assert exact_cloud_review_status(destination)["enabled"] is True
        assert destination.has_exact_cloud_review_receipt("consumed-receipt")
        request = destination.get_approval_request("recover-pending")
        assert request is not None
        assert request[missing_column] == (1 if missing_column == "dedupe_count" else None)
    else:
        assert destination.get_sync_payload("guard_exact_cloud_review_capability") is None


def test_independent_cli_recovery_failure_does_not_discard_complete_review_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _prepare(tmp_path)
    monkeypatch.setattr(store_connection_schema, "salvage_local_cli_state", lambda **_kwargs: False)
    _recover(store, monkeypatch)
    assert exact_cloud_review_status(store)["enabled"] is True
    assert store._last_sqlite_recovery_details == {"cloud_review": True, "local_cli": False}
    assert not store._recover_fatal_sqlite_store(ValueError("not a storage failure"))
    assert store._last_sqlite_recovery == "skipped"
    assert store._last_sqlite_recovery_details is None
