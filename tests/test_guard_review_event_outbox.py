from __future__ import annotations

import json
import sqlite3
from typing import TypedDict

import pytest

from codex_plugin_scanner.guard.models import GuardApprovalRequest
from codex_plugin_scanner.guard.review_event_integrity import review_event_payload_digest
from codex_plugin_scanner.guard.runtime.review_event_delivery import decode_stored_review_event
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_review_event_outbox_schema import (
    REVIEW_EVENT_SCHEMA_VERSION,
    REVIEW_REQUEST_SNAPSHOT_COLUMNS,
    ensure_review_event_outbox_schema,
)
from tests.guard_review_event_outbox_test_support import as_int

# pyright: reportMissingImports=false

_NOW = "2026-08-24T12:00:00+00:00"
_LATER = "2026-08-24T12:00:01+00:00"


class _DeliveryBinding(TypedDict):
    oauth_subject_hash: str
    workspace_id: str
    machine_id: str
    machine_installation_id: str


def _request(request_id: str, *, summary: str = "Review test action") -> GuardApprovalRequest:
    return GuardApprovalRequest(
        request_id=request_id,
        harness="codex",
        artifact_id=f"codex:project:{request_id}",
        artifact_name="Test action",
        artifact_hash="hash-abc",
        policy_action="require-reapproval",
        recommended_scope="artifact",
        changed_fields=("tool_action_request",),
        source_scope="project",
        config_path="/test/config.toml",
        review_command=f"hol-guard approvals approve {request_id}",
        approval_url=f"http://127.0.0.1:5474/requests/{request_id}",
        action_identity=request_id,
        queue_group_id=request_id,
        trigger_summary=summary,
        last_seen_at=_NOW,
    )


def _connect(
    store: GuardStore,
    *,
    grant_id: str = "grant-1",
    workspace_id: str = "workspace-1",
    machine_id: str = "machine-1",
) -> _DeliveryBinding:
    state_key = (
        "oauth_local_credentials"
        if store.guard_source == "default"
        else f"oauth_local_credentials:{store.guard_source}"
    )
    store.set_sync_payload(
        state_key,
        {"grant_id": grant_id, "workspace_id": workspace_id, "machine_id": machine_id},
        _NOW,
    )
    binding = store.get_review_event_oauth_binding()
    assert binding is not None
    return {
        "oauth_subject_hash": binding["oauth_subject_hash"],
        "workspace_id": binding["workspace_id"],
        "machine_id": binding["machine_id"],
        "machine_installation_id": binding["machine_installation_id"],
    }


def _all_events(store: GuardStore) -> list[sqlite3.Row]:
    with store._connect() as connection:
        return connection.execute("select * from guard_review_outbox_events order by stream_sequence").fetchall()


def test_identity_incomplete_event_is_quarantined_with_valid_hash(tmp_path) -> None:
    store = GuardStore(tmp_path / "guard")
    store.add_approval_request(_request("request-1"), _NOW)

    events = _all_events(store)
    assert len(events) == 1
    event = events[0]
    assert event["binding_status"] == "quarantined"
    assert event["quarantine_reason"] == "identity_incomplete"
    assert event["event_schema_version"] == REVIEW_EVENT_SCHEMA_VERSION
    assert event["payload_hash"] == review_event_payload_digest(
        str(event["payload_json"]),
        oauth_source=event["oauth_source"],
        oauth_subject_hash=event["oauth_subject_hash"],
        workspace_id=event["workspace_id"],
        machine_id=event["machine_id"],
        machine_installation_id=event["machine_installation_id"],
    )
    assert store.list_ready_review_events(now=_NOW, limit=10) == []
    assert store.review_event_outbox_status(now=_NOW)["quarantined_depth"] == 1


def test_later_credential_availability_does_not_silently_adopt_quarantine(tmp_path) -> None:
    store = GuardStore(tmp_path / "guard")
    store.add_approval_request(_request("request-1"), _NOW)
    binding = _connect(store)

    store.add_approval_request(_request("request-1", summary="refreshed"), _LATER)

    assert store.list_ready_review_events(now=_LATER, limit=10, **binding) == []
    events = _all_events(store)
    assert len(events) == 2
    assert all(row["binding_status"] == "quarantined" for row in events)


def test_create_refresh_and_resolution_are_append_only_and_versioned(tmp_path) -> None:
    store = GuardStore(tmp_path / "guard")
    binding = _connect(store)
    store.add_approval_request(_request("request-1"), _NOW)
    store.add_approval_request(_request("request-1", summary="updated"), _LATER)
    store.resolve_approval_request(
        "request-1",
        resolution_action="approve",
        resolution_scope="artifact",
        reason="approved",
        resolved_at=_LATER,
    )

    rows = store.list_ready_review_events(now=_LATER, limit=10, **binding)
    assert [row["event_type"] for row in rows] == [
        "review.request.created",
        "review.request.refreshed",
        "review.request.resolved",
    ]
    assert [row["request_sequence"] for row in rows] == [1, 2, 3]
    assert [row["stream_sequence"] for row in rows] == sorted(as_int(row["stream_sequence"]) for row in rows)
    resolved_payload = json.loads(str(rows[-1]["payload_json"]))
    assert resolved_payload["status"] == "resolved"
    assert resolved_payload["resolutionAction"] == "approve"


def test_global_stream_sequence_is_distinct_from_per_request_sequence(tmp_path) -> None:
    store = GuardStore(tmp_path / "guard")
    binding = _connect(store)
    store.add_approval_request(_request("request-a"), _NOW)
    store.add_approval_request(_request("request-b"), _NOW)
    store.add_approval_request(_request("request-a", summary="refreshed"), _LATER)

    rows = store.list_ready_review_events(now=_LATER, limit=10, **binding)
    assert [row["stream_sequence"] for row in rows] == [1, 2, 3]
    assert [(row["local_request_id"], row["request_sequence"]) for row in rows] == [
        ("request-a", 1),
        ("request-b", 1),
        ("request-a", 2),
    ]


def test_acknowledgement_compacts_only_contiguous_binding_prefix(tmp_path) -> None:
    store = GuardStore(tmp_path / "guard")
    binding = _connect(store)
    store.add_approval_request(_request("request-a"), _NOW)
    store.add_approval_request(_request("request-b"), _NOW)
    store.add_approval_request(_request("request-c"), _NOW)
    rows = store.list_ready_review_events(now=_NOW, limit=10, **binding)
    first, quarantined, third = (as_int(row["sequence"]) for row in rows)
    assert (
        store.quarantine_review_event(
            quarantined,
            reason="payload_invalid",
            error="invalid payload",
            **binding,
        )
        == 1
    )

    assert store.acknowledge_review_events([third], **binding) == 0
    assert len(store.list_ready_review_events(now=_NOW, limit=10, **binding)) == 1
    assert store.acknowledge_review_events([first], **binding) == 2

    with store._connect() as connection:
        cursor = connection.execute("select acknowledged_stream_sequence from guard_review_outbox_cursors").fetchone()
        retained = connection.execute(
            "select stream_sequence, binding_status from guard_review_outbox_events"
        ).fetchall()
    assert cursor is not None
    assert cursor["acknowledged_stream_sequence"] == third
    assert [(row["stream_sequence"], row["binding_status"]) for row in retained] == [(quarantined, "quarantined")]


def test_request_mutations_roll_back_when_event_append_fails(tmp_path) -> None:
    create_store = GuardStore(tmp_path / "create-guard")
    with create_store._connect() as connection:
        connection.execute(
            """
            create trigger reject_review_event before insert on guard_review_outbox_events
            begin select raise(abort, 'event write failed'); end
            """
        )

    with pytest.raises(sqlite3.IntegrityError, match="event write failed"):
        create_store.add_approval_request(_request("request-1"), _NOW)

    assert create_store.get_approval_request("request-1") is None
    assert _all_events(create_store) == []

    resolve_store = GuardStore(tmp_path / "resolve-guard")
    _connect(resolve_store)
    resolve_store.add_approval_request(_request("request-1"), _NOW)
    with resolve_store._connect() as connection:
        connection.execute(
            """
            create trigger reject_resolution_event before insert on guard_review_outbox_events
            when new.event_type = 'review.request.resolved'
            begin select raise(abort, 'resolution event failed'); end
            """
        )

    with pytest.raises(sqlite3.IntegrityError, match="resolution event failed"):
        resolve_store.resolve_approval_request(
            "request-1",
            resolution_action="approve",
            resolution_scope="artifact",
            reason=None,
            resolved_at=_LATER,
        )

    request = resolve_store.get_approval_request("request-1")
    assert request is not None
    assert request["status"] == "pending"
    assert [row["event_type"] for row in _all_events(resolve_store)] == ["review.request.created"]


def test_requeue_appends_snapshot_without_replacing_history(tmp_path) -> None:
    store = GuardStore(tmp_path / "guard")
    binding = _connect(store)
    store.add_approval_request(_request("request-1"), _NOW)

    assert store.requeue_pending_review_events(changed_at=_LATER) == 1
    rows = store.list_ready_review_events(now=_LATER, limit=10, **binding)
    assert [row["event_type"] for row in rows] == [
        "review.request.created",
        "review.request.snapshot_requeued",
    ]
    payload = json.loads(str(rows[-1]["payload_json"]))
    snapshot = payload["requestSnapshot"]
    assert set(snapshot) == set(REVIEW_REQUEST_SNAPSHOT_COLUMNS)
    assert snapshot["harness"] == "codex"
    assert snapshot["policy_action"] == "require-reapproval"
    assert snapshot["artifact_id"] == "codex:project:request-1"
    assert snapshot["scanner_evidence_json"] == "[]"

    reconnect_store = GuardStore(tmp_path / "reconnect-guard")
    reconnect_store.add_approval_request(_request("request-reconnect"), _NOW)
    reconnect_binding = _connect(reconnect_store)
    assert reconnect_store.requeue_pending_review_events(changed_at=_LATER) == 1
    reconnect_store.resolve_approval_request(
        "request-reconnect",
        resolution_action="approve",
        resolution_scope="artifact",
        reason=None,
        resolved_at=_LATER,
    )
    reconnect_rows = reconnect_store.list_ready_review_events(now=_LATER, limit=10, **reconnect_binding)
    assert [row["event_type"] for row in reconnect_rows] == [
        "review.request.created",
        "review.request.snapshot_requeued",
        "review.request.resolved",
    ]
    assert [decode_stored_review_event(row).request_sequence for row in reconnect_rows] == [1, 2, 3]
    with reconnect_store._connect() as connection:
        sequence_binding = connection.execute(
            """
            select oauth_source, oauth_subject_hash, workspace_id, machine_id, machine_installation_id
            from guard_review_outbox_request_sequences where local_request_id = 'request-reconnect'
            """
        ).fetchone()
        partial_index = connection.execute(
            "select sql from sqlite_master where name = 'idx_guard_review_outbox_empty_payload_digest'"
        ).fetchone()
    assert sequence_binding is not None
    assert tuple(sequence_binding) == ("default", *reconnect_binding.values())
    assert partial_index is not None and "where payload_hash = ''" in str(partial_index["sql"])


def test_requeue_never_retargets_request_after_identity_change(tmp_path) -> None:
    store = GuardStore(tmp_path / "guard")
    old_binding = _connect(store, grant_id="grant-old", workspace_id="workspace-old")
    store.add_approval_request(_request("request-1"), _NOW)
    new_binding = _connect(store, grant_id="grant-new", workspace_id="workspace-new")

    assert store.requeue_pending_review_events(changed_at=_LATER) == 1

    rows = _all_events(store)
    assert len(rows) == 2
    assert rows[-1]["oauth_subject_hash"] == old_binding["oauth_subject_hash"]
    assert rows[-1]["workspace_id"] == old_binding["workspace_id"]
    assert rows[-1]["binding_status"] == "quarantined"
    assert rows[-1]["quarantine_reason"] == "identity_changed_requires_confirmation"
    assert store.list_ready_review_events(now=_LATER, limit=10, **new_binding) == []


def test_same_subject_refresh_updates_machine_binding_without_confirmation(tmp_path) -> None:
    store = GuardStore(tmp_path / "guard")
    old_binding = _connect(store, machine_id="machine-old")
    store.add_approval_request(_request("request-1"), _NOW)
    new_binding = _connect(store, machine_id="machine-new")

    assert store.refresh_review_event_outbox_binding() == 1
    assert store.list_ready_review_events(now=_NOW, limit=10, **old_binding) == []
    rows = store.list_ready_review_events(now=_NOW, limit=10, **new_binding)
    assert len(rows) == 1
    assert decode_stored_review_event(rows[0]).request_sequence == 1


def test_cross_subject_or_workspace_change_requires_explicit_reassignment(tmp_path) -> None:
    store = GuardStore(tmp_path / "guard")
    old_binding = _connect(store, grant_id="grant-old", workspace_id="workspace-old")
    store.add_approval_request(_request("request-1"), _NOW)
    new_binding = _connect(store, grant_id="grant-new", workspace_id="workspace-new")

    assert store.refresh_review_event_outbox_binding_for_identity(**new_binding) == 1
    assert store.list_ready_review_events(now=_NOW, limit=10, **old_binding) == []
    assert store.list_ready_review_events(now=_NOW, limit=10, **new_binding) == []
    with pytest.raises(ValueError, match="approved source"):
        store.reassign_quarantined_review_events(
            approved_source="other",
            approved_workspace_id="workspace-new",
        )
    with pytest.raises(ValueError, match="approved workspace"):
        store.reassign_quarantined_review_events(
            approved_source="default",
            approved_workspace_id="workspace-old",
        )
    assert (
        store.reassign_quarantined_review_events(
            approved_source="default",
            approved_workspace_id="workspace-new",
        )
        == 1
    )
    reassigned = store.list_ready_review_events(now=_NOW, limit=10, **new_binding)
    assert len(reassigned) == 1
    assert decode_stored_review_event(reassigned[0]).request_sequence == 1


def test_oauth_source_remains_immutable(tmp_path) -> None:
    store = GuardStore(tmp_path / "guard")
    _connect(store)
    store.add_approval_request(_request("request-1"), _NOW)
    with store._connect() as connection, pytest.raises(sqlite3.IntegrityError, match="immutable"):
        connection.execute("update approval_requests set oauth_source = 'other' where request_id = 'request-1'")


def test_retry_metadata_updates_event_without_replacing_it(tmp_path) -> None:
    store = GuardStore(tmp_path / "guard")
    binding = _connect(store)
    store.add_approval_request(_request("request-1"), _NOW)
    row = store.list_ready_review_events(now=_NOW, limit=1, **binding)[0]

    assert store.retry_review_events([as_int(row["sequence"])], now=_NOW, error="offline", **binding) == 1
    assert store.list_ready_review_events(now=_NOW, limit=1, **binding) == []
    retried = store.list_ready_review_events(now="9999-01-01T00:00:00+00:00", limit=1, **binding)
    assert retried[0]["event_id"] == row["event_id"]
    assert retried[0]["attempt_count"] == 1


def _retired_outbox_connection() -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.execute(
        "create table sync_state (state_key text primary key, payload_json text not null, updated_at text not null)"
    )
    connection.execute("create table approval_requests (request_id text primary key)")
    connection.execute(
        """
        create table guard_live_request_outbox (
          sequence integer primary key autoincrement, local_request_id text not null,
          changed_at text not null, oauth_source text, oauth_subject_hash text,
          workspace_id text, machine_id text, machine_installation_id text,
          attempt_count integer not null default 0, next_attempt_at text, last_error text
        )
        """
    )
    return connection


def test_retired_outbox_rows_migrate_once_without_data_loss() -> None:
    connection = _retired_outbox_connection()
    for changed_at in (_NOW, _LATER):
        connection.execute(
            """
            insert into guard_live_request_outbox (
              local_request_id, changed_at, oauth_source, oauth_subject_hash,
              workspace_id, machine_id, machine_installation_id
            ) values ('request-1', ?, 'default', 'subject-1',
                      'workspace-1', 'machine-1', 'installation-1')
            """,
            (changed_at,),
        )

    ensure_review_event_outbox_schema(connection, _LATER)
    connection.execute("delete from sync_state where state_key = 'guard_review_outbox_events_migrated'")
    ensure_review_event_outbox_schema(connection, _LATER)

    rows = connection.execute("select * from guard_review_outbox_events order by request_sequence").fetchall()
    assert [(row["local_request_id"], row["request_sequence"]) for row in rows] == [
        ("request-1", 1),
        ("request-1", 2),
    ]
    assert all(row["quarantine_reason"] == "retired_request_snapshot_missing" for row in rows)
    assert all(
        row["payload_hash"]
        == review_event_payload_digest(
            str(row["payload_json"]),
            oauth_source=row["oauth_source"],
            oauth_subject_hash=row["oauth_subject_hash"],
            workspace_id=row["workspace_id"],
            machine_id=row["machine_id"],
            machine_installation_id=row["machine_installation_id"],
        )
        for row in rows
    )
    assert (
        connection.execute(
            "select 1 from sqlite_master where type = 'table' and name = 'guard_live_request_outbox'"
        ).fetchone()
        is None
    )
    assert (
        connection.execute(
            "select 1 from sync_state where state_key = 'guard_review_outbox_events_migrated'"
        ).fetchone()
        is not None
    )


def test_retired_outbox_incomplete_identity_stays_quarantined() -> None:
    connection = _retired_outbox_connection()
    connection.execute(
        "insert into guard_live_request_outbox (local_request_id, changed_at, oauth_source) values (?, ?, ?)",
        ("request-1", _NOW, "default"),
    )

    ensure_review_event_outbox_schema(connection, _LATER)

    row = connection.execute("select binding_status, quarantine_reason from guard_review_outbox_events").fetchone()
    assert row is not None
    assert (row["binding_status"], row["quarantine_reason"]) == (
        "quarantined",
        "retired_request_snapshot_missing",
    )
