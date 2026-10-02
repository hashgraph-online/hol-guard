from __future__ import annotations

import json
import sqlite3

import pytest

from codex_plugin_scanner.guard.runtime.cloud_review_event_projection import project_cloud_review_event
from codex_plugin_scanner.guard.runtime.review_event_delivery import decode_stored_review_event
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.guard.store_review_event_outbox_schema import REVIEW_REQUEST_SNAPSHOT_COLUMNS
from tests.guard_review_event_outbox_test_support import _all_events, _connect, _DeliveryBinding, _request

# pyright: reportMissingImports=false

_NOW = "2026-08-24T12:00:00+00:00"
_LATER = "2026-08-24T12:00:01+00:00"


def _plain_binding(binding: _DeliveryBinding) -> dict[str, str]:
    return {
        "oauth_subject_hash": binding["oauth_subject_hash"],
        "workspace_id": binding["workspace_id"],
        "machine_id": binding["machine_id"],
        "machine_installation_id": binding["machine_installation_id"],
    }


def _seed_snapshot_sequence_collisions(tmp_path, *, acknowledged_through: int = 529):
    store = GuardStore(tmp_path / "guard")
    binding = _connect(store)
    target_ids = [f"target-{index:02d}" for index in range(23)]
    for request_id in target_ids:
        store.add_approval_request(_request(request_id), _NOW)
    for index in range(10):
        store.add_approval_request(_request(f"filler-{index:02d}"), _NOW)
    with store._connect() as connection:
        connection.executemany(
            "delete from approval_requests where request_id = ?",
            [(f"filler-{index:02d}",) for index in range(10)],
        )

    assert store.requeue_pending_review_events(changed_at=_LATER) == len(target_ids)
    with store._connect() as connection:
        connection.execute(
            """
            insert into guard_review_outbox_cursors (
              oauth_source, oauth_subject_hash, workspace_id, machine_id,
              machine_installation_id, acknowledged_stream_sequence, updated_at
            ) values (?, ?, ?, ?, ?, ?, ?)
            """,
            ("default", *binding.values(), acknowledged_through, _LATER),
        )
        connection.execute(
            """
            update guard_review_outbox_events
            set attempt_count = ?, next_attempt_at = ?, last_error = ?
            where stream_sequence = ?
            """,
            (3, _LATER, "previous collision retry", 34),
        )
        rows = connection.execute(
            """
            select * from guard_review_outbox_events
            where event_type = 'review.request.snapshot_requeued'
            order by stream_sequence
            """
        ).fetchall()
    assert [row["stream_sequence"] for row in rows] == list(range(34, 57))
    return store, binding, rows


def _snapshot_collision_ids(rows: list[sqlite3.Row]) -> dict[int, str]:
    return {int(row["stream_sequence"]): str(row["event_id"]) for row in rows}


def test_requeue_appends_snapshot_without_replacing_history(tmp_path) -> None:
    store = GuardStore(tmp_path / "guard")
    binding = _connect(store)
    store.add_approval_request(_request("request-1"), _NOW)

    assert store.requeue_pending_review_events(changed_at=_LATER) == 1
    assert store.requeue_pending_review_events(changed_at=_LATER) == 0
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


def test_recover_review_snapshot_sequences_preserves_envelopes_and_future_allocations(tmp_path) -> None:
    store, binding, before_rows = _seed_snapshot_sequence_collisions(tmp_path)
    collisions = _snapshot_collision_ids(before_rows)

    replacements = store.recover_review_snapshot_sequences(
        collisions=collisions,
        acknowledged_through=529,
        binding=_plain_binding(binding),
    )
    expected = dict(zip(range(34, 57), range(530, 553), strict=True))
    assert replacements == expected

    after_rows = [row for row in _all_events(store) if row["event_type"] == "review.request.snapshot_requeued"]
    assert [row["stream_sequence"] for row in after_rows] == list(range(530, 553))
    preserved_before = {
        int(row["stream_sequence"]): {key: value for key, value in dict(row).items() if key != "stream_sequence"}
        for row in before_rows
    }
    old_sequence_by_new = {new: old for old, new in replacements.items()}
    for row in after_rows:
        preserved_after = {key: value for key, value in dict(row).items() if key != "stream_sequence"}
        new_sequence = int(row["stream_sequence"])
        assert preserved_after == preserved_before[old_sequence_by_new[new_sequence]]
    decoded = decode_stored_review_event(dict(after_rows[0]))
    assert decoded.stream_sequence == 530
    projected_row = next(
        row
        for row in store.list_ready_review_events(now=_LATER, limit=100, **binding)
        if row["event_id"] == decoded.event_id
    )
    projected = project_cloud_review_event(
        store,
        outbox_row=projected_row,
        delivery_binding=_plain_binding(binding),
        redaction_level="full",
        oauth=None,
    )
    assert projected is not None
    _, projected_event = projected
    assert projected_event["eventId"] == decoded.event_id
    assert projected_event["localStreamSequence"] == 530
    assert projected_event["localRequestId"] == decoded.snapshot["request_id"]
    assert projected_event["eventPayloadJson"] == decoded.payload_json
    assert projected_event["payloadHash"] == decoded.payload_hash

    with store._connect() as connection:
        cursor = connection.execute("select acknowledged_stream_sequence from guard_review_outbox_cursors").fetchone()
        sequence = connection.execute(
            "select seq from sqlite_sequence where name = 'guard_review_outbox_events'"
        ).fetchone()
    assert cursor is not None and cursor["acknowledged_stream_sequence"] == 529
    assert sequence is not None and sequence["seq"] == 552

    store.add_approval_request(_request("future-request"), _LATER)
    future = [row for row in _all_events(store) if row["local_request_id"] == "future-request"]
    assert len(future) == 1 and future[0]["stream_sequence"] == 553


def test_recover_review_snapshot_sequences_allows_collisions_above_cloud_high_water(tmp_path) -> None:
    store, binding, before_rows = _seed_snapshot_sequence_collisions(tmp_path, acknowledged_through=0)

    replacements = store.recover_review_snapshot_sequences(
        collisions=_snapshot_collision_ids(before_rows),
        acknowledged_through=0,
        binding=_plain_binding(binding),
    )

    assert replacements == dict(zip(range(34, 57), range(57, 80), strict=True))


def test_recover_review_snapshot_sequences_defers_when_a_later_event_is_pending(tmp_path) -> None:
    store, binding, before_rows = _seed_snapshot_sequence_collisions(tmp_path)
    store.resolve_approval_request(
        "target-00",
        resolution_action="approve",
        resolution_scope="artifact",
        reason=None,
        resolved_at=_LATER,
    )

    assert (
        store.recover_review_snapshot_sequences(
            collisions={int(before_rows[0]["stream_sequence"]): str(before_rows[0]["event_id"])},
            acknowledged_through=529,
            binding=_plain_binding(binding),
        )
        == {}
    )
    snapshot = next(row for row in _all_events(store) if row["event_id"] == before_rows[0]["event_id"])
    assert snapshot["stream_sequence"] == before_rows[0]["stream_sequence"]


def test_recover_review_snapshot_sequences_rejects_mismatch_binding_and_acknowledged_rows(tmp_path) -> None:
    store, binding, before_rows = _seed_snapshot_sequence_collisions(tmp_path)
    collisions = _snapshot_collision_ids(before_rows)

    wrong_event_id = dict(collisions)
    wrong_event_id[34] = "not-the-stored-event"
    assert (
        store.recover_review_snapshot_sequences(
            collisions=wrong_event_id,
            acknowledged_through=529,
            binding=_plain_binding(binding),
        )
        == {}
    )
    wrong_binding: _DeliveryBinding = {**binding, "workspace_id": "other-workspace"}
    assert (
        store.recover_review_snapshot_sequences(
            collisions=collisions,
            acknowledged_through=529,
            binding=_plain_binding(wrong_binding),
        )
        == {}
    )
    with store._connect() as connection:
        connection.execute(
            "update guard_review_outbox_events set acknowledged_at = ? where stream_sequence = ?",
            (_LATER, 35),
        )
    assert (
        store.recover_review_snapshot_sequences(
            collisions=collisions,
            acknowledged_through=529,
            binding=_plain_binding(binding),
        )
        == {}
    )
    snapshot_sequences = [
        row["stream_sequence"] for row in _all_events(store) if row["event_type"] == "review.request.snapshot_requeued"
    ]
    assert snapshot_sequences == list(range(34, 57))


def test_recover_review_snapshot_sequences_rolls_back_all_updates_on_failure(tmp_path) -> None:
    store, binding, before_rows = _seed_snapshot_sequence_collisions(tmp_path)
    collisions = _snapshot_collision_ids(before_rows)
    with store._connect() as connection:
        connection.execute(
            """
            create trigger reject_review_snapshot_resequence
            before update of stream_sequence on guard_review_outbox_events
            when old.stream_sequence = 40
            begin
              select raise(abort, 'snapshot re-sequence failed');
            end
            """
        )

    with pytest.raises(sqlite3.IntegrityError, match="snapshot re-sequence failed"):
        store.recover_review_snapshot_sequences(
            collisions=collisions,
            acknowledged_through=529,
            binding=_plain_binding(binding),
        )
    after_rows = [row for row in _all_events(store) if row["event_type"] == "review.request.snapshot_requeued"]
    assert [row["stream_sequence"] for row in after_rows] == list(range(34, 57))
    with store._connect() as connection:
        sequence = connection.execute(
            "select seq from sqlite_sequence where name = 'guard_review_outbox_events'"
        ).fetchone()
        connection.execute("drop trigger reject_review_snapshot_resequence")
    assert sequence is not None and sequence["seq"] == 56
    assert store.recover_review_snapshot_sequences(
        collisions=collisions,
        acknowledged_through=529,
        binding=_plain_binding(binding),
    ) == dict(zip(range(34, 57), range(530, 553), strict=True))
