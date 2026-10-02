"""Transactional writes for the local Review event outbox."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Mapping
from uuid import uuid4

from .continuation_snapshot import validated_continuation_snapshot
from .review_correlation import cloud_review_correlation_id
from .review_event_integrity import review_event_payload_digest
from .store_review_event_outbox_binding import bind_review_events_for_request, load_review_oauth_binding
from .store_review_event_outbox_schema import REVIEW_EVENT_SCHEMA_VERSION, review_event_payload_json

# pyright: reportAny=false, reportUnusedCallResult=false

_MAX_SAFE_STREAM_SEQUENCE = (1 << 53) - 1
_MAX_SNAPSHOT_SEQUENCE_COLLISIONS = 256
_REVIEW_BINDING_COLUMNS = (
    "oauth_subject_hash",
    "workspace_id",
    "machine_id",
    "machine_installation_id",
)


def recover_review_snapshot_sequences(
    connection: sqlite3.Connection,
    *,
    source: str,
    collisions: dict[int, str],
    acknowledged_through: int,
    binding: tuple[str, str, str, str],
) -> dict[int, int]:
    """Rebase authenticated snapshot events after a Cloud sequence collision."""

    if (
        type(collisions) is not dict
        or not collisions
        or len(collisions) > _MAX_SNAPSHOT_SEQUENCE_COLLISIONS
        or type(acknowledged_through) is not int
        or not 0 <= acknowledged_through <= _MAX_SAFE_STREAM_SEQUENCE
        or len(binding) != 4
        or not all(isinstance(value, str) and value and value.strip() == value for value in binding)
    ):
        return {}
    normalized: dict[int, str] = {}
    for old_sequence, event_id in collisions.items():
        if (
            type(old_sequence) is not int
            or not 0 < old_sequence <= _MAX_SAFE_STREAM_SEQUENCE
            or not isinstance(event_id, str)
            or not event_id
            or event_id.strip() != event_id
        ):
            return {}
        normalized[old_sequence] = event_id
    if len(set(normalized.values())) != len(normalized):
        return {}

    connection.execute("begin immediate")

    def _abort() -> dict[int, int]:
        connection.rollback()
        return {}

    current = load_review_oauth_binding(connection, source)
    if current is None or tuple(current[key] for key in _REVIEW_BINDING_COLUMNS) != binding:
        return _abort()

    sequences = sorted(normalized)
    sequence_placeholders = ", ".join("?" for _ in sequences)
    rows = connection.execute(
        "select * from guard_review_outbox_events where stream_sequence in (" + sequence_placeholders + ")",
        sequences,
    ).fetchall()
    rows_by_sequence = {int(row["stream_sequence"]): row for row in rows}
    if len(rows_by_sequence) != len(normalized):
        return _abort()

    from .runtime.review_event_delivery import StoredReviewEventError, decode_stored_review_event

    collided_ids = tuple(normalized.values())
    collided_id_placeholders = ", ".join("?" for _ in collided_ids)
    for old_sequence in sequences:
        row = rows_by_sequence[old_sequence]
        later = connection.execute(
            "select 1 from guard_review_outbox_events "
            "where local_request_id = ? and request_sequence > ? "
            "and acknowledged_at is null and oauth_source = ? "
            "and event_id not in (" + collided_id_placeholders + ") limit 1",
            (row["local_request_id"], row["request_sequence"], source, *collided_ids),
        ).fetchone()
        if later is not None:
            return _abort()
        if (
            row["event_id"] != normalized[old_sequence]
            or row["oauth_source"] != source
            or tuple(row[key] for key in _REVIEW_BINDING_COLUMNS) != binding
            or row["binding_status"] != "ready"
            or row["acknowledged_at"] is not None
            or row["event_type"] != "review.request.snapshot_requeued"
        ):
            return _abort()
        try:
            stored_event = decode_stored_review_event(dict(row))
        except (StoredReviewEventError, TypeError, ValueError):
            return _abort()
        if (
            stored_event.stream_sequence != old_sequence
            or stored_event.event_id != normalized[old_sequence]
            or stored_event.event_type != "review.request.snapshot_requeued"
        ):
            return _abort()

    local_cursor_row = connection.execute(
        """
        select acknowledged_stream_sequence
        from guard_review_outbox_cursors
        where oauth_source = ? and oauth_subject_hash = ? and workspace_id = ?
          and machine_id = ? and machine_installation_id = ?
        """,
        (source, *binding),
    ).fetchone()
    local_cursor = int(local_cursor_row["acknowledged_stream_sequence"]) if local_cursor_row is not None else 0
    local_max_row = connection.execute(
        "select coalesce(max(stream_sequence), 0) as maximum from guard_review_outbox_events"
    ).fetchone()
    local_max = int(local_max_row["maximum"]) if local_max_row is not None else 0
    sqlite_sequence_row = connection.execute(
        "select seq from sqlite_sequence where name = 'guard_review_outbox_events'"
    ).fetchone()
    sqlite_sequence = int(sqlite_sequence_row["seq"]) if sqlite_sequence_row is not None else 0
    base = max(acknowledged_through, local_cursor, local_max, sqlite_sequence)
    if base > _MAX_SAFE_STREAM_SEQUENCE - len(sequences):
        return _abort()
    replacements = {old_sequence: base + index for index, old_sequence in enumerate(sequences, start=1)}

    for old_sequence in sequences:
        cursor = connection.execute(
            """
            update guard_review_outbox_events
            set stream_sequence = ?
            where stream_sequence = ? and event_id = ? and oauth_source = ?
              and oauth_subject_hash = ? and workspace_id = ?
              and machine_id = ? and machine_installation_id = ?
              and binding_status = 'ready' and acknowledged_at is null
            """,
            (
                replacements[old_sequence],
                old_sequence,
                normalized[old_sequence],
                source,
                *binding,
            ),
        )
        if cursor.rowcount != 1:
            raise sqlite3.IntegrityError("Review snapshot sequence recovery lost its validated row.")

    final_sequence = replacements[sequences[-1]]
    sequence_update = connection.execute(
        "update sqlite_sequence set seq = max(seq, ?) where name = 'guard_review_outbox_events'",
        (final_sequence,),
    )
    if sequence_update.rowcount == 0:
        connection.execute(
            "insert into sqlite_sequence (name, seq) values ('guard_review_outbox_events', ?)",
            (final_sequence,),
        )
    return replacements


def _binding_for_append(
    connection: sqlite3.Connection,
    *,
    request_id: str,
    source: str,
) -> tuple[Mapping[str, str | None], str, str | None]:
    current = load_review_oauth_binding(connection, source)
    prior = connection.execute(
        """
        select oauth_subject_hash, workspace_id, machine_id, machine_installation_id
        from guard_review_outbox_request_sequences
        where local_request_id = ?
        """,
        (request_id,),
    ).fetchone()
    if prior is None:
        values = current or {
            "oauth_subject_hash": None,
            "workspace_id": None,
            "machine_id": None,
            "machine_installation_id": None,
        }
        return (
            values,
            "ready" if current is not None else "quarantined",
            (None if current is not None else "identity_incomplete"),
        )
    prior_values = {
        key: prior[key] for key in ("oauth_subject_hash", "workspace_id", "machine_id", "machine_installation_id")
    }
    prior_complete = all(isinstance(value, str) and value.strip() for value in prior_values.values())
    if not prior_complete:
        return prior_values, "quarantined", "identity_incomplete"
    if current is None or (
        prior_values["oauth_subject_hash"] != current["oauth_subject_hash"]
        or prior_values["workspace_id"] != current["workspace_id"]
    ):
        return prior_values, "quarantined", "identity_changed_requires_confirmation"
    return current, "ready", None


def append_request_snapshot_event(
    connection: sqlite3.Connection,
    *,
    request_id: str,
    source: str,
    event_type: str,
    occurred_at: str,
    continuation_result: Mapping[str, object] | None = None,
) -> int:
    """Append a request snapshot without replacing any unacknowledged event."""

    request = connection.execute(
        "select * from approval_requests where request_id = ?",
        (request_id,),
    ).fetchone()
    if request is None:
        return 0
    values, binding_status, quarantine_reason = _binding_for_append(
        connection,
        request_id=request_id,
        source=source,
    )
    payload = review_event_payload_json(
        dict(request),
        event_type=event_type,
        occurred_at=occurred_at,
        continuation_result=continuation_result,
    )
    connection.execute(
        """
        insert into guard_review_outbox_request_sequences (
          local_request_id, last_sequence, updated_at, oauth_source,
          oauth_subject_hash, workspace_id, machine_id, machine_installation_id
        ) values (?, 1, ?, ?, ?, ?, ?, ?)
        on conflict(local_request_id) do update set
          last_sequence = guard_review_outbox_request_sequences.last_sequence + 1,
          updated_at = excluded.updated_at,
          oauth_source = coalesce(guard_review_outbox_request_sequences.oauth_source, excluded.oauth_source),
          oauth_subject_hash = coalesce(
            guard_review_outbox_request_sequences.oauth_subject_hash,
            excluded.oauth_subject_hash
          ),
          workspace_id = coalesce(guard_review_outbox_request_sequences.workspace_id, excluded.workspace_id),
          machine_id = coalesce(guard_review_outbox_request_sequences.machine_id, excluded.machine_id),
          machine_installation_id = coalesce(
            guard_review_outbox_request_sequences.machine_installation_id,
            excluded.machine_installation_id
          )
        """,
        (
            request_id,
            occurred_at,
            source,
            values["oauth_subject_hash"],
            values["workspace_id"],
            values["machine_id"],
            values["machine_installation_id"],
        ),
    )
    row = connection.execute(
        "select last_sequence from guard_review_outbox_request_sequences where local_request_id = ?",
        (request_id,),
    ).fetchone()
    if row is None:
        raise RuntimeError("Review event request sequence allocation failed.")
    request_sequence = int(row["last_sequence"])
    cursor = connection.execute(
        """
        insert into guard_review_outbox_events (
          event_id, local_request_id, request_sequence, event_type, event_schema_version,
          payload_json, payload_hash, occurred_at, oauth_source, oauth_subject_hash,
          workspace_id, machine_id, machine_installation_id, binding_status, quarantine_reason
        ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            uuid4().hex,
            request_id,
            request_sequence,
            event_type,
            REVIEW_EVENT_SCHEMA_VERSION,
            payload,
            review_event_payload_digest(
                payload,
                oauth_source=source,
                oauth_subject_hash=values["oauth_subject_hash"],
                workspace_id=values["workspace_id"],
                machine_id=values["machine_id"],
                machine_installation_id=values["machine_installation_id"],
            ),
            occurred_at,
            source,
            values["oauth_subject_hash"],
            values["workspace_id"],
            values["machine_id"],
            values["machine_installation_id"],
            binding_status,
            quarantine_reason,
        ),
    )
    return max(0, int(cursor.rowcount or 0))


def requeue_pending_request_events(
    connection: sqlite3.Connection,
    *,
    source: str,
    changed_at: str,
    require_binding: bool = False,
    snapshot_repair_sequences: dict[str, int] | None = None,
    only_retry_identity_drift: bool = False,
) -> int:
    connection.execute("begin immediate")
    current_binding = load_review_oauth_binding(connection, source)
    if require_binding and current_binding is None:
        return 0
    if snapshot_repair_sequences is not None and not snapshot_repair_sequences:
        return 0
    current_identity = (
        (
            source,
            current_binding["oauth_subject_hash"],
            current_binding["workspace_id"],
            current_binding["machine_id"],
            current_binding["machine_installation_id"],
        )
        if current_binding is not None
        else None
    )
    request_query = """
        select request_id, continuation_snapshot_json from approval_requests
        where status = 'pending' and oauth_source = ?
    """
    request_parameters: list[object] = [source]
    if snapshot_repair_sequences is not None:
        request_query += " and request_id in (" + ", ".join("?" for _ in snapshot_repair_sequences) + ")"
        request_parameters.extend(snapshot_repair_sequences)
    rows = connection.execute(
        request_query + " order by coalesce(last_seen_at, created_at), request_id", request_parameters
    ).fetchall()
    appended = 0
    for row in rows:
        request_id = str(row["request_id"])
        if only_retry_identity_drift:
            try:
                frozen = validated_continuation_snapshot(json.loads(row["continuation_snapshot_json"]))
            except (TypeError, ValueError):
                frozen = None
            if (
                frozen is None
                or frozen["capability"] not in {"retry-only", "unsupported"}
                or frozen["correlationId"] == cloud_review_correlation_id(request_id)
            ):
                continue
        if require_binding and current_binding is not None:
            established = connection.execute(
                """
                select 1 from guard_review_outbox_request_sequences
                where local_request_id = ? and oauth_source = ?
                  and oauth_subject_hash = ? and workspace_id = ?
                  and machine_id = ? and machine_installation_id = ?
                """,
                (
                    request_id,
                    source,
                    current_binding["oauth_subject_hash"],
                    current_binding["workspace_id"],
                    current_binding["machine_id"],
                    current_binding["machine_installation_id"],
                ),
            ).fetchone()
            if established is None:
                # Enabling decisions is not consent to upload another account's
                # requests or requests whose original identity was lost.
                continue
        snapshot_query = """
            select oauth_source, oauth_subject_hash, workspace_id, machine_id,
                   machine_installation_id, binding_status
            from guard_review_outbox_events
            where local_request_id = ?
              and event_type = 'review.request.snapshot_requeued'
        """
        snapshot_parameters: list[object] = [request_id]
        if snapshot_repair_sequences is None:
            snapshot_query += " and acknowledged_at is null"
        else:
            # A newer durable snapshot already repairs this event. Do not keep
            # appending snapshots if an older server repeats the rejection.
            snapshot_query += " and request_sequence > ?"
            snapshot_parameters.append(snapshot_repair_sequences[request_id])
        existing_snapshot = connection.execute(
            snapshot_query + " order by request_sequence desc limit 1", snapshot_parameters
        ).fetchone()
        if (
            existing_snapshot is not None
            and current_identity is not None
            and (
                str(existing_snapshot["binding_status"]) == "ready"
                and (
                    str(existing_snapshot["oauth_source"]),
                    existing_snapshot["oauth_subject_hash"],
                    existing_snapshot["workspace_id"],
                    existing_snapshot["machine_id"],
                    existing_snapshot["machine_installation_id"],
                )
                == current_identity
            )
        ):
            continue
        bind_review_events_for_request(connection, request_id=request_id, oauth_source=source)
        appended += append_request_snapshot_event(
            connection,
            request_id=request_id,
            source=source,
            event_type="review.request.snapshot_requeued",
            occurred_at=changed_at,
        )
    return appended
