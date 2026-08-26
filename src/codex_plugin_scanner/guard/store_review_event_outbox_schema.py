"""Schema and migration for the append-only local Review event outbox."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Mapping
from typing import Final
from uuid import uuid4

from .review_event_integrity import review_event_payload_digest
from .store_review_event_outbox_upgrade import ensure_review_event_outbox_upgrade

# pyright: reportAny=false, reportUnusedCallResult=false

REVIEW_EVENT_SCHEMA_VERSION: Final = 1
REVIEW_EVENT_SCHEMA_NAME: Final = "guard-cloud-review-event-v2"
REVIEW_EVENT_OUTBOX_MIGRATION_VERSION: Final = 25
_RETIRED_OUTBOX_MIGRATION_STATE_KEY: Final = "guard_review_outbox_events_migrated"
REVIEW_REQUEST_SNAPSHOT_COLUMNS: Final = (
    "request_id",
    "harness",
    "artifact_id",
    "artifact_name",
    "artifact_type",
    "artifact_hash",
    "publisher",
    "policy_action",
    "recommended_scope",
    "changed_fields_json",
    "source_scope",
    "oauth_source",
    "config_path",
    "workspace",
    "launch_target",
    "normalized_identity_key",
    "action_identity",
    "queue_group_id",
    "dedupe_count",
    "last_seen_at",
    "transport",
    "risk_summary",
    "risk_signals_json",
    "artifact_label",
    "source_label",
    "trigger_summary",
    "why_now",
    "launch_summary",
    "risk_headline",
    "action_envelope_json",
    "decision_v2_json",
    "fallback_cli_command",
    "scanner_evidence_json",
    "browser_intent_json",
    "continuation_snapshot_json",
    "desktop_notified_at",
    "raw_command_text",
    "guard_version",
    "first_seen_guard_version",
    "last_seen_guard_version",
    "watch_only_observation",
    "review_command",
    "approval_url",
    "status",
    "resolution_action",
    "resolution_scope",
    "reason",
    "created_at",
    "resolved_at",
)


def finalize_review_event_payload_hashes(connection: sqlite3.Connection) -> None:
    """Finalize trigger-written hashes inside the surrounding SQLite transaction."""

    rows = connection.execute(
        """
        select stream_sequence, payload_json, oauth_source, oauth_subject_hash,
               workspace_id, machine_id, machine_installation_id
        from guard_review_outbox_events where payload_hash = ''
        """
    ).fetchall()
    for row in rows:
        payload = str(row["payload_json"])
        connection.execute(
            "update guard_review_outbox_events set payload_hash = ? where stream_sequence = ?",
            (
                review_event_payload_digest(
                    payload,
                    oauth_source=row["oauth_source"],
                    oauth_subject_hash=row["oauth_subject_hash"],
                    workspace_id=row["workspace_id"],
                    machine_id=row["machine_id"],
                    machine_installation_id=row["machine_installation_id"],
                ),
                row["stream_sequence"],
            ),
        )


def _event_payload(prefix: str, event_type: str) -> str:
    snapshot = ",\n        ".join(f"'{column}', {prefix}.{column}" for column in REVIEW_REQUEST_SNAPSHOT_COLUMNS)
    return f"""json_object(
      'schema', '{REVIEW_EVENT_SCHEMA_NAME}',
      'localRequestId', {prefix}.request_id,
      'eventType', '{event_type}',
      'occurredAt', coalesce({prefix}.resolved_at, {prefix}.last_seen_at, {prefix}.created_at),
      'status', {prefix}.status,
      'resolutionAction', {prefix}.resolution_action,
      'resolutionScope', {prefix}.resolution_scope,
      'reason', {prefix}.reason,
      'oauthSource', {prefix}.oauth_source,
      'requestSnapshot', json_object(
        {snapshot}
      )
    )"""


def review_event_payload_json(
    request: Mapping[str, object],
    *,
    event_type: str,
    occurred_at: str,
    continuation_result: Mapping[str, object] | None = None,
) -> str:
    """Build the canonical immutable event payload from a complete request row."""

    missing = [column for column in REVIEW_REQUEST_SNAPSHOT_COLUMNS if column not in request]
    if missing:
        raise ValueError(f"Review request snapshot is missing columns: {', '.join(missing)}")
    snapshot = {column: request[column] for column in REVIEW_REQUEST_SNAPSHOT_COLUMNS}
    payload = {
        "schema": REVIEW_EVENT_SCHEMA_NAME,
        "localRequestId": request["request_id"],
        "eventType": event_type,
        "occurredAt": occurred_at,
        "status": request["status"],
        "resolutionAction": request["resolution_action"],
        "resolutionScope": request["resolution_scope"],
        "reason": request["reason"],
        "oauthSource": request["oauth_source"],
        "requestSnapshot": snapshot,
    }
    if continuation_result is not None:
        payload["continuationResult"] = dict(continuation_result)
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _binding_value(column: str) -> str:
    return f"""(
      select {column}
      from guard_review_outbox_request_sequences
      where local_request_id = new.request_id
    )"""


def _insert_trigger() -> str:
    payload = _event_payload("new", "review.request.created")
    return f"""
        create trigger if not exists guard_review_outbox_after_insert
        after insert on approval_requests
        begin
          insert into guard_review_outbox_request_sequences (
            local_request_id, last_sequence, updated_at
          ) values (new.request_id, 1, coalesce(new.last_seen_at, new.created_at))
          on conflict(local_request_id) do update set
            last_sequence = guard_review_outbox_request_sequences.last_sequence + 1,
            updated_at = excluded.updated_at;
          insert into guard_review_outbox_events (
            event_id, local_request_id, request_sequence, event_type,
            event_schema_version, payload_json, payload_hash, occurred_at,
            oauth_source, binding_status, quarantine_reason
          ) values (
            lower(hex(randomblob(16))),
            new.request_id,
            (select last_sequence from guard_review_outbox_request_sequences
             where local_request_id = new.request_id),
            'review.request.created',
            {REVIEW_EVENT_SCHEMA_VERSION},
            {payload},
            '',
            coalesce(new.last_seen_at, new.created_at),
            new.oauth_source,
            'quarantined',
            'identity_incomplete'
          );
        end
    """


def _update_trigger() -> str:
    event_type = "case when old.status <> new.status then 'review.request.resolved' else 'review.request.refreshed' end"
    resolved_payload = _event_payload("new", "review.request.resolved")
    refreshed_payload = _event_payload("new", "review.request.refreshed")
    payload = f"case when old.status <> new.status then {resolved_payload} else {refreshed_payload} end"
    subject = _binding_value("oauth_subject_hash")
    workspace = _binding_value("workspace_id")
    machine = _binding_value("machine_id")
    installation = _binding_value("machine_installation_id")
    source = _binding_value("oauth_source")
    complete = (
        f"{subject} is not null and {workspace} is not null and {machine} is not null and {installation} is not null"
    )
    return f"""
        create trigger if not exists guard_review_outbox_after_update
        after update on approval_requests
        begin
          insert into guard_review_outbox_request_sequences (
            local_request_id, last_sequence, updated_at
          ) values (new.request_id, 1, coalesce(new.resolved_at, new.last_seen_at, new.created_at))
          on conflict(local_request_id) do update set
            last_sequence = guard_review_outbox_request_sequences.last_sequence + 1,
            updated_at = excluded.updated_at;
          insert into guard_review_outbox_events (
            event_id, local_request_id, request_sequence, event_type,
            event_schema_version, payload_json, payload_hash, occurred_at,
            oauth_source, oauth_subject_hash, workspace_id, machine_id,
            machine_installation_id, binding_status, quarantine_reason
          ) values (
            lower(hex(randomblob(16))),
            new.request_id,
            (select last_sequence from guard_review_outbox_request_sequences
             where local_request_id = new.request_id),
            {event_type},
            {REVIEW_EVENT_SCHEMA_VERSION},
            {payload},
            '',
            coalesce(new.resolved_at, new.last_seen_at, new.created_at),
            coalesce({source}, new.oauth_source),
            {subject},
            {workspace},
            {machine},
            {installation},
            case when {complete} then 'ready' else 'quarantined' end,
            case when {complete} then null else 'identity_incomplete' end
          );
        end
    """


def review_event_outbox_schema_statements() -> tuple[str, ...]:
    return (
        """
        create table if not exists guard_review_outbox_events (
          stream_sequence integer primary key autoincrement,
          event_id text not null unique,
          local_request_id text not null,
          request_sequence integer not null,
          event_type text not null,
          event_schema_version integer not null,
          payload_json text not null,
          payload_hash text not null,
          occurred_at text not null,
          oauth_source text,
          oauth_subject_hash text,
          workspace_id text,
          machine_id text,
          machine_installation_id text,
          binding_status text not null check(binding_status in ('ready', 'quarantined')),
          quarantine_reason text,
          acknowledged_at text,
          attempt_count integer not null default 0,
          next_attempt_at text,
          last_error text,
          unique(local_request_id, request_sequence)
        )
        """,
        """
        create table if not exists guard_review_outbox_cursors (
          oauth_source text not null,
          oauth_subject_hash text not null,
          workspace_id text not null,
          machine_id text not null,
          machine_installation_id text not null,
          acknowledged_stream_sequence integer not null default 0,
          updated_at text not null,
          primary key (
            oauth_source, oauth_subject_hash, workspace_id,
            machine_id, machine_installation_id
          )
        )
        """,
        """
        create table if not exists guard_review_outbox_request_sequences (
          local_request_id text primary key,
          last_sequence integer not null check(last_sequence > 0),
          updated_at text not null,
          oauth_source text,
          oauth_subject_hash text,
          workspace_id text,
          machine_id text,
          machine_installation_id text
        )
        """,
        """
        create index if not exists idx_guard_review_outbox_ready
        on guard_review_outbox_events (
          oauth_source, oauth_subject_hash, workspace_id, machine_id,
          machine_installation_id, binding_status, next_attempt_at, stream_sequence
        )
        """,
        """
        create index if not exists idx_guard_review_outbox_request
        on guard_review_outbox_events (local_request_id, request_sequence)
        """,
        """
        create index if not exists idx_guard_review_outbox_quarantine
        on guard_review_outbox_events (binding_status, quarantine_reason, stream_sequence)
        """,
        """
        create index if not exists idx_guard_review_outbox_empty_payload_digest
        on guard_review_outbox_events (payload_hash) where payload_hash = ''
        """,
        """
        create trigger if not exists guard_approval_oauth_source_immutable
        before update of oauth_source on approval_requests
        when old.oauth_source is not null and new.oauth_source is not old.oauth_source
        begin
          select raise(abort, 'approval OAuth source is immutable');
        end
        """,
    )


def _retired_outbox_payload(
    connection: sqlite3.Connection,
    row: sqlite3.Row,
) -> tuple[str, str | None]:
    request = connection.execute(
        "select * from approval_requests where request_id = ?",
        (row["local_request_id"],),
    ).fetchone()
    if request is None:
        return _retired_outbox_marker_payload(row), "retired_request_snapshot_missing"
    request_values = dict(request)
    try:
        payload = review_event_payload_json(
            request_values,
            event_type="review.request.snapshot_migrated",
            occurred_at=str(row["changed_at"]),
        )
    except ValueError:
        return _retired_outbox_marker_payload(row), "retired_request_snapshot_incomplete"
    if request_values.get("oauth_source") != row["oauth_source"]:
        return payload, "retired_request_source_ambiguous"
    return payload, None


def _retired_outbox_marker_payload(row: sqlite3.Row) -> str:
    return json.dumps(
        {
            "schema": REVIEW_EVENT_SCHEMA_NAME,
            "localRequestId": str(row["local_request_id"]),
            "eventType": "review.request.snapshot_migrated",
            "occurredAt": str(row["changed_at"]),
            "retiredSequence": int(row["sequence"]),
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def _migrate_retired_outbox(connection: sqlite3.Connection, now: str) -> None:
    marker = connection.execute(
        "select 1 from sync_state where state_key = ?",
        (_RETIRED_OUTBOX_MIGRATION_STATE_KEY,),
    ).fetchone()
    if marker is not None:
        return
    old_table = connection.execute(
        "select 1 from sqlite_master where type = 'table' and name = 'guard_live_request_outbox'"
    ).fetchone()
    if old_table is not None:
        rows = connection.execute(
            """
            select sequence, local_request_id, changed_at, oauth_source,
                   oauth_subject_hash, workspace_id, machine_id, machine_installation_id,
                   attempt_count, next_attempt_at, last_error
            from guard_live_request_outbox order by sequence
            """
        ).fetchall()
        for row in rows:
            payload, source_quarantine = _retired_outbox_payload(connection, row)
            identity = tuple(
                row[name]
                for name in (
                    "oauth_source",
                    "oauth_subject_hash",
                    "workspace_id",
                    "machine_id",
                    "machine_installation_id",
                )
            )
            complete = all(isinstance(value, str) and value.strip() for value in identity)
            quarantine_reason = source_quarantine or (None if complete else "retired_identity_incomplete")
            connection.execute(
                """
                insert or ignore into guard_review_outbox_events (
                  event_id, local_request_id, request_sequence, event_type,
                  event_schema_version, payload_json, payload_hash, occurred_at,
                  oauth_source, oauth_subject_hash, workspace_id, machine_id,
                  machine_installation_id, binding_status, quarantine_reason,
                  attempt_count, next_attempt_at, last_error
                ) values (?, ?, ?, 'review.request.snapshot_migrated', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    uuid4().hex,
                    row["local_request_id"],
                    row["sequence"],
                    REVIEW_EVENT_SCHEMA_VERSION,
                    payload,
                    review_event_payload_digest(
                        payload,
                        oauth_source=identity[0],
                        oauth_subject_hash=identity[1],
                        workspace_id=identity[2],
                        machine_id=identity[3],
                        machine_installation_id=identity[4],
                    ),
                    row["changed_at"],
                    *identity,
                    "ready" if quarantine_reason is None else "quarantined",
                    quarantine_reason,
                    row["attempt_count"],
                    row["next_attempt_at"],
                    row["last_error"],
                ),
            )
            connection.execute(
                """
                insert into guard_review_outbox_request_sequences (
                  local_request_id, last_sequence, updated_at, oauth_source,
                  oauth_subject_hash, workspace_id, machine_id, machine_installation_id
                ) values (?, ?, ?, ?, ?, ?, ?, ?)
                on conflict(local_request_id) do update set
                  last_sequence = max(last_sequence, excluded.last_sequence), updated_at = excluded.updated_at
                """,
                (row["local_request_id"], row["sequence"], row["changed_at"], *identity),
            )
        connection.execute("drop table guard_live_request_outbox")
    connection.execute(
        "insert into sync_state (state_key, payload_json, updated_at) values (?, '{\"migrated\":true}', ?)",
        (_RETIRED_OUTBOX_MIGRATION_STATE_KEY, now),
    )


def ensure_review_event_outbox_schema(connection: sqlite3.Connection, now: str) -> None:
    for statement in review_event_outbox_schema_statements():
        connection.execute(statement)
    ensure_review_event_outbox_upgrade(connection, migration_version=REVIEW_EVENT_OUTBOX_MIGRATION_VERSION)
    _migrate_retired_outbox(connection, now)
    connection.execute("drop trigger if exists guard_live_request_outbox_after_insert")
    connection.execute("drop trigger if exists guard_live_request_outbox_after_update")
    connection.execute("drop trigger if exists guard_review_outbox_after_insert")
    connection.execute("drop trigger if exists guard_review_outbox_after_update")
    connection.execute(_insert_trigger())
    connection.execute(_update_trigger())
    migrations = connection.execute(
        "select 1 from sqlite_master where type = 'table' and name = 'schema_migrations'"
    ).fetchone()
    if migrations is not None:
        connection.execute(
            "insert or ignore into schema_migrations (version, applied_at) values (?, ?)",
            (REVIEW_EVENT_OUTBOX_MIGRATION_VERSION, now),
        )
