"""Approval queue persistence helpers for the local Guard store."""

from __future__ import annotations

import base64
import json
import sqlite3
from pathlib import Path

from .native_approval_queue_identity import (
    ApprovalQueueIdentityUnavailableError,
    connection_guard_home,
    native_approval_queue_identities,
    queue_identity_item,
)

APPROVAL_QUEUE_BACKFILL_BATCH_SIZE = 500


class InvalidApprovalCursorError(ValueError):
    pass


def approval_schema_statement() -> str:
    return """
        create table if not exists approval_requests (
          request_id text primary key,
          harness text not null,
          artifact_id text not null,
          artifact_name text not null,
          artifact_type text not null,
          artifact_hash text not null,
          publisher text,
          policy_action text not null,
          recommended_scope text not null,
          changed_fields_json text not null,
          source_scope text not null,
          oauth_source text,
          config_path text not null,
          workspace text,
          launch_target text,
          normalized_identity_key text,
          action_identity text,
          queue_group_id text,
          dedupe_count integer not null default 1,
          last_seen_at text,
          transport text,
          risk_summary text,
          risk_signals_json text not null default '[]',
          artifact_label text,
          source_label text,
          trigger_summary text,
          why_now text,
          launch_summary text,
          risk_headline text,
          action_envelope_json text,
          decision_v2_json text,
          fallback_cli_command text,
          scanner_evidence_json text not null default '[]',
          browser_intent_json text,
          desktop_notified_at text,
          raw_command_text text,
          continuation_snapshot_json text,
          extension_allow_hint_json text,
          guard_version text,
          first_seen_guard_version text,
          last_seen_guard_version text,
          watch_only_observation integer not null default 0,
          review_command text not null,
          approval_url text not null,
          status text not null,
          resolution_action text,
          resolution_scope text,
          reason text,
          created_at text not null,
          resolved_at text
        )
        """


def approval_index_statements() -> list[str]:
    return [
        "create index if not exists idx_approval_status_created on approval_requests(status, created_at desc)",
        (
            "create index if not exists idx_approval_status_harness_created "
            "on approval_requests(status, harness, created_at desc)"
        ),
        (
            "create index if not exists idx_approval_status_identity_workspace "
            "on approval_requests(status, normalized_identity_key, workspace)"
        ),
        (
            "create index if not exists idx_approval_source_group_status "
            "on approval_requests(oauth_source, queue_group_id, status)"
        ),
        (
            "create index if not exists idx_approval_status_last_seen "
            "on approval_requests(status, last_seen_at desc, request_id desc)"
        ),
        (
            "create index if not exists idx_approval_status_harness_last_seen "
            "on approval_requests(status, harness, last_seen_at desc, request_id desc)"
        ),
        "create index if not exists idx_approval_harness_status on approval_requests(harness, status)",
        "create index if not exists idx_approval_artifact_hash on approval_requests(artifact_hash)",
        "create index if not exists idx_approval_workspace_status on approval_requests(workspace, status)",
        "create index if not exists idx_approval_policy_action on approval_requests(policy_action)",
        (
            "create index if not exists idx_approval_status_watch_last_seen "
            "on approval_requests(status, watch_only_observation, last_seen_at desc, request_id desc)"
        ),
        "create index if not exists idx_approval_resolution on approval_requests(resolution_action, resolved_at)",
    ]


def _backfill_queue_counters(connection: sqlite3.Connection) -> None:
    """Fill the counters that need no identity when the resident cannot serve one."""

    connection.execute(
        """
        update approval_requests
        set dedupe_count = case when dedupe_count is null or dedupe_count < 1 then 1 else dedupe_count end,
            last_seen_at = coalesce(last_seen_at, created_at)
        where last_seen_at is null
           or dedupe_count is null
           or dedupe_count < 1
        """
    )


def _legacy_queue_rows(connection: sqlite3.Connection, *, after: tuple[str, str] | None) -> list[sqlite3.Row]:
    predicate = ""
    parameters: list[object] = []
    if after is not None:
        predicate = "and (created_at > ? or (created_at = ? and request_id > ?))"
        parameters.extend((after[0], after[0], after[1]))
    parameters.append(APPROVAL_QUEUE_BACKFILL_BATCH_SIZE)
    return list(
        connection.execute(
            f"""
            select request_id, harness, artifact_id, workspace, launch_target, action_envelope_json,
                   action_identity, queue_group_id, dedupe_count, last_seen_at, created_at
            from approval_requests
            where (
                action_identity is null
                or queue_group_id is null
                or last_seen_at is null
                or dedupe_count is null
                or dedupe_count < 1
            )
            {predicate}
            order by created_at asc, request_id asc
            limit ?
            """,
            parameters,
        ).fetchall()
    )


def _optional_json_object(value: object) -> dict[str, object] | None:
    if value is None:
        return None
    try:
        parsed = json.loads(str(value))
    except (json.JSONDecodeError, TypeError, ValueError):
        return None
    return dict(parsed) if isinstance(parsed, dict) else None


def _identity_items(rows: list[sqlite3.Row]) -> list[dict[str, object]]:
    return [
        queue_identity_item(
            launch_target=row["launch_target"],
            harness=str(row["harness"]),
            workspace=row["workspace"],
            artifact_id=str(row["artifact_id"]),
            envelope=_optional_json_object(row["action_envelope_json"]),
            browser_intent=None,
            action_identity=row["action_identity"],
            queue_group_id=row["queue_group_id"],
        )
        for row in rows
    ]


def _queue_identities_for_rows(rows: list[sqlite3.Row], guard_home: Path) -> tuple[dict[str, tuple[str, str]], bool]:
    """Identify ``rows``. The bool is true when the resident never answered.

    A rejected batch is halved and then tried one row at a time. A row that is
    still rejected is omitted. An unavailable resident stops the split so a
    down runtime is not retried once per legacy row.
    """

    if not rows:
        return {}, False
    try:
        derived = native_approval_queue_identities(
            _identity_items(rows),
            guard_home=guard_home,
            provision=False,
        )
    except ApprovalQueueIdentityUnavailableError as error:
        if error.reason != "rejected":
            return {}, True
        if len(rows) == 1:
            return {}, False
        midpoint = len(rows) // 2
        left, left_unavailable = _queue_identities_for_rows(rows[:midpoint], guard_home)
        if left_unavailable:
            return left, True
        right, right_unavailable = _queue_identities_for_rows(rows[midpoint:], guard_home)
        left.update(right)
        return left, right_unavailable
    return {
        str(row["request_id"]): (identity.action_identity, identity.queue_group_id)
        for row, identity in zip(rows, derived, strict=True)
    }, False


def _apply_backfill_updates(
    connection: sqlite3.Connection,
    rows: list[sqlite3.Row],
    identities: dict[str, tuple[str, str]],
) -> None:
    for row in rows:
        action_identity, queue_group_id = identities.get(
            str(row["request_id"]), (row["action_identity"], row["queue_group_id"])
        )
        connection.execute(
            """
            update approval_requests
            set action_identity = ?,
                queue_group_id = ?,
                dedupe_count = ?,
                last_seen_at = ?
            where request_id = ?
            """,
            (
                action_identity,
                queue_group_id,
                max(1, int(row["dedupe_count"] or 1)),
                row["last_seen_at"] or row["created_at"],
                row["request_id"],
            ),
        )


def backfill_approval_queue_columns(connection: sqlite3.Connection) -> bool:
    """Fill legacy queue identities inside the schema migration's transaction.

    Returns True when every selected row was identified, or the only rows left
    unidentified were rejected. Returns False when the resident was unavailable
    or no home could be resolved; the resident's queue write fills the rest. A
    rejected row stays unidentified and is skipped; later rows still run.
    """

    complete = True
    after: tuple[str, str] | None = None
    while True:
        rows = _legacy_queue_rows(connection, after=after)
        if not rows:
            return complete
        missing = [row for row in rows if not row["action_identity"] or not row["queue_group_id"]]
        identities: dict[str, tuple[str, str]] = {}
        if missing:
            # The identity is derived natively. Without a resident the rows keep
            # their legacy shape, which the duplicate lookup already handles.
            resolved_home = connection_guard_home(connection)
            if resolved_home is None:
                _backfill_queue_counters(connection)
                return False
            found, unavailable = _queue_identities_for_rows(missing, resolved_home)
            identities = found
            _apply_backfill_updates(connection, rows, identities)
            if unavailable:
                _backfill_queue_counters(connection)
                return False
        else:
            _apply_backfill_updates(connection, rows, identities)
        after = (str(rows[-1]["created_at"]), str(rows[-1]["request_id"]))


def _decode_page_cursor(cursor: str) -> dict[str, str] | None:
    try:
        padded = cursor + ("=" * (-len(cursor) % 4))
        decoded = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
        payload = json.loads(decoded)
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    last_seen_at = payload.get("last_seen_at")
    request_id = payload.get("request_id")
    if isinstance(last_seen_at, str) and isinstance(request_id, str):
        return {"last_seen_at": last_seen_at, "request_id": request_id}
    return None
