"""Approval queue persistence helpers for the local Guard store."""

from __future__ import annotations

import base64
import json
import logging
import re
import sqlite3
from collections.abc import Sequence
from pathlib import Path

from .approval_resolution import approval_resolution_block_reason
from .native_approval_queue_identity import (
    ApprovalQueueIdentityUnavailableError,
    connection_guard_home,
    native_approval_queue_identities,
    queue_identity_item,
)
from .store_approval_projection import (
    _optional_json_object as _optional_json_object,
)
from .store_approval_projection import (
    _project_listing_rows as _project_listing_rows,
)
from .store_approval_projection import (
    _row_to_approval_summary as _row_to_approval_summary,
)
from .store_approval_projection import (
    _row_to_draft as _row_to_draft,
)
from .store_approval_projection import (
    _row_to_payload as _row_to_payload,
)
from .store_approval_projection import (
    _rows_to_payloads as _rows_to_payloads,
)

logger = logging.getLogger(__name__)

APPROVAL_QUEUE_BACKFILL_BATCH_SIZE = 500
_APPROVAL_RESOLUTION_BATCH_SIZE = 500


class InvalidApprovalCursorError(ValueError):
    pass


def _begin_immediate(connection: sqlite3.Connection) -> None:
    if connection.in_transaction:
        return
    connection.execute("begin immediate")


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


_APPROVAL_COLUMNS = """
    request_id, harness, artifact_id, artifact_name, artifact_type, artifact_hash, publisher, policy_action,
    recommended_scope, changed_fields_json, source_scope, oauth_source, config_path, workspace, launch_target,
    normalized_identity_key, action_identity, queue_group_id, dedupe_count, last_seen_at, transport,
    risk_summary, risk_signals_json, artifact_label, source_label, trigger_summary, why_now,
    launch_summary, risk_headline, action_envelope_json, decision_v2_json,
    fallback_cli_command, scanner_evidence_json, watch_only_observation,
    browser_intent_json, continuation_snapshot_json, review_command,
    approval_url, status, resolution_action, resolution_scope, reason, created_at, resolved_at,
    raw_command_text, guard_version, first_seen_guard_version, last_seen_guard_version
"""
_SUMMARY_COLUMNS = """
    request_id, harness, artifact_id, artifact_name, artifact_type, policy_action, decision_v2_json,
    action_envelope_json, changed_fields_json, source_scope, config_path, workspace, launch_target,
    risk_summary, risk_headline, action_identity, queue_group_id, dedupe_count, raw_command_text,
    fallback_cli_command, watch_only_observation, review_command, created_at, last_seen_at, status
"""
_REMAINING_SUMMARIES = 10
_SUPERSEDED_PREFIX = "superseded_by_fresh_review:"


def list_approval_requests(
    connection: sqlite3.Connection,
    *,
    status: str | None = "pending",
    harness: str | None = None,
    limit: int | None = 50,
) -> list[dict[str, object]]:
    """Queue payloads read inside a caller's transaction; `GuardStore` reads natively."""

    filters = [(column, value) for column, value in (("status", status), ("harness", harness)) if value is not None]
    where_clause = f"where {' and '.join(f'{column} = ?' for column, _ in filters)}" if filters else ""
    params: list[object] = [value for _, value in filters]
    query = (
        f"select {_APPROVAL_COLUMNS} from approval_requests {where_clause} order by last_seen_at desc, request_id desc"
    )
    if limit is not None:
        query += " limit ?"
        params.append(limit)
    rows = connection.execute(query, params).fetchall()
    return _rows_to_payloads(rows, guard_home=connection_guard_home(connection))


def get_approval_request(
    connection: sqlite3.Connection, request_id: str, *, derive_scope: bool = True
) -> dict[str, object] | None:
    columns = _approval_columns(connection)
    row = connection.execute(
        f"""
        select request_id, harness, artifact_id, artifact_name, artifact_type, artifact_hash, publisher, policy_action,
               recommended_scope, changed_fields_json, source_scope,
                {_column_expr(columns, "oauth_source", "NULL")}, config_path, workspace, launch_target,
                {_column_expr(columns, "normalized_identity_key", "NULL")},
                {_column_expr(columns, "action_identity", "NULL")},
                {_column_expr(columns, "queue_group_id", "NULL")},
                {_column_expr(columns, "dedupe_count", "1")},
                {_column_expr(columns, "last_seen_at", "created_at")},
                transport,
                risk_summary, risk_signals_json, artifact_label, source_label, trigger_summary, why_now,
                launch_summary, risk_headline, action_envelope_json, decision_v2_json,
                {_column_expr(columns, "fallback_cli_command", "NULL")},
                {_column_expr(columns, "raw_command_text", "NULL")},
                {_column_expr(columns, "guard_version", "NULL")},
                {_column_expr(columns, "first_seen_guard_version", "NULL")},
                {_column_expr(columns, "last_seen_guard_version", "NULL")},
                {_column_expr(columns, "scanner_evidence_json", "'[]'")},
                {_column_expr(columns, "watch_only_observation", "0")},
                {_column_expr(columns, "browser_intent_json", "NULL")}, review_command,
                {_column_expr(columns, "continuation_snapshot_json", "NULL")},
                {_column_expr(columns, "extension_allow_hint_json", "NULL")},
                approval_url, status, resolution_action, resolution_scope, reason, created_at, resolved_at
        from approval_requests
        where request_id = ?
        """,
        (request_id,),
    ).fetchone()
    if row is None:
        return None
    guard_home = connection_guard_home(connection)
    if derive_scope:
        payload = _row_to_payload(row, guard_home=guard_home)
    else:
        payload, contract_error = _row_to_draft(row, _project_listing_rows([row], guard_home=guard_home)[0])
        if contract_error is not None:
            payload["decision_contract_error"] = contract_error
    reason = row["reason"]
    if (
        row["status"] == "expired"
        and isinstance(reason, str)
        and reason.startswith("superseded_by_fresh_review:")
        and {"oauth_source", "queue_group_id"} <= columns
    ):
        replacement = reason.removeprefix("superseded_by_fresh_review:")
        if re.fullmatch(r"[A-Za-z0-9-]{1,64}", replacement):
            candidate = connection.execute(
                """select policy_action, decision_v2_json, action_envelope_json from approval_requests
                where request_id = ? and status = 'pending' and harness = ?
                and artifact_id = ? and workspace IS ? and oauth_source IS ? and queue_group_id IS ?""",
                (
                    replacement,
                    row["harness"],
                    row["artifact_id"],
                    row["workspace"],
                    row["oauth_source"],
                    row["queue_group_id"],
                ),
            ).fetchone()
            if (
                candidate is not None
                and _project_listing_rows([candidate], guard_home=guard_home)[0].contract_error is None
            ):
                payload["superseded_by_request_id"] = replacement
    return payload


def _approval_columns(connection: sqlite3.Connection) -> set[str]:
    rows = connection.execute("pragma table_info(approval_requests)").fetchall()
    return {str(row["name"]) for row in rows}


def _column_expr(existing: set[str], column_name: str, fallback_sql: str) -> str:
    if column_name in existing:
        return column_name
    return f"{fallback_sql} as {column_name}"


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


def _pending_summaries(connection: sqlite3.Connection) -> tuple[list[dict[str, object]], int]:
    """The first pending summaries and the pending count, read inside a caller's transaction."""

    rows = connection.execute(
        f"select {_SUMMARY_COLUMNS} from approval_requests where status = 'pending' "
        "order by last_seen_at desc, request_id desc limit ?",
        (_REMAINING_SUMMARIES + 1,),
    ).fetchall()
    # Every fetched row is projected, as the page read that came before did.
    projections = _project_listing_rows(rows, guard_home=connection_guard_home(connection))
    summaries = [_row_to_approval_summary(row, projection) for row, projection in zip(rows, projections, strict=True)]
    total = connection.execute("select count(*) from approval_requests where status = 'pending'").fetchone()
    return summaries[:_REMAINING_SUMMARIES], int(total[0])


def get_next_pending_request(
    connection: sqlite3.Connection,
    *,
    exclude_ids: set[str] | None = None,
) -> dict[str, object] | None:
    excluded = exclude_ids or set()
    rows = list_approval_requests(connection, status="pending", limit=10)
    for row in rows:
        if str(row["request_id"]) not in excluded:
            return row
    return None


def resolve_one_request_only(
    connection: sqlite3.Connection,
    request_id: str,
    *,
    resolution_action: str,
    resolution_scope: str,
    reason: str | None,
    resolved_at: str,
) -> bool:
    cursor = connection.execute(
        """
        update approval_requests
        set status = 'resolved',
            resolution_action = ?,
            resolution_scope = ?,
            reason = ?,
            resolved_at = ?
        where request_id = ?
          and status = 'pending'
        """,
        (resolution_action, resolution_scope, reason, resolved_at, request_id),
    )
    return int(cursor.rowcount if cursor.rowcount is not None else 0) == 1


def resolve_request_with_queue_result(
    connection: sqlite3.Connection,
    request_id: str,
    *,
    resolution_action: str,
    resolution_scope: str,
    reason: str | None,
    resolved_at: str,
) -> dict[str, object]:
    _begin_immediate(connection)
    request = get_approval_request(connection, request_id)
    if request is None:
        return _unresolved_queue_result(connection, error="not_found")
    if request["status"] != "pending":
        return _unresolved_queue_result(connection, error="already_resolved", item=request)
    resolution_block_reason = approval_resolution_block_reason(request)
    if resolution_block_reason is not None:
        return _unresolved_queue_result(connection, error=resolution_block_reason, item=request)
    did_resolve = resolve_one_request_only(
        connection,
        request_id,
        resolution_action=resolution_action,
        resolution_scope=resolution_scope,
        reason=reason,
        resolved_at=resolved_at,
    )
    if not did_resolve:
        return _unresolved_queue_result(connection, error="already_resolved", item=request)
    queue_group_id = request.get("queue_group_id")
    duplicate_ids = resolve_matching_duplicate_requests(
        connection,
        queue_group_id=str(queue_group_id) if isinstance(queue_group_id, str) else None,
        oauth_source=str(request["oauth_source"]) if isinstance(request.get("oauth_source"), str) else None,
        request_id=request_id,
        resolution_action=resolution_action,
        resolution_scope=resolution_scope,
        reason=reason,
        resolved_at=resolved_at,
    )
    updated = get_approval_request(connection, request_id)
    next_request = get_next_pending_request(connection, exclude_ids={request_id, *duplicate_ids})
    remaining_summaries, remaining_count = _pending_summaries(connection)
    return {
        "resolved": True,
        "item": updated,
        "resolved_request": updated,
        "remaining_pending_count": remaining_count,
        "next_selectable_request_id": next_request["request_id"] if next_request is not None else None,
        "remaining_pending_summaries": remaining_summaries,
        "resolved_duplicate_ids": duplicate_ids,
        "resolution_summary": _resolution_summary(remaining_count),
        "retry_hint": "Retry the action in your AI assistant if you approved it.",
    }


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


def resolve_matching_duplicate_requests(
    connection: sqlite3.Connection,
    *,
    queue_group_id: str | None,
    oauth_source: str | None,
    request_id: str,
    resolution_action: str,
    resolution_scope: str,
    reason: str | None,
    resolved_at: str,
) -> list[str]:
    if queue_group_id is None:
        return []
    _begin_immediate(connection)
    rows = connection.execute(
        """
        select request_id, policy_action, decision_v2_json, action_envelope_json
        from approval_requests
        where queue_group_id = ?
          and oauth_source is ?
          and request_id != ?
          and status = 'pending'
        order by last_seen_at desc, request_id desc
        """,
        (queue_group_id, oauth_source, request_id),
    ).fetchall()
    resolvable_ids = resolvable_approval_request_ids(connection, rows)
    _resolve_request_ids(
        connection,
        resolvable_ids,
        resolution_action=resolution_action,
        resolution_scope=resolution_scope,
        reason=reason,
        resolved_at=resolved_at,
    )
    return resolvable_ids


def resolvable_approval_request_ids(connection: sqlite3.Connection, rows: Sequence[sqlite3.Row]) -> list[str]:
    """Return, in order, the pending rows whose persisted surfaces are resolvable.

    One batched projection in the connection's Guard home covers every row, so a
    scope sweep holds the write lock for a bounded number of resident calls and an
    unreadable row reads as inconsistent instead of aborting the sweep.
    """

    projections = _project_listing_rows(list(rows), guard_home=connection_guard_home(connection))
    resolvable: list[str] = []
    for row, projection in zip(rows, projections, strict=True):
        request: dict[str, object] = {"policy_action": projection.policy_action}
        if projection.contract_error is not None:
            request["decision_contract_error"] = projection.contract_error
        if approval_resolution_block_reason(request) is None:
            resolvable.append(str(row["request_id"]))
    return resolvable


def _resolve_request_ids(
    connection: sqlite3.Connection,
    request_ids: list[str],
    *,
    resolution_action: str,
    resolution_scope: str,
    reason: str | None,
    resolved_at: str,
) -> None:
    for offset in range(0, len(request_ids), _APPROVAL_RESOLUTION_BATCH_SIZE):
        chunk = request_ids[offset : offset + _APPROVAL_RESOLUTION_BATCH_SIZE]
        placeholders = ", ".join("?" for _ in chunk)
        connection.execute(
            f"""
            update approval_requests
            set status = 'resolved',
                resolution_action = ?,
                resolution_scope = ?,
                reason = ?,
                resolved_at = ?
            where request_id in ({placeholders})
              and status = 'pending'
            """,
            (resolution_action, resolution_scope, reason, resolved_at, *chunk),
        )


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


def _resolution_summary(remaining_count: int) -> str:
    if remaining_count == 0:
        return "Decision saved. No blocked actions remain."
    if remaining_count == 1:
        return "Decision saved. 1 blocked action remains."
    return f"Decision saved. {remaining_count} blocked actions remain."


def _unresolved_queue_result(
    connection: sqlite3.Connection,
    *,
    error: str,
    item: dict[str, object] | None = None,
) -> dict[str, object]:
    remaining_summaries, remaining_count = _pending_summaries(connection)
    next_request = get_next_pending_request(connection)
    return {
        "resolved": False,
        "error": error,
        "item": item,
        "remaining_pending_count": remaining_count,
        "next_selectable_request_id": next_request["request_id"] if next_request is not None else None,
        "remaining_pending_summaries": remaining_summaries,
        "resolved_duplicate_ids": [],
        "resolution_summary": "Request was not resolved.",
        "retry_hint": "Refresh the approval queue and choose an active request.",
    }


def bulk_resolve_approval_requests(
    connection: sqlite3.Connection,
    request_ids: list[str],
    *,
    resolution_action: str,
    resolution_scope: str,
    reason: str | None,
    resolved_at: str,
) -> None:
    if not request_ids:
        return
    placeholders = ",".join("?" for _ in request_ids)
    connection.execute(
        f"""
        update approval_requests
        set status = 'resolved',
            resolution_action = ?,
            resolution_scope = ?,
            reason = ?,
            resolved_at = ?
        where request_id in ({placeholders})
          and status = 'pending'
        """,
        [resolution_action, resolution_scope, reason, resolved_at, *request_ids],
    )
