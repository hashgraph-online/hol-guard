"""Approval queue persistence helpers for the local Guard store."""

from __future__ import annotations

import json
import sqlite3

from .models import GuardApprovalRequest
from .runtime.action_identity import normalize_command_identity


def _normalized_identity_key(launch_target: str | None) -> str:
    return normalize_command_identity(launch_target or "")


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
          config_path text not null,
          workspace text,
          launch_target text,
          normalized_identity_key text,
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


def add_approval_request(connection: sqlite3.Connection, request: GuardApprovalRequest, now: str) -> str:
    existing = connection.execute(
        """
        select request_id
        from approval_requests
        where harness = ?
          and artifact_id = ?
          and workspace IS ?
          and normalized_identity_key = ?
          and status = 'pending'
        order by created_at desc
        limit 1
        """,
        (request.harness, request.artifact_id, request.workspace, _normalized_identity_key(request.launch_target)),
    ).fetchone()
    request_id = str(existing["request_id"]) if existing is not None else request.request_id
    if existing is not None:
        review_command = _rewrite_review_command(request.review_command, request_id)
        approval_url = _rewrite_approval_url(request.approval_url, request_id)
        connection.execute(
            """
            update approval_requests
            set artifact_name = ?, artifact_type = ?, artifact_hash = ?, publisher = ?, policy_action = ?,
                recommended_scope = ?, changed_fields_json = ?, source_scope = ?, config_path = ?, workspace = ?,
                launch_target = ?, normalized_identity_key = ?, transport = ?, risk_summary = ?, risk_signals_json = ?,
                artifact_label = ?, source_label = ?, trigger_summary = ?, why_now = ?, launch_summary = ?,
                risk_headline = ?, action_envelope_json = ?, decision_v2_json = ?, fallback_cli_command = ?,
                review_command = ?, approval_url = ?, created_at = ?
            where request_id = ?
            """,
            (
                request.artifact_name,
                request.artifact_type,
                request.artifact_hash,
                request.publisher,
                request.policy_action,
                request.recommended_scope,
                json.dumps(list(request.changed_fields)),
                request.source_scope,
                request.config_path,
                request.workspace,
                request.launch_target,
                _normalized_identity_key(request.launch_target),
                request.transport,
                request.risk_summary,
                json.dumps(list(request.risk_signals)),
                request.artifact_label,
                request.source_label,
                request.trigger_summary,
                request.why_now,
                request.launch_summary,
                request.risk_headline,
                json.dumps(request.action_envelope_json) if request.action_envelope_json is not None else None,
                json.dumps(request.decision_v2_json) if request.decision_v2_json is not None else None,
                (
                    _rewrite_review_command(request.fallback_cli_command, request_id)
                    if request.fallback_cli_command
                    else None
                ),
                review_command,
                approval_url,
                now,
                request_id,
            ),
        )
        return request_id
    connection.execute(
        """
        insert into approval_requests (
          request_id, harness, artifact_id, artifact_name, artifact_type, artifact_hash, publisher, policy_action,
          recommended_scope, changed_fields_json, source_scope, config_path, workspace,
           launch_target, normalized_identity_key, transport, risk_summary,
           risk_signals_json, artifact_label, source_label, trigger_summary, why_now, launch_summary, risk_headline,
            action_envelope_json, decision_v2_json, fallback_cli_command, review_command,
            approval_url, status, resolution_action, resolution_scope, reason, created_at, resolved_at
          )
          values (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
          )
        """,
        (
            request.request_id,
            request.harness,
            request.artifact_id,
            request.artifact_name,
            request.artifact_type,
            request.artifact_hash,
            request.publisher,
            request.policy_action,
            request.recommended_scope,
            json.dumps(list(request.changed_fields)),
            request.source_scope,
            request.config_path,
            request.workspace,
            request.launch_target,
            _normalized_identity_key(request.launch_target),
            request.transport,
            request.risk_summary,
            json.dumps(list(request.risk_signals)),
            request.artifact_label,
            request.source_label,
            request.trigger_summary,
            request.why_now,
            request.launch_summary,
            request.risk_headline,
            json.dumps(request.action_envelope_json) if request.action_envelope_json is not None else None,
            json.dumps(request.decision_v2_json) if request.decision_v2_json is not None else None,
            request.fallback_cli_command,
            request.review_command,
            request.approval_url,
            "pending",
            None,
            None,
            None,
            now,
            None,
        ),
    )
    return request.request_id


def _rewrite_review_command(command: str, request_id: str) -> str:
    prefix, _, _ = command.rpartition(" ")
    if prefix:
        return f"{prefix} {request_id}"
    return request_id


def _rewrite_approval_url(url: str, request_id: str) -> str:
    prefix, _, _ = url.rpartition("/")
    if prefix:
        return f"{prefix}/{request_id}"
    return request_id


def list_approval_requests(
    connection: sqlite3.Connection,
    *,
    status: str | None = "pending",
    harness: str | None = None,
    limit: int | None = 50,
    before_cursor: str | None = None,
    search: str | None = None,
    created_after: str | None = None,
    created_before: str | None = None,
) -> list[dict[str, object]]:
    clauses = []
    params: list[object] = []
    if status is not None:
        clauses.append("status = ?")
        params.append(status)
    if harness is not None:
        clauses.append("harness = ?")
        params.append(harness)
    if before_cursor is not None:
        clauses.append("created_at < ?")
        params.append(before_cursor)
    if created_after is not None:
        clauses.append("created_at > ?")
        params.append(created_after)
    if created_before is not None:
        clauses.append("created_at < ?")
        params.append(created_before)
    if search is not None:
        search_clause = (
            "(lower(artifact_name) like lower(?)"
            " or lower(artifact_id) like lower(?)"
            " or lower(coalesce(risk_summary, '')) like lower(?))"
        )
        clauses.append(search_clause)
        pattern = f"%{search}%"
        params.extend([pattern, pattern, pattern])
    where_clause = f"where {' and '.join(clauses)}" if clauses else ""
    query = f"""
        select request_id, harness, artifact_id, artifact_name, artifact_type, artifact_hash, publisher, policy_action,
               recommended_scope, changed_fields_json, source_scope, config_path, workspace, launch_target, transport,
                risk_summary, risk_signals_json, artifact_label, source_label, trigger_summary, why_now,
                launch_summary, risk_headline, action_envelope_json, decision_v2_json,
                fallback_cli_command, review_command,
                approval_url, status, resolution_action, resolution_scope, reason, created_at, resolved_at
        from approval_requests
        {where_clause}
        order by created_at desc
    """
    if limit is None:
        rows = connection.execute(query, params).fetchall()
    else:
        rows = connection.execute(f"{query}\nlimit ?", (*params, limit)).fetchall()
    return [_row_to_payload(row) for row in rows]


def get_approval_request(connection: sqlite3.Connection, request_id: str) -> dict[str, object] | None:
    row = connection.execute(
        """
        select request_id, harness, artifact_id, artifact_name, artifact_type, artifact_hash, publisher, policy_action,
               recommended_scope, changed_fields_json, source_scope, config_path, workspace, launch_target, transport,
                risk_summary, risk_signals_json, artifact_label, source_label, trigger_summary, why_now,
                launch_summary, risk_headline, action_envelope_json, decision_v2_json,
                fallback_cli_command, review_command,
                approval_url, status, resolution_action, resolution_scope, reason, created_at, resolved_at
        from approval_requests
        where request_id = ?
        """,
        (request_id,),
    ).fetchone()
    if row is None:
        return None
    return _row_to_payload(row)


def resolve_approval_request(
    connection: sqlite3.Connection,
    request_id: str,
    *,
    resolution_action: str,
    resolution_scope: str,
    reason: str | None,
    resolved_at: str,
) -> None:
    connection.execute(
        """
        update approval_requests
        set status = 'resolved',
            resolution_action = ?,
            resolution_scope = ?,
            reason = ?,
            resolved_at = ?
        where request_id = ?
        """,
        (resolution_action, resolution_scope, reason, resolved_at, request_id),
    )


def count_approval_requests(
    connection: sqlite3.Connection,
    *,
    status: str | None = "pending",
    harness: str | None = None,
) -> int:
    clauses = []
    params: list[object] = []
    if status is not None:
        clauses.append("status = ?")
        params.append(status)
    if harness is not None:
        clauses.append("harness = ?")
        params.append(harness)
    where_clause = f"where {' and '.join(clauses)}" if clauses else ""
    row = connection.execute(f"select count(*) as total from approval_requests {where_clause}", params).fetchone()
    return int(row["total"]) if row is not None else 0


def _row_to_payload(row: sqlite3.Row) -> dict[str, object]:
    return {
        "request_id": str(row["request_id"]),
        "harness": str(row["harness"]),
        "artifact_id": str(row["artifact_id"]),
        "artifact_name": str(row["artifact_name"]),
        "artifact_type": str(row["artifact_type"]),
        "artifact_hash": str(row["artifact_hash"]),
        "publisher": row["publisher"],
        "policy_action": str(row["policy_action"]),
        "recommended_scope": str(row["recommended_scope"]),
        "changed_fields": _safe_json_list(row["changed_fields_json"]),
        "source_scope": str(row["source_scope"]),
        "config_path": str(row["config_path"]),
        "workspace": row["workspace"],
        "launch_target": row["launch_target"],
        "transport": row["transport"],
        "risk_summary": row["risk_summary"],
        "risk_signals": _safe_json_list(row["risk_signals_json"]),
        "artifact_label": row["artifact_label"],
        "source_label": row["source_label"],
        "trigger_summary": row["trigger_summary"],
        "why_now": row["why_now"],
        "launch_summary": row["launch_summary"],
        "risk_headline": row["risk_headline"],
        "action_envelope_json": _optional_json_object(row["action_envelope_json"]),
        "decision_v2_json": _optional_json_object(row["decision_v2_json"]),
        "fallback_cli_command": row["fallback_cli_command"],
        "review_command": str(row["review_command"]),
        "approval_url": str(row["approval_url"]),
        "status": str(row["status"]),
        "resolution_action": row["resolution_action"],
        "resolution_scope": row["resolution_scope"],
        "reason": row["reason"],
        "created_at": str(row["created_at"]),
        "resolved_at": row["resolved_at"],
    }


def _safe_json_list(value: object) -> list[object]:
    if value is None:
        return []
    try:
        parsed = json.loads(str(value))
    except (json.JSONDecodeError, TypeError, ValueError):
        return []
    return list(parsed) if isinstance(parsed, list) else []


def approval_index_statements() -> list[str]:
    return [
        "create index if not exists idx_approval_status_created on approval_requests(status, created_at desc)",
        "create index if not exists idx_approval_harness_status on approval_requests(harness, status)",
        "create index if not exists idx_approval_artifact_hash on approval_requests(artifact_hash)",
        "create index if not exists idx_approval_workspace_status on approval_requests(workspace, status)",
        "create index if not exists idx_approval_policy_action on approval_requests(policy_action)",
        "create index if not exists idx_approval_resolution on approval_requests(resolution_action, resolved_at)",
    ]


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


def clear_approval_requests_by_harness(connection: sqlite3.Connection, harness: str) -> int:
    cursor = connection.execute(
        "delete from approval_requests where harness = ? and status = 'resolved'",
        (harness,),
    )
    return cursor.rowcount


def clear_approval_requests_by_workspace(connection: sqlite3.Connection, workspace: str) -> int:
    cursor = connection.execute(
        "delete from approval_requests where workspace = ? and status = 'resolved'",
        (workspace,),
    )
    return cursor.rowcount


def clear_approval_requests_by_scope(connection: sqlite3.Connection, source_scope: str) -> int:
    cursor = connection.execute(
        "delete from approval_requests where source_scope = ? and status = 'resolved'",
        (source_scope,),
    )
    return cursor.rowcount


def clear_resolved_approval_requests_before(connection: sqlite3.Connection, before_timestamp: str) -> int:
    cursor = connection.execute(
        "delete from approval_requests where status = 'resolved' and resolved_at < ?",
        (before_timestamp,),
    )
    return cursor.rowcount


def compact_approval_requests(connection: sqlite3.Connection) -> int:
    rows = connection.execute(
        """
        select artifact_id, max(created_at) as latest_created
        from approval_requests
        where status = 'resolved'
        group by artifact_id
        having count(*) > 1
        """
    ).fetchall()
    total_removed = 0
    for row in rows:
        cursor = connection.execute(
            """
            delete from approval_requests
            where artifact_id = ?
              and status = 'resolved'
              and created_at < ?
            """,
            (row["artifact_id"], row["latest_created"]),
        )
        total_removed += cursor.rowcount
    return total_removed


def _optional_json_object(value: object) -> dict[str, object] | None:
    if value is None:
        return None
    try:
        parsed = json.loads(str(value))
    except (json.JSONDecodeError, TypeError, ValueError):
        return None
    if isinstance(parsed, dict):
        return {str(key): item for key, item in parsed.items() if isinstance(key, str)}
    return None
