"""Approval queue persistence helpers for the local Guard store."""

from __future__ import annotations

import json
import sqlite3

from .models import GuardApprovalRequest


def approval_schema_statement() -> str:
    return """
        create table if not exists approval_requests (
          request_id text primary key,
          harness text not null,
          artifact_id text not null,
          artifact_name text not null,
          artifact_hash text not null,
          publisher text,
          policy_action text not null,
          recommended_scope text not null,
          changed_fields_json text not null,
          source_scope text not null,
          config_path text not null,
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


def add_approval_request(connection: sqlite3.Connection, request: GuardApprovalRequest, now: str) -> None:
    connection.execute(
        """
        delete from approval_requests
        where harness = ? and artifact_id = ? and status = 'pending'
        """,
        (request.harness, request.artifact_id),
    )
    connection.execute(
        """
        insert into approval_requests (
          request_id, harness, artifact_id, artifact_name, artifact_hash, publisher, policy_action,
          recommended_scope, changed_fields_json, source_scope, config_path, review_command,
          approval_url, status, resolution_action, resolution_scope, reason, created_at, resolved_at
        )
        values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', null, null, null, ?, null)
        """,
        (
            request.request_id,
            request.harness,
            request.artifact_id,
            request.artifact_name,
            request.artifact_hash,
            request.publisher,
            request.policy_action,
            request.recommended_scope,
            json.dumps(list(request.changed_fields)),
            request.source_scope,
            request.config_path,
            request.review_command,
            request.approval_url,
            now,
        ),
    )


def list_approval_requests(
    connection: sqlite3.Connection,
    *,
    status: str | None = "pending",
    harness: str | None = None,
    limit: int = 50,
) -> list[dict[str, object]]:
    clauses = []
    params: list[object] = []
    if status is not None:
        clauses.append("status = ?")
        params.append(status)
    if harness is not None:
        clauses.append("harness = ?")
        params.append(harness)
    where_clause = f"where {' and '.join(clauses)}" if clauses else ""
    rows = connection.execute(
        f"""
        select request_id, harness, artifact_id, artifact_name, artifact_hash, publisher, policy_action,
               recommended_scope, changed_fields_json, source_scope, config_path, review_command,
               approval_url, status, resolution_action, resolution_scope, reason, created_at, resolved_at
        from approval_requests
        {where_clause}
        order by created_at desc
        limit ?
        """,
        (*params, limit),
    ).fetchall()
    return [_row_to_payload(row) for row in rows]


def get_approval_request(connection: sqlite3.Connection, request_id: str) -> dict[str, object] | None:
    row = connection.execute(
        """
        select request_id, harness, artifact_id, artifact_name, artifact_hash, publisher, policy_action,
               recommended_scope, changed_fields_json, source_scope, config_path, review_command,
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


def count_approval_requests(connection: sqlite3.Connection, *, status: str | None = "pending") -> int:
    if status is None:
        row = connection.execute("select count(*) as total from approval_requests").fetchone()
    else:
        row = connection.execute(
            "select count(*) as total from approval_requests where status = ?",
            (status,),
        ).fetchone()
    return int(row["total"]) if row is not None else 0


def _row_to_payload(row: sqlite3.Row) -> dict[str, object]:
    return {
        "request_id": str(row["request_id"]),
        "harness": str(row["harness"]),
        "artifact_id": str(row["artifact_id"]),
        "artifact_name": str(row["artifact_name"]),
        "artifact_hash": str(row["artifact_hash"]),
        "publisher": row["publisher"],
        "policy_action": str(row["policy_action"]),
        "recommended_scope": str(row["recommended_scope"]),
        "changed_fields": json.loads(str(row["changed_fields_json"])),
        "source_scope": str(row["source_scope"]),
        "config_path": str(row["config_path"]),
        "review_command": str(row["review_command"]),
        "approval_url": str(row["approval_url"]),
        "status": str(row["status"]),
        "resolution_action": row["resolution_action"],
        "resolution_scope": row["resolution_scope"],
        "reason": row["reason"],
        "created_at": str(row["created_at"]),
        "resolved_at": row["resolved_at"],
    }
