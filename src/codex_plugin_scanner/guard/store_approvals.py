"""Approval queue persistence helpers for the local Guard store."""

from __future__ import annotations

import base64
import hashlib
import json
import re
import sqlite3

from .approval_scope_support import supported_request_scopes
from .models import GuardApprovalRequest
from .runtime.action_identity import normalize_command_identity

MAX_APPROVAL_PAGE_LIMIT = 200
APPROVAL_QUEUE_BACKFILL_BATCH_SIZE = 500
_QUEUE_IDENTITY_VERSION = "v1"
_VOLATILE_PAYLOAD_KEY_TOKENS = frozenset(
    {
        "callid",
        "conversationid",
        "messageid",
        "requestid",
        "sessionid",
        "threadid",
        "toolcallid",
        "traceid",
        "turnid",
    }
)


class InvalidApprovalCursorError(ValueError):
    pass


def _normalized_identity_key(launch_target: str | None) -> str:
    return normalize_command_identity(launch_target or "")


def _begin_immediate(connection: sqlite3.Connection) -> None:
    if connection.in_transaction:
        return
    connection.execute("begin immediate")


def approval_queue_identity_for_request(request: GuardApprovalRequest) -> tuple[str, str]:
    action_identity = request.action_identity or _build_action_identity(
        launch_target=request.launch_target,
        action_envelope=request.action_envelope_json,
    )
    queue_group_id = request.queue_group_id or _build_queue_group_id(
        harness=request.harness,
        workspace=request.workspace,
        artifact_id=request.artifact_id,
        action_identity=action_identity,
        browser_intent=request.browser_intent,
    )
    return action_identity, queue_group_id


def _build_action_identity(
    *,
    launch_target: str | None,
    action_envelope: dict[str, object] | None,
) -> str:
    envelope = action_envelope or {}
    command = _optional_text(envelope.get("command")) or launch_target or ""
    payload = {
        "version": _QUEUE_IDENTITY_VERSION,
        "action_type": _optional_text(envelope.get("action_type")),
        "tool_name": _optional_text(envelope.get("tool_name")),
        "command": normalize_command_identity(command),
        "prompt_excerpt": _optional_text(envelope.get("prompt_excerpt")),
        "target_paths": _string_sequence(envelope.get("target_paths")),
        "network_hosts": _string_sequence(envelope.get("network_hosts")),
        "mcp_server": _optional_text(envelope.get("mcp_server")),
        "mcp_tool": _optional_text(envelope.get("mcp_tool")),
        "package_manager": None,
        "package_name": None,
        "script_name": _optional_text(envelope.get("script_name")),
        "raw_payload_redacted": _stable_identity_payload(envelope.get("raw_payload_redacted")),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _build_queue_group_id(
    *,
    harness: str,
    workspace: str | None,
    artifact_id: str,
    action_identity: str,
    browser_intent: dict[str, object] | None = None,
) -> str:
    # Include browser intent identity in dedupe key when present
    browser_identity_hash = None
    if browser_intent is not None:
        from .runtime.action_identity import normalize_browser_mcp_identity

        browser_identity_hash = normalize_browser_mcp_identity(browser_intent)
    payload = json.dumps(
        {
            "version": _QUEUE_IDENTITY_VERSION,
            "harness": harness,
            "workspace": workspace,
            "artifact_id": artifact_id,
            "action_identity": action_identity,
            "browser_identity_hash": browser_identity_hash,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    return f"approval-group:{_QUEUE_IDENTITY_VERSION}:{digest}"


def _optional_text(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _string_sequence(value: object) -> list[str]:
    if not isinstance(value, list | tuple):
        return []
    return sorted(str(item) for item in value if isinstance(item, str) and item.strip())


def _stable_identity_payload(value: object) -> object:
    if isinstance(value, dict):
        normalized: dict[str, object] = {}
        for key, item in sorted(value.items()):
            if not isinstance(key, str):
                continue
            if _identity_payload_key_token(key) in _VOLATILE_PAYLOAD_KEY_TOKENS:
                continue
            normalized[key] = _stable_identity_payload(item)
        return normalized
    if isinstance(value, list | tuple):
        return [_stable_identity_payload(item) for item in value]
    if isinstance(value, str | int | float | bool) or value is None:
        return value
    return str(value)


def _identity_payload_key_token(key: str) -> str:
    return re.sub(r"[^a-z0-9]", "", key.lower())


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
          desktop_notified_at text,
          raw_command_text text,
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
    _begin_immediate(connection)
    identity_key = _normalized_identity_key(request.launch_target)
    action_identity, queue_group_id = approval_queue_identity_for_request(request)
    existing = connection.execute(
        """
        select request_id
        from approval_requests
        where queue_group_id = ?
          and harness = ?
          and status = 'pending'
        order by last_seen_at desc, request_id desc
        limit 1
        """,
        (queue_group_id, request.harness),
    ).fetchone()
    if existing is None:
        existing = connection.execute(
            """
        select request_id
        from approval_requests
        where harness = ?
          and artifact_id = ?
          and workspace IS ?
          and normalized_identity_key = ?
          and queue_group_id IS NULL
          and status = 'pending'
        order by created_at desc
        limit 1
        """,
            (request.harness, request.artifact_id, request.workspace, identity_key),
        ).fetchone()
    if existing is None:
        existing = connection.execute(
            """
            select request_id
            from approval_requests
            where harness = ?
              and artifact_id = ?
              and workspace IS ?
              and launch_target IS ?
              and normalized_identity_key IS NULL
              and queue_group_id IS NULL
              and status = 'pending'
            order by created_at desc
            limit 1
            """,
            (request.harness, request.artifact_id, request.workspace, request.launch_target),
        ).fetchone()
    request_id = str(existing["request_id"]) if existing is not None else request.request_id
    if existing is not None:
        review_command = _rewrite_review_command(request.review_command, request_id)
        approval_url = _rewrite_approval_url(request.approval_url, request_id)
        connection.execute(
            """
            update approval_requests
            set harness = ?, artifact_name = ?, artifact_type = ?, artifact_hash = ?, publisher = ?, policy_action = ?,
                recommended_scope = ?, changed_fields_json = ?, source_scope = ?, config_path = ?, workspace = ?,
                launch_target = ?, normalized_identity_key = ?, action_identity = ?, queue_group_id = ?,
                dedupe_count = coalesce(dedupe_count, 1) + 1, last_seen_at = ?,
                transport = ?, risk_summary = ?, risk_signals_json = ?,
                artifact_label = ?, source_label = ?, trigger_summary = ?, why_now = ?, launch_summary = ?,
                risk_headline = ?, action_envelope_json = ?, decision_v2_json = ?, fallback_cli_command = ?,
                scanner_evidence_json = ?, review_command = ?, approval_url = ?, raw_command_text = ?
            where request_id = ?
            """,
            (
                request.harness,
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
                identity_key,
                action_identity,
                queue_group_id,
                now,
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
                json.dumps(list(request.scanner_evidence), sort_keys=True),
                review_command,
                approval_url,
                request.raw_command_text,
                request_id,
            ),
        )
        return request_id
    connection.execute(
        """
        insert into approval_requests (
          request_id, harness, artifact_id, artifact_name, artifact_type, artifact_hash, publisher, policy_action,
          recommended_scope, changed_fields_json, source_scope, config_path, workspace,
          launch_target, normalized_identity_key, action_identity, queue_group_id, dedupe_count, last_seen_at,
          transport, risk_summary,
          risk_signals_json, artifact_label, source_label, trigger_summary, why_now, launch_summary, risk_headline,
          action_envelope_json, decision_v2_json, fallback_cli_command, scanner_evidence_json,
          review_command, approval_url, status, resolution_action, resolution_scope, reason, created_at, resolved_at,
          raw_command_text
        )
        values (
          ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
          ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
          ?
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
            identity_key,
            action_identity,
            queue_group_id,
            max(1, int(request.dedupe_count)),
            request.last_seen_at or now,
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
            json.dumps(list(request.scanner_evidence), sort_keys=True),
            request.review_command,
            request.approval_url,
            "pending",
            None,
            None,
            None,
            now,
            None,
            request.raw_command_text,
        ),
    )
    return request.request_id


def _rewrite_review_command(command: str, request_id: str) -> str:
    prefix, _, _ = command.rpartition(" ")
    if prefix:
        return f"{prefix} {request_id}"
    return request_id


def _rewrite_approval_url(url: str, request_id: str) -> str:
    normalized = url.replace("/approvals/", "/requests/")
    prefix, _, _ = normalized.rpartition("/")
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
    cursor: str | None = None,
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
        clauses.append("last_seen_at < ?")
        params.append(before_cursor)
    if cursor is not None:
        marker = _decode_page_cursor(cursor)
        if marker is None:
            raise InvalidApprovalCursorError("invalid approval queue cursor")
        clauses.append("(last_seen_at < ? or (last_seen_at = ? and request_id < ?))")
        params.extend([marker["last_seen_at"], marker["last_seen_at"], marker["request_id"]])
    if created_after is not None:
        clauses.append("created_at > ?")
        params.append(created_after)
    if created_before is not None:
        clauses.append("created_at < ?")
        params.append(created_before)
    if search is not None:
        search_clause, search_params = _approval_search_clause(search)
        clauses.append(search_clause)
        params.extend(search_params)
    where_clause = f"where {' and '.join(clauses)}" if clauses else ""
    query = f"""
        select request_id, harness, artifact_id, artifact_name, artifact_type, artifact_hash, publisher, policy_action,
               recommended_scope, changed_fields_json, source_scope, config_path, workspace, launch_target,
                normalized_identity_key, action_identity, queue_group_id, dedupe_count, last_seen_at, transport,
                risk_summary, risk_signals_json, artifact_label, source_label, trigger_summary, why_now,
                launch_summary, risk_headline, action_envelope_json, decision_v2_json,
                fallback_cli_command, scanner_evidence_json, review_command,
                approval_url, status, resolution_action, resolution_scope, reason, created_at, resolved_at,
                raw_command_text
        from approval_requests
        {where_clause}
        order by last_seen_at desc, request_id desc
    """
    if limit is None:
        rows = connection.execute(query, params).fetchall()
    else:
        rows = connection.execute(f"{query}\nlimit ?", (*params, limit)).fetchall()
    return [_row_to_payload(row) for row in rows]


def get_approval_request(connection: sqlite3.Connection, request_id: str) -> dict[str, object] | None:
    columns = _approval_columns(connection)
    row = connection.execute(
        f"""
        select request_id, harness, artifact_id, artifact_name, artifact_type, artifact_hash, publisher, policy_action,
               recommended_scope, changed_fields_json, source_scope, config_path, workspace, launch_target,
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
                {_column_expr(columns, "scanner_evidence_json", "'[]'")}, review_command,
                approval_url, status, resolution_action, resolution_scope, reason, created_at, resolved_at
        from approval_requests
        where request_id = ?
        """,
        (request_id,),
    ).fetchone()
    if row is None:
        return None
    return _row_to_payload(row)


def _approval_columns(connection: sqlite3.Connection) -> set[str]:
    rows = connection.execute("pragma table_info(approval_requests)").fetchall()
    return {str(row["name"]) for row in rows}


def _column_expr(existing: set[str], column_name: str, fallback_sql: str) -> str:
    if column_name in existing:
        return column_name
    return f"{fallback_sql} as {column_name}"


def _approval_search_clause(search: str) -> tuple[str, list[object]]:
    pattern = f"%{search}%"
    columns = [
        "artifact_name",
        "artifact_id",
        "risk_summary",
        "risk_headline",
        "trigger_summary",
        "why_now",
        "launch_summary",
        "launch_target",
        "raw_command_text",
        "fallback_cli_command",
        "review_command",
        "action_identity",
        "action_envelope_json",
        "decision_v2_json",
        "config_path",
    ]
    return (
        "(" + " or ".join(f"lower(coalesce({column}, '')) like lower(?)" for column in columns) + ")",
        [pattern] * len(columns),
    )


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
    search: str | None = None,
) -> int:
    clauses = []
    params: list[object] = []
    if status is not None:
        clauses.append("status = ?")
        params.append(status)
    if harness is not None:
        clauses.append("harness = ?")
        params.append(harness)
    if search is not None:
        search_clause, search_params = _approval_search_clause(search)
        clauses.append(search_clause)
        params.extend(search_params)
    where_clause = f"where {' and '.join(clauses)}" if clauses else ""
    row = connection.execute(f"select count(*) as total from approval_requests {where_clause}", params).fetchone()
    return int(row["total"]) if row is not None else 0


def _row_to_payload(row: sqlite3.Row) -> dict[str, object]:
    payload: dict[str, object] = {
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
        "normalized_identity_key": row["normalized_identity_key"],
        "action_identity": row["action_identity"],
        "queue_group_id": row["queue_group_id"],
        "dedupe_count": int(row["dedupe_count"] or 1),
        "last_seen_at": row["last_seen_at"],
        "display_status": str(row["status"]),
        "resolution_intent": row["resolution_action"],
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
        "raw_command_text": row["raw_command_text"],
        "scanner_evidence": _json_object_list(row["scanner_evidence_json"]),
        "review_command": str(row["review_command"]),
        "approval_url": str(row["approval_url"]),
        "status": str(row["status"]),
        "resolution_action": row["resolution_action"],
        "resolution_scope": row["resolution_scope"],
        "reason": row["reason"],
        "created_at": str(row["created_at"]),
        "resolved_at": row["resolved_at"],
    }
    payload["allowed_scopes"] = list(supported_request_scopes(payload))
    return payload


def _safe_json_list(value: object) -> list[object]:
    if value is None:
        return []
    try:
        parsed = json.loads(str(value))
    except (json.JSONDecodeError, TypeError, ValueError):
        return []
    return list(parsed) if isinstance(parsed, list) else []


def _json_object(value: object) -> dict[str, object] | None:
    if value is None:
        return None
    try:
        parsed = json.loads(str(value))
    except (json.JSONDecodeError, TypeError, ValueError):
        return None
    return dict(parsed) if isinstance(parsed, dict) else None


def _json_object_list(value: object) -> list[dict[str, object]]:
    if value is None:
        return []
    try:
        parsed = json.loads(str(value))
    except (json.JSONDecodeError, TypeError, ValueError):
        return []
    if not isinstance(parsed, list):
        return []
    return [dict(item) for item in parsed if isinstance(item, dict)]


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
        "create index if not exists idx_approval_group_status on approval_requests(queue_group_id, status)",
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
        "create index if not exists idx_approval_resolution on approval_requests(resolution_action, resolved_at)",
    ]


def list_pending_approval_summaries(
    connection: sqlite3.Connection,
    *,
    limit: int = 50,
    cursor: str | None = None,
    harness: str | None = None,
    search: str | None = None,
    include_totals: bool = True,
) -> dict[str, object]:
    return list_approval_request_page(
        connection,
        status="pending",
        limit=limit,
        cursor=cursor,
        harness=harness,
        search=search,
        include_totals=include_totals,
    )


def _approval_summary_where_clause(
    *,
    status: str | None,
    harness: str | None,
    cursor: str | None,
    search: str | None,
) -> tuple[str, list[object]]:
    clauses: list[str] = []
    params: list[object] = []
    if status is not None:
        clauses.append("status = ?")
        params.append(status)
    if harness is not None:
        clauses.append("harness = ?")
        params.append(harness)
    if cursor is not None:
        marker = _decode_page_cursor(cursor)
        if marker is None:
            raise InvalidApprovalCursorError("invalid approval queue cursor")
        clauses.append("(last_seen_at < ? or (last_seen_at = ? and request_id < ?))")
        params.extend([marker["last_seen_at"], marker["last_seen_at"], marker["request_id"]])
    if search is not None:
        search_clause, search_params = _approval_search_clause(search)
        clauses.append(search_clause)
        params.extend(search_params)
    where_clause = f"where {' and '.join(clauses)}" if clauses else ""
    return where_clause, params


def _row_to_approval_summary(row: sqlite3.Row) -> dict[str, object]:
    return {
        "request_id": str(row["request_id"]),
        "harness": str(row["harness"]),
        "artifact_id": str(row["artifact_id"]),
        "artifact_name": str(row["artifact_name"]),
        "artifact_type": str(row["artifact_type"]),
        "policy_action": str(row["policy_action"]),
        "changed_fields": _safe_json_list(row["changed_fields_json"]),
        "source_scope": str(row["source_scope"]),
        "config_path": str(row["config_path"]),
        "workspace": row["workspace"],
        "launch_target": row["launch_target"],
        "risk_summary": row["risk_summary"],
        "risk_headline": row["risk_headline"],
        "raw_command_text": row["raw_command_text"],
        "fallback_cli_command": row["fallback_cli_command"],
        "review_command": str(row["review_command"]),
        "action_identity": row["action_identity"],
        "queue_group_id": row["queue_group_id"],
        "dedupe_count": int(row["dedupe_count"] or 1),
        "created_at": str(row["created_at"]),
        "last_seen_at": row["last_seen_at"],
        "display_status": str(row["status"]),
    }


def list_approval_request_summary_rows(
    connection: sqlite3.Connection,
    *,
    status: str | None = "pending",
    harness: str | None = None,
    limit: int | None = 50,
    cursor: str | None = None,
    search: str | None = None,
) -> list[dict[str, object]]:
    where_clause, params = _approval_summary_where_clause(
        status=status,
        harness=harness,
        cursor=cursor,
        search=search,
    )
    query = f"""
        select request_id, harness, artifact_id, artifact_name, artifact_type, policy_action,
               changed_fields_json, source_scope, config_path, workspace, launch_target,
               risk_summary, risk_headline, action_identity, queue_group_id, dedupe_count,
               raw_command_text, fallback_cli_command, review_command, created_at, last_seen_at, status
        from approval_requests
        {where_clause}
        order by last_seen_at desc, request_id desc
    """
    if limit is None:
        rows = connection.execute(query, params).fetchall()
    else:
        rows = connection.execute(f"{query}\nlimit ?", (*params, limit)).fetchall()
    return [_row_to_approval_summary(row) for row in rows]


def list_approval_request_page(
    connection: sqlite3.Connection,
    *,
    status: str | None = "pending",
    limit: int = 50,
    cursor: str | None = None,
    harness: str | None = None,
    search: str | None = None,
    include_totals: bool = True,
) -> dict[str, object]:
    page_limit = min(MAX_APPROVAL_PAGE_LIMIT, max(1, limit))
    rows = list_approval_request_summary_rows(
        connection,
        status=status,
        harness=harness,
        limit=page_limit + 1,
        cursor=cursor,
        search=search,
    )
    items = rows[:page_limit]
    next_cursor = _encode_page_cursor(items[-1]) if len(rows) > page_limit and items else None
    payload: dict[str, object] = {
        "items": items,
        "next_cursor": next_cursor,
        "status": status or "all",
    }
    if include_totals:
        if status == "pending":
            pending_total = count_approval_requests(
                connection,
                status="pending",
                harness=harness,
                search=search,
            )
            payload["total_pending_count"] = pending_total
            payload["total_count"] = pending_total
        elif status == "resolved":
            resolved_total = count_approval_requests(
                connection,
                status="resolved",
                harness=harness,
                search=search,
            )
            payload["total_count"] = resolved_total
            payload["total_pending_count"] = count_approval_requests(
                connection,
                status="pending",
                harness=harness,
                search=search,
            )
        elif status is None:
            payload["total_count"] = count_approval_requests(
                connection,
                status=None,
                harness=harness,
                search=search,
            )
            payload["total_pending_count"] = count_approval_requests(
                connection,
                status="pending",
                harness=harness,
                search=search,
            )
        else:
            payload["total_pending_count"] = count_approval_requests(
                connection,
                status="pending",
                harness=harness,
                search=search,
            )
            payload["total_count"] = count_approval_requests(
                connection,
                status=status,
                harness=harness,
                search=search,
            )
    return payload


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
        request_id=request_id,
        resolution_action=resolution_action,
        resolution_scope=resolution_scope,
        reason=reason,
        resolved_at=resolved_at,
    )
    updated = get_approval_request(connection, request_id)
    next_request = get_next_pending_request(connection, exclude_ids={request_id, *duplicate_ids})
    remaining_page = list_pending_approval_summaries(connection, limit=10)
    remaining_count_value = remaining_page.get("total_pending_count")
    remaining_count = int(remaining_count_value) if isinstance(remaining_count_value, int) else 0
    return {
        "resolved": True,
        "item": updated,
        "resolved_request": updated,
        "remaining_pending_count": remaining_count,
        "next_selectable_request_id": next_request["request_id"] if next_request is not None else None,
        "remaining_pending_summaries": remaining_page["items"],
        "resolved_duplicate_ids": duplicate_ids,
        "resolution_summary": _resolution_summary(remaining_count),
        "retry_hint": "Retry the action in your AI assistant if you approved it.",
    }


def backfill_approval_queue_columns(connection: sqlite3.Connection) -> None:
    while True:
        rows = connection.execute(
            """
            select request_id, harness, artifact_id, workspace, launch_target, action_envelope_json,
                   action_identity, queue_group_id, dedupe_count, last_seen_at, created_at
            from approval_requests
            where action_identity is null
               or queue_group_id is null
               or last_seen_at is null
               or dedupe_count is null
               or dedupe_count < 1
            order by created_at asc, request_id asc
            limit ?
            """,
            (APPROVAL_QUEUE_BACKFILL_BATCH_SIZE,),
        ).fetchall()
        if not rows:
            return
        for row in rows:
            action_identity = row["action_identity"] or _build_action_identity(
                launch_target=row["launch_target"],
                action_envelope=_optional_json_object(row["action_envelope_json"]),
            )
            queue_group_id = row["queue_group_id"] or _build_queue_group_id(
                harness=str(row["harness"]),
                workspace=row["workspace"],
                artifact_id=str(row["artifact_id"]),
                action_identity=str(action_identity),
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


def resolve_matching_duplicate_requests(
    connection: sqlite3.Connection,
    *,
    queue_group_id: str | None,
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
        select request_id
        from approval_requests
        where queue_group_id = ?
          and request_id != ?
          and status = 'pending'
        order by last_seen_at desc, request_id desc
        """,
        (queue_group_id, request_id),
    ).fetchall()
    connection.execute(
        """
        update approval_requests
        set status = 'resolved',
            resolution_action = ?,
            resolution_scope = ?,
            reason = ?,
            resolved_at = ?
        where queue_group_id = ?
          and request_id != ?
          and status = 'pending'
        """,
        (resolution_action, resolution_scope, reason, resolved_at, queue_group_id, request_id),
    )
    return [str(row["request_id"]) for row in rows]


def _approval_summary(item: dict[str, object]) -> dict[str, object]:
    return {
        "request_id": item["request_id"],
        "harness": item["harness"],
        "artifact_id": item["artifact_id"],
        "artifact_name": item["artifact_name"],
        "artifact_type": item["artifact_type"],
        "policy_action": item["policy_action"],
        "source_scope": item["source_scope"],
        "config_path": item["config_path"],
        "workspace": item["workspace"],
        "launch_target": item["launch_target"],
        "risk_summary": item["risk_summary"],
        "risk_headline": item["risk_headline"],
        "action_identity": item["action_identity"],
        "queue_group_id": item["queue_group_id"],
        "dedupe_count": item["dedupe_count"],
        "created_at": item["created_at"],
        "last_seen_at": item["last_seen_at"],
        "display_status": item["display_status"],
    }


def _encode_page_cursor(item: dict[str, object]) -> str:
    raw = json.dumps(
        {"last_seen_at": item["last_seen_at"], "request_id": item["request_id"]},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


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
    remaining_page = list_pending_approval_summaries(connection, limit=10)
    next_request = get_next_pending_request(connection)
    remaining_count_value = remaining_page.get("total_pending_count")
    return {
        "resolved": False,
        "error": error,
        "item": item,
        "remaining_pending_count": int(remaining_count_value) if isinstance(remaining_count_value, int) else 0,
        "next_selectable_request_id": next_request["request_id"] if next_request is not None else None,
        "remaining_pending_summaries": remaining_page["items"],
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
