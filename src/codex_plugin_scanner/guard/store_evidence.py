"""Phase 15: Evidence store — table, indexes, CRUD, search, export, compaction."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    evidence_id: str
    action_id: str
    request_id: str
    harness: str
    workspace: str
    signal_id: str
    category: str
    severity: str
    confidence: float
    summary: str
    details: dict[str, object] = field(default_factory=dict)
    action_identity: str | None = None
    created_at: str = field(default_factory=_now_iso)


def evidence_schema_statement() -> str:
    return """
    create table if not exists guard_evidence (
      evidence_id     text not null primary key,
      action_id       text not null default '',
      request_id      text not null default '',
      harness         text not null default '',
      workspace       text not null default '',
      signal_id       text not null default '',
      category        text not null default '',
      severity        text not null default '',
      confidence      real not null default 0.0,
      summary         text not null default '',
      details_json    text not null default '{}',
      action_identity text,
      created_at      text not null
    )
    """


def evidence_index_statements() -> list[str]:
    return [
        "create index if not exists idx_evidence_created on guard_evidence(created_at desc)",
        "create index if not exists idx_evidence_request on guard_evidence(request_id)",
        "create index if not exists idx_evidence_action on guard_evidence(action_id)",
        "create index if not exists idx_evidence_category_severity on guard_evidence(category, severity)",
        "create index if not exists idx_evidence_harness_workspace on guard_evidence(harness, workspace)",
        "create index if not exists idx_evidence_identity on guard_evidence(action_identity)",
    ]


def _row_to_record(row: sqlite3.Row) -> EvidenceRecord:
    try:
        details: dict[str, object] = json.loads(row["details_json"])
    except (json.JSONDecodeError, TypeError):
        details = {}
    columns = set(row.keys())
    return EvidenceRecord(
        evidence_id=row["evidence_id"],
        action_id=row["action_id"],
        request_id=row["request_id"],
        harness=row["harness"],
        workspace=row["workspace"],
        signal_id=row["signal_id"],
        category=row["category"],
        severity=row["severity"],
        confidence=row["confidence"],
        summary=row["summary"],
        details=details,
        action_identity=row["action_identity"] if "action_identity" in columns else None,
        created_at=row["created_at"],
    )


def store_evidence(conn: sqlite3.Connection, record: EvidenceRecord) -> EvidenceRecord:
    conn.execute(
        """
        insert or replace into guard_evidence
          (evidence_id, action_id, request_id, harness, workspace, signal_id,
           category, severity, confidence, summary, details_json, action_identity, created_at)
        values (?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            record.evidence_id,
            record.action_id,
            record.request_id,
            record.harness,
            record.workspace,
            record.signal_id,
            record.category,
            record.severity,
            record.confidence,
            record.summary,
            json.dumps(record.details),
            record.action_identity,
            record.created_at,
        ),
    )
    conn.commit()
    return record


def list_evidence(
    conn: sqlite3.Connection,
    *,
    harness: str | None = None,
    category: str | None = None,
    severity: str | None = None,
    request_id: str | None = None,
    action_identity: str | None = None,
    before_cursor: str | None = None,
    limit: int = 100,
) -> list[EvidenceRecord]:
    clauses: list[str] = []
    params: list[object] = []

    if harness is not None:
        clauses.append("harness = ?")
        params.append(harness)
    if category is not None:
        clauses.append("category = ?")
        params.append(category)
    if severity is not None:
        clauses.append("severity = ?")
        params.append(severity)
    if request_id is not None:
        clauses.append("request_id = ?")
        params.append(request_id)
    if action_identity is not None:
        clauses.append("action_identity = ?")
        params.append(action_identity)
    if before_cursor is not None:
        clauses.append("created_at < ?")
        params.append(before_cursor)

    where = f"where {' and '.join(clauses)}" if clauses else ""
    params.append(limit)
    rows = conn.execute(
        f"select * from guard_evidence {where} order by created_at desc limit ?",
        params,
    ).fetchall()
    return [_row_to_record(r) for r in rows]


def search_evidence(
    conn: sqlite3.Connection,
    query: str,
    *,
    limit: int = 100,
) -> list[EvidenceRecord]:
    pattern = f"%{query}%"
    rows = conn.execute(
        "select * from guard_evidence where lower(summary) like lower(?) order by created_at desc limit ?",
        (pattern, limit),
    ).fetchall()
    return [_row_to_record(r) for r in rows]


def count_evidence(
    conn: sqlite3.Connection,
    *,
    harness: str | None = None,
    category: str | None = None,
) -> int:
    clauses: list[str] = []
    params: list[object] = []
    if harness is not None:
        clauses.append("harness = ?")
        params.append(harness)
    if category is not None:
        clauses.append("category = ?")
        params.append(category)
    where = f"where {' and '.join(clauses)}" if clauses else ""
    row = conn.execute(f"select count(*) from guard_evidence {where}", params).fetchone()
    return int(row[0])


def export_evidence_json(
    conn: sqlite3.Connection,
    *,
    limit: int = 10_000,
    redact_fields: tuple[str, ...] | None = None,
) -> str:
    """Export evidence records as JSON, omitting sensitive fields by default.

    Pass ``redact_fields=()`` to include all fields including ``details``.
    By default ``details`` is redacted (excluded from export).
    """
    _redact = {"details"} if redact_fields is None else set(redact_fields)
    records = list_evidence(conn, limit=limit)
    rows: list[dict[str, object]] = []
    for r in records:
        row: dict[str, object] = {
            "evidence_id": r.evidence_id,
            "action_id": r.action_id,
            "request_id": r.request_id,
            "harness": r.harness,
            "workspace": r.workspace,
            "signal_id": r.signal_id,
            "category": r.category,
            "severity": r.severity,
            "confidence": r.confidence,
            "summary": r.summary,
            "action_identity": r.action_identity,
            "created_at": r.created_at,
        }
        if "details" not in _redact:
            row["details"] = r.details
        rows.append(row)
    return json.dumps(rows, indent=2)


def clear_evidence(conn: sqlite3.Connection) -> int:
    cursor = conn.execute("delete from guard_evidence")
    conn.commit()
    return cursor.rowcount


def compact_evidence(conn: sqlite3.Connection, *, retain_days: int = 90) -> int:
    cutoff = (
        (datetime.now(timezone.utc) - timedelta(days=retain_days))
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )
    cursor = conn.execute(
        "delete from guard_evidence where created_at < ?",
        (cutoff,),
    )
    conn.commit()
    return cursor.rowcount
