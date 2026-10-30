"""Phase 15: Evidence store — table, indexes, CRUD, search, export, compaction.

The native resident (``guard_store`` op) owns the evidence reads and writes;
this module keeps the schema the store creates at startup, the record type
and the redacted exports.
"""

from __future__ import annotations

import csv
import io
import json
import re
import sqlite3
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol

from .redaction import redact_local_path, redact_sensitive_text, redact_text

EXPORT_PRIVACY_WARNING = (
    "Evidence exports redact detector details, local user paths, and token-like values. "
    "Review the file before sharing it outside your team."
)

_EXPORT_COLUMNS: tuple[str, ...] = (
    "evidence_id",
    "action_id",
    "request_id",
    "harness",
    "workspace",
    "signal_id",
    "category",
    "severity",
    "confidence",
    "summary",
    "action_identity",
    "created_at",
)
_CSV_FORMULA_TRIGGER_PATTERN = re.compile(r"^[=+\-@\t\r\n]")
_EVIDENCE_LIST_COLUMNS: tuple[str, ...] = (
    "evidence_id",
    "action_id",
    "request_id",
    "harness",
    "workspace",
    "signal_id",
    "category",
    "severity",
    "confidence",
    "summary",
    "details_json",
    "action_identity",
    "created_at",
)
_EVIDENCE_SUMMARY_COLUMNS: tuple[str, ...] = tuple(
    column for column in _EVIDENCE_LIST_COLUMNS if column != "details_json"
)


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
        "create index if not exists idx_evidence_request_created on guard_evidence(request_id, created_at desc)",
        "create index if not exists idx_evidence_identity_created on guard_evidence(action_identity, created_at desc)",
        "create index if not exists idx_evidence_harness_created on guard_evidence(harness, created_at desc)",
        (
            "create index if not exists idx_evidence_category_severity_created "
            "on guard_evidence(category, severity, created_at desc)"
        ),
        (
            "create index if not exists idx_evidence_harness_category_severity_created "
            "on guard_evidence(harness, category, severity, created_at desc)"
        ),
    ]


_EVIDENCE_SCHEMA_READY: set[str] = set()


def _evidence_schema_cache_key(connection: sqlite3.Connection) -> str:
    row = connection.execute("pragma database_list").fetchone()
    if row is None:
        return ":memory:"
    file_path = row[2]
    return str(file_path) if file_path else ":memory:"


def ensure_evidence_schema(connection: sqlite3.Connection) -> None:
    """Create or repair the evidence table, columns, and indexes."""
    cache_key = _evidence_schema_cache_key(connection)
    if cache_key in _EVIDENCE_SCHEMA_READY:
        row = connection.execute(
            "select 1 from sqlite_master where type='table' and name='guard_evidence' limit 1"
        ).fetchone()
        if row is not None:
            return
        _EVIDENCE_SCHEMA_READY.discard(cache_key)
    connection.execute(evidence_schema_statement())
    rows = connection.execute("pragma table_info(guard_evidence)").fetchall()
    existing = {str(row[1]) for row in rows}
    if "action_identity" not in existing:
        try:
            connection.execute("alter table guard_evidence add column action_identity text")
        except sqlite3.OperationalError as error:
            if "duplicate column name" not in str(error).lower():
                raise
    for statement in evidence_index_statements():
        connection.execute(statement)
    _EVIDENCE_SCHEMA_READY.add(cache_key)


class _NativeStore(Protocol):
    def _native_store_call(self, method: str, args: Mapping[str, object]) -> Any: ...


def _row_to_record(row: Mapping[str, Any], *, include_details: bool = True) -> EvidenceRecord:
    details: dict[str, object] = {}
    if include_details:
        try:
            details = json.loads(row["details_json"])
        except (json.JSONDecodeError, TypeError):
            details = {}
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
        action_identity=row.get("action_identity"),
        created_at=row["created_at"],
    )


def store_evidence(store: _NativeStore, record: EvidenceRecord) -> EvidenceRecord:
    store._native_store_call(
        "add_evidence",
        {
            "evidence_id": record.evidence_id,
            "action_id": record.action_id,
            "request_id": record.request_id,
            "harness": record.harness,
            "workspace": record.workspace,
            "signal_id": record.signal_id,
            "category": record.category,
            "severity": record.severity,
            "confidence": record.confidence,
            "summary": record.summary,
            "details_json": json.dumps(record.details),
            "action_identity": record.action_identity,
            "created_at": record.created_at,
        },
    )
    return record


def list_evidence(
    store: _NativeStore,
    *,
    harness: str | None = None,
    category: str | None = None,
    severity: str | None = None,
    request_id: str | None = None,
    action_identity: str | None = None,
    before_cursor: str | None = None,
    limit: int = 100,
    include_details: bool = True,
) -> list[EvidenceRecord]:
    """Read newest first, in as many native reads as the rows need."""

    args: dict[str, object] = {
        "harness": harness,
        "category": category,
        "severity": severity,
        "request_id": request_id,
        "action_identity": action_identity,
        "before_cursor": before_cursor,
        "include_details": include_details,
    }
    records: list[EvidenceRecord] = []
    while len(records) < limit:
        page = store._native_store_call(
            "list_evidence", {**args, "limit": limit - len(records), "offset": len(records)}
        )
        records.extend(_row_to_record(row, include_details=include_details) for row in page["rows"])
        if not page["more"] or not page["rows"]:
            break
    return records


def count_evidence(
    store: _NativeStore,
    *,
    harness: str | None = None,
    category: str | None = None,
    severity: str | None = None,
) -> int:
    return int(
        store._native_store_call("count_evidence", {"harness": harness, "category": category, "severity": severity})
    )


def _redact_export_value(value: object) -> object:
    if isinstance(value, str):
        redacted = redact_text(value).text
        return redact_sensitive_text(redact_local_path(redacted))
    if isinstance(value, list):
        return [_redact_export_value(item) for item in value]
    if isinstance(value, tuple):
        return [_redact_export_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _redact_export_value(item) for key, item in value.items()}
    return value


def evidence_record_to_dict(record: EvidenceRecord, *, redact_fields: set[str] | None = None) -> dict[str, object]:
    active_redact_fields = {"details"} if redact_fields is None else redact_fields
    row: dict[str, object] = {
        "evidence_id": record.evidence_id,
        "action_id": record.action_id,
        "request_id": record.request_id,
        "harness": record.harness,
        "workspace": record.workspace,
        "signal_id": record.signal_id,
        "category": record.category,
        "severity": record.severity,
        "confidence": record.confidence,
        "summary": record.summary,
        "action_identity": record.action_identity,
        "created_at": record.created_at,
    }
    if "details" not in active_redact_fields:
        row["details"] = record.details
    return {key: _redact_export_value(value) for key, value in row.items()}


def export_evidence_payload(
    store: _NativeStore,
    *,
    limit: int = 10_000,
    redact_fields: tuple[str, ...] | None = None,
) -> dict[str, object]:
    redact_set = {"details"} if redact_fields is None else set(redact_fields)
    records = list_evidence(store, limit=limit, include_details="details" not in redact_set)
    rows = [evidence_record_to_dict(record, redact_fields=redact_set) for record in records]
    return {
        "exported_at": _now_iso(),
        "privacy_warning": EXPORT_PRIVACY_WARNING,
        "redaction": {
            "details": "omitted" if "details" in redact_set else "redacted",
            "local_paths": "redacted",
            "token_like_values": "redacted",
        },
        "total_rows": len(rows),
        "items": rows,
    }


def export_evidence_json(
    store: _NativeStore,
    *,
    limit: int = 10_000,
    redact_fields: tuple[str, ...] | None = None,
) -> str:
    """Export evidence records as redacted JSON with sharing guidance."""

    return json.dumps(export_evidence_payload(store, limit=limit, redact_fields=redact_fields), indent=2)


def export_evidence_csv(
    store: _NativeStore,
    *,
    limit: int = 10_000,
    redact_fields: tuple[str, ...] | None = None,
) -> str:
    payload = export_evidence_payload(store, limit=limit, redact_fields=redact_fields)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(("privacy_warning", payload["privacy_warning"]))
    writer.writerow(("exported_at", payload["exported_at"]))
    writer.writerow(("total_rows", payload["total_rows"]))
    writer.writerow(())
    writer.writerow(_EXPORT_COLUMNS)
    items = payload.get("items")
    if isinstance(items, list):
        for item in items:
            if not isinstance(item, dict):
                continue
            writer.writerow([_sanitize_csv_formula_cell(item.get(column, "")) for column in _EXPORT_COLUMNS])
    return output.getvalue()


def _sanitize_csv_formula_cell(value: object) -> object:
    if not isinstance(value, str):
        return value
    if _CSV_FORMULA_TRIGGER_PATTERN.match(value):
        return f"'{value}"
    return value


def clear_evidence(store: _NativeStore) -> int:
    return int(store._native_store_call("clear_evidence", {}))
