"""Guard storage column upgrades and historical receipt migrations."""

from __future__ import annotations

# pyright: reportAttributeAccessIssue=false, reportUndefinedVariable=false


class StoreConnectionColumnsMixin:
    @staticmethod
    def _enable_wal_mode(connection: _schema.sqlite3.Connection) -> None:
        original_busy_timeout_row = connection.execute("pragma busy_timeout").fetchone()
        original_busy_timeout_ms = int(original_busy_timeout_row[0]) if original_busy_timeout_row else 0
        retry_deadline = _schema.time.monotonic() + (original_busy_timeout_ms / 1000)
        lock_error: _schema.sqlite3.OperationalError | None = None
        try:
            while True:
                remaining_timeout_ms = max(0, int((retry_deadline - _schema.time.monotonic()) * 1000))
                if lock_error is not None and remaining_timeout_ms <= 0:
                    raise lock_error
                wal_busy_timeout_ms = min(remaining_timeout_ms, _schema.SQLITE_WAL_BUSY_TIMEOUT_MS)
                connection.execute(f"pragma busy_timeout={wal_busy_timeout_ms}")
                try:
                    connection.execute("pragma journal_mode=WAL")
                    return
                except _schema.sqlite3.OperationalError as exc:
                    if "database is locked" not in str(exc).lower():
                        raise
                    lock_error = exc
                    remaining_seconds = retry_deadline - _schema.time.monotonic()
                    if remaining_seconds <= 0:
                        raise
                    _schema._sleep_compat(min(_schema._sqlite_lock_retry_delay_seconds_compat(), remaining_seconds))
        finally:
            connection.execute(f"pragma busy_timeout={original_busy_timeout_ms}")

    @staticmethod
    def _ensure_policy_column(connection: _schema.sqlite3.Connection, column_name: str, column_type: str) -> None:
        rows = connection.execute("pragma table_info(policy_decisions)").fetchall()
        existing = {str(row["name"]) for row in rows}
        if column_name in existing:
            return
        connection.execute(f"alter table policy_decisions add column {column_name} {column_type}")

    @staticmethod
    def _ensure_runtime_receipts_column(
        connection: _schema.sqlite3.Connection, column_name: str, column_type: str
    ) -> None:
        rows = connection.execute("pragma table_info(runtime_receipts)").fetchall()
        existing = {str(row["name"]) for row in rows}
        if column_name in existing:
            return
        connection.execute(f"alter table runtime_receipts add column {column_name} {column_type}")

    @staticmethod
    def _ensure_runtime_receipt_envelopes_table(connection: _schema.sqlite3.Connection) -> None:
        connection.execute(
            """
            create table if not exists runtime_receipt_envelopes (
              receipt_id text primary key references runtime_receipts(receipt_id) on delete cascade,
              envelope_full_json text,
              envelope_redacted_json text not null
            )
            """
        )

    @staticmethod
    def _migrate_v5_receipt_envelopes(connection: _schema.sqlite3.Connection) -> None:
        rows = connection.execute("pragma table_info(runtime_receipts)").fetchall()
        existing = {str(row["name"]) for row in rows}
        if "action_envelope_json" not in existing:
            return
        connection.execute(
            """
            insert into runtime_receipt_envelopes (receipt_id, envelope_full_json, envelope_redacted_json)
            select receipt_id, action_envelope_json, '{}'
            from runtime_receipts
            where action_envelope_json is not null
              and not exists (
                select 1 from runtime_receipt_envelopes
                where runtime_receipt_envelopes.receipt_id = runtime_receipts.receipt_id
              )
            """
        )
        connection.execute("drop table if exists runtime_receipts_new")
        connection.execute(
            """
            create table runtime_receipts_new (
              receipt_id text primary key,
              harness text not null,
              artifact_id text not null,
              artifact_hash text not null,
              policy_decision text not null,
              capabilities_summary text not null default '',
              changed_capabilities_json text not null,
              provenance_summary text not null,
              user_override text,
              artifact_name text,
              source_scope text,
              scanner_evidence_json text not null default '[]',
              timestamp text not null,
              diff_summary text,
              approval_source text,
              approval_request_id text,
              raw_command_text text
            )
            """
        )
        connection.execute(
            """
            insert into runtime_receipts_new (
              rowid, receipt_id, harness, artifact_id, artifact_hash, policy_decision,
              capabilities_summary, changed_capabilities_json, provenance_summary, user_override,
              artifact_name, source_scope, scanner_evidence_json, timestamp, diff_summary,
              approval_source, approval_request_id, raw_command_text
            )
            select
              rowid, receipt_id, harness, artifact_id, artifact_hash, policy_decision,
              capabilities_summary, changed_capabilities_json, provenance_summary, user_override,
              artifact_name, source_scope, scanner_evidence_json, timestamp, diff_summary,
              approval_source, null, null
            from runtime_receipts
            """
        )
        connection.execute("drop table runtime_receipts")
        connection.execute("alter table runtime_receipts_new rename to runtime_receipts")

    @staticmethod
    def _ensure_approval_column(connection: _schema.sqlite3.Connection, column_name: str, column_type: str) -> None:
        rows = connection.execute("pragma table_info(approval_requests)").fetchall()
        existing = {str(row["name"]) for row in rows}
        if column_name in existing:
            return
        connection.execute(f"alter table approval_requests add column {column_name} {column_type}")

    @staticmethod
    def _ensure_column(
        connection: _schema.sqlite3.Connection, table_name: str, column_name: str, column_type: str
    ) -> None:
        rows = connection.execute(f"pragma table_info({table_name})").fetchall()
        existing = {str(row["name"]) for row in rows}
        if column_name in existing:
            return
        connection.execute(f"alter table {table_name} add column {column_name} {column_type}")

    @staticmethod
    def _ensure_attachment_column(connection: _schema.sqlite3.Connection, column_name: str, column_type: str) -> None:
        rows = connection.execute("pragma table_info(guard_client_attachments)").fetchall()
        existing = {str(row["name"]) for row in rows}
        if column_name in existing:
            return
        connection.execute(f"alter table guard_client_attachments add column {column_name} {column_type}")

    @staticmethod
    def _ensure_evidence_column(connection: _schema.sqlite3.Connection, column_name: str, column_type: str) -> None:
        rows = connection.execute("pragma table_info(guard_evidence)").fetchall()
        existing = {str(row["name"]) for row in rows}
        if column_name in existing:
            return
        connection.execute(f"alter table guard_evidence add column {column_name} {column_type}")

    @staticmethod
    def _record_schema_version(connection: _schema.sqlite3.Connection, *, version: int) -> None:
        connection.execute(
            """
            insert or ignore into schema_migrations (version, applied_at)
            values (?, ?)
            """,
            (version, _schema._now()),
        )

    @staticmethod
    def _schema_version_applied(connection: _schema.sqlite3.Connection, *, version: int) -> bool:
        row = connection.execute(
            "select 1 from schema_migrations where version = ?",
            (version,),
        ).fetchone()
        return row is not None

    @staticmethod
    def _ensure_local_device(connection: _schema.sqlite3.Connection) -> None:
        row = connection.execute(
            "select device_key from guard_devices where device_key = ?",
            (_schema._DEVICE_ROW_KEY,),
        ).fetchone()
        if row is not None:
            return
        now = _schema._now()
        connection.execute(
            """
            insert into guard_devices (device_key, installation_id, device_label, created_at, updated_at)
            values (?, ?, ?, ?, ?)
            """,
            (_schema._DEVICE_ROW_KEY, _schema.uuid4().hex, "Local machine", now, now),
        )

    def list_table_names(self) -> list[str]:
        with self._connect() as connection:
            rows = connection.execute("select name from sqlite_master where type = 'table'").fetchall()
        return sorted(str(row["name"]) for row in rows)


# These globals remain owned by the connection facade.
from . import store_connection_schema as _schema  # noqa: E402
