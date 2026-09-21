"""Control-plane persistence for privacy-safe native hook decision receipts."""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from contextlib import AbstractContextManager
from datetime import datetime, timezone
from typing import Final, Protocol, cast

from .native_decision_receipt import validate_native_decision_receipt

NATIVE_DECISION_RECEIPT_MIGRATION_VERSION: Final = 26


class _ConnectionOwner(Protocol):
    def _connect(self) -> AbstractContextManager[sqlite3.Connection]: ...


def native_decision_receipt_schema_statement() -> str:
    return """
    create table if not exists native_hook_decision_receipts (
      decision_id text primary key,
      schema text not null check (schema = 'guard-native-hook-decision-receipt.v1'),
      version integer not null check (version = 1),
      authority text not null check (authority = 'rust'),
      request_id text not null,
      request_digest text not null,
      harness text not null,
      event_name text not null check (event_name in ('PreToolUse', 'PostToolUse')),
      payload_kind text not null,
      policy_generation integer not null,
      policy_digest text,
      rule_digest text,
      runtime_identity text,
      decision text not null check (decision in ('allow', 'deny')),
      model_output_action text not null,
      policy_action text,
      observed_policy_action text,
      reason_code text not null,
      workspace_bound integer not null check (workspace_bound in (0, 1)),
      source_ref_external_allowed integer not null check (source_ref_external_allowed in (0, 1)),
      reviewed_output_sha256 text,
      observe_mode integer not null check (observe_mode in (0, 1)),
      deadline_budget_ms integer,
      recorded_at text not null
    )
    """


def native_decision_receipt_index_statements() -> tuple[str, ...]:
    return (
        """
        create index if not exists idx_native_hook_decision_receipts_recorded_at
        on native_hook_decision_receipts (recorded_at)
        """,
    )


def native_decision_receipt_migration_versions() -> tuple[int, ...]:
    return (NATIVE_DECISION_RECEIPT_MIGRATION_VERSION,)


def native_decision_receipt_schema_statements(*prefix: str) -> tuple[str, ...]:
    return (
        *prefix,
        native_decision_receipt_schema_statement(),
        *native_decision_receipt_index_statements(),
        "insert or ignore into schema_migrations (version, applied_at) values "
        f"({NATIVE_DECISION_RECEIPT_MIGRATION_VERSION}, datetime('now'))",
    )


class StoreNativeDecisionReceiptsMixin:
    def record_native_decision_receipt(self: _ConnectionOwner, receipt: Mapping[str, object]) -> bool:
        """Store one validated receipt; duplicate decision IDs are harmless."""

        validated = validate_native_decision_receipt(receipt)
        if validated is None:
            raise ValueError("native decision receipt is invalid")
        with self._connect() as connection:
            connection.execute(
                """
                insert or ignore into native_hook_decision_receipts (
                  decision_id, schema, version, authority, request_id,
                  request_digest, harness, event_name, payload_kind,
                  policy_generation, policy_digest, rule_digest,
                  runtime_identity, decision, model_output_action,
                  policy_action, observed_policy_action, reason_code,
                  workspace_bound, source_ref_external_allowed,
                  reviewed_output_sha256, observe_mode, deadline_budget_ms,
                  recorded_at
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    validated["decision_id"],
                    validated["schema"],
                    validated["version"],
                    validated["authority"],
                    validated["request_id"],
                    validated["request_digest"],
                    validated["harness"],
                    validated["event_name"],
                    validated["payload_kind"],
                    validated["policy_generation"],
                    validated["policy_digest"],
                    validated["rule_digest"],
                    validated["runtime_identity"],
                    validated["decision"],
                    validated["model_output_action"],
                    validated["policy_action"],
                    validated["observed_policy_action"],
                    validated["reason_code"],
                    int(cast_bool(validated["workspace_bound"])),
                    int(cast_bool(validated["source_ref_external_allowed"])),
                    validated["reviewed_output_sha256"],
                    int(cast_bool(validated["observe_mode"])),
                    validated["deadline_budget_ms"],
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
        return True

    def native_decision_receipt_count(self: _ConnectionOwner) -> int:
        with self._connect() as connection:
            row = cast(
                sqlite3.Row | None,
                connection.execute("select count(*) as count from native_hook_decision_receipts").fetchone(),
            )
        return int(row["count"]) if row is not None else 0


def cast_bool(value: object) -> bool:
    if not isinstance(value, bool):
        raise ValueError("native decision receipt boolean is invalid")
    return value


__all__ = [
    "NATIVE_DECISION_RECEIPT_MIGRATION_VERSION",
    "StoreNativeDecisionReceiptsMixin",
    "native_decision_receipt_index_statements",
    "native_decision_receipt_migration_versions",
    "native_decision_receipt_schema_statement",
    "native_decision_receipt_schema_statements",
]
