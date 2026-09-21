"""Control-plane persistence for privacy-safe native hook decision receipts."""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Mapping, Sequence
from contextlib import AbstractContextManager
from datetime import datetime, timezone
from typing import Final, Protocol, cast

from .native_decision_receipt import validate_native_decision_receipt

NATIVE_DECISION_RECEIPT_MIGRATION_VERSION: Final = 26
NATIVE_COMMAND_RECEIPT_BINDING_MIGRATION_VERSION: Final = 28
_MAX_COMMAND_BINDING_CHARACTERS: Final = 2048
_COMMAND_BINDING_COLUMN: Final = (
    "command_extensions_json text check (command_extensions_json is null "
    f"or length(command_extensions_json) between 2 and {_MAX_COMMAND_BINDING_CHARACTERS})"
)


class _ConnectionOwner(Protocol):
    def _connect(self) -> AbstractContextManager[sqlite3.Connection]: ...


def native_decision_receipt_schema_statement() -> str:
    return f"""
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
      {_COMMAND_BINDING_COLUMN},
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
    return (NATIVE_DECISION_RECEIPT_MIGRATION_VERSION, NATIVE_COMMAND_RECEIPT_BINDING_MIGRATION_VERSION)


def ensure_native_command_receipt_binding_schema(connection: sqlite3.Connection, *, applied_at: str) -> None:
    """Upgrade legacy receipt rows without inventing a missing command binding."""
    columns = {str(row[1]) for row in connection.execute("pragma table_info(native_hook_decision_receipts)")}
    if "command_extensions_json" not in columns:
        connection.execute("alter table native_hook_decision_receipts add column " + _COMMAND_BINDING_COLUMN)
    connection.execute(
        "insert or ignore into schema_migrations (version, applied_at) values (?, ?)",
        (NATIVE_COMMAND_RECEIPT_BINDING_MIGRATION_VERSION, applied_at),
    )


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

        _record_native_decision_receipts(self, (receipt,))
        return True

    def record_native_decision_receipts(
        self: _ConnectionOwner, receipts: Sequence[Mapping[str, object]]
    ) -> tuple[str, ...]:
        """Commit a bounded batch atomically, returning acknowledged identities.

        Validate every input before opening a transaction. A failed commit
        acknowledges none; replay of an already committed decision is harmless.
        """

        return _record_native_decision_receipts(self, receipts)

    def native_decision_receipt_count(self: _ConnectionOwner) -> int:
        with self._connect() as connection:
            row = cast(
                sqlite3.Row | None,
                connection.execute("select count(*) as count from native_hook_decision_receipts").fetchone(),
            )
        return int(row["count"]) if row is not None else 0

    def get_native_decision_receipt(self: _ConnectionOwner, decision_id: str) -> dict[str, object] | None:
        """Read one complete receipt and reject changed identity or binding data."""
        if re.fullmatch(r"[0-9a-f]{64}", decision_id) is None:
            return None
        with self._connect() as connection:
            row = connection.execute(
                "select * from native_hook_decision_receipts where decision_id = ?",
                (decision_id,),
            ).fetchone()
        if row is None:
            return None
        result = dict(row)
        result.pop("recorded_at")
        raw_binding = result.pop("command_extensions_json")
        if raw_binding is not None:
            if not isinstance(raw_binding, str) or len(raw_binding) > _MAX_COMMAND_BINDING_CHARACTERS:
                return None
            try:
                result["command_extensions"] = json.loads(raw_binding)
            except (ValueError, RecursionError):
                return None
        for field in ("workspace_bound", "source_ref_external_allowed", "observe_mode"):
            if result[field] not in (0, 1):
                return None
            result[field] = bool(result[field])
        return validate_native_decision_receipt(result)


def _record_native_decision_receipts(
    owner: _ConnectionOwner, receipts: Sequence[Mapping[str, object]]
) -> tuple[str, ...]:
    if len(receipts) > 50:
        raise ValueError("native decision receipt batch exceeds 50 records")
    validated_receipts: list[dict[str, object]] = []
    for receipt in receipts:
        validated = validate_native_decision_receipt(receipt)
        if validated is None:
            raise ValueError("native decision receipt is invalid")
        # The command binding is nested. Detach it before batching so a caller
        # cannot mutate that mapping after validation and change the stored
        # binding without changing the receipt identity.
        detached = json.loads(json.dumps(validated, sort_keys=True, separators=(",", ":"), allow_nan=False))
        validated = validate_native_decision_receipt(detached)
        if validated is None:
            raise ValueError("native decision receipt changed during capture")
        validated_receipts.append(validated)
    if not validated_receipts:
        return ()
    recorded_at = datetime.now(timezone.utc).isoformat()
    with owner._connect() as connection:
        connection.executemany(
            """
                insert or ignore into native_hook_decision_receipts (
                  decision_id, schema, version, authority, request_id,
                  request_digest, harness, event_name, payload_kind,
                  policy_generation, policy_digest, rule_digest,
                  runtime_identity, decision, model_output_action,
                  policy_action, observed_policy_action, reason_code,
                  workspace_bound, source_ref_external_allowed,
                  reviewed_output_sha256, observe_mode, deadline_budget_ms,
                  command_extensions_json, recorded_at
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
            [
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
                    (
                        json.dumps(validated["command_extensions"], sort_keys=True, separators=(",", ":"))
                        if "command_extensions" in validated
                        else None
                    ),
                    recorded_at,
                )
                for validated in validated_receipts
            ],
        )
    return tuple(cast(str, receipt["decision_id"]) for receipt in validated_receipts)


def cast_bool(value: object) -> bool:
    if not isinstance(value, bool):
        raise ValueError("native decision receipt boolean is invalid")
    return value


__all__ = [
    "NATIVE_COMMAND_RECEIPT_BINDING_MIGRATION_VERSION",
    "NATIVE_DECISION_RECEIPT_MIGRATION_VERSION",
    "StoreNativeDecisionReceiptsMixin",
    "ensure_native_command_receipt_binding_schema",
    "native_decision_receipt_index_statements",
    "native_decision_receipt_migration_versions",
    "native_decision_receipt_schema_statement",
    "native_decision_receipt_schema_statements",
]
