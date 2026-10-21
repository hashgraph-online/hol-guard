"""Control-plane persistence for privacy-safe native hook decision receipts."""

from __future__ import annotations

import json
import re
import sqlite3
from collections.abc import Mapping
from contextlib import AbstractContextManager
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Final, Protocol

from .native_decision_receipt import validate_native_decision_receipt

NATIVE_DECISION_RECEIPT_MIGRATION_VERSION: Final = 26
NATIVE_COMMAND_RECEIPT_BINDING_MIGRATION_VERSION: Final = 28
NATIVE_PROMPT_RECEIPT_MIGRATION_VERSION: Final = 29
_MAX_COMMAND_BINDING_CHARACTERS: Final = 2048
_MAX_PROMPT_RISK_CHARACTERS: Final = 256
_COMMAND_BINDING_COLUMN: Final = (
    "command_extensions_json text check (command_extensions_json is null "
    f"or length(command_extensions_json) between 2 and {_MAX_COMMAND_BINDING_CHARACTERS})"
)


class _ConnectionOwner(Protocol):
    def _connect(self) -> AbstractContextManager[sqlite3.Connection]: ...


def native_decision_receipt_schema_statement(*, prompt: bool = False) -> str:
    table = "native_prompt_decision_receipts" if prompt else "native_hook_decision_receipts"
    event_check = "event_name = 'UserPromptSubmit'" if prompt else "event_name in ('PreToolUse', 'PostToolUse')"
    risk_column = (
        "prompt_risk_classes_json text not null check "
        f"(length(prompt_risk_classes_json) between 2 and {_MAX_PROMPT_RISK_CHARACTERS}),"
        if prompt
        else ""
    )
    return f"""
    create table if not exists {table} (
      decision_id text primary key,
      schema text not null check (schema = 'guard-native-hook-decision-receipt.v1'),
      version integer not null check (version = 1),
      authority text not null check (authority = 'rust'),
      request_id text not null,
      request_digest text not null,
      harness text not null,
      event_name text not null check ({event_check}),
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
      {risk_column}
      recorded_at text not null
    )
    """


def native_decision_receipt_index_statements() -> tuple[str, ...]:
    return (
        """
        create index if not exists idx_native_hook_decision_receipts_recorded_at
        on native_hook_decision_receipts (recorded_at)
        """,
        """
        create index if not exists idx_native_prompt_decision_receipts_recorded_at
        on native_prompt_decision_receipts (recorded_at)
        """,
    )


def native_decision_receipt_migration_versions() -> tuple[int, ...]:
    return (
        NATIVE_DECISION_RECEIPT_MIGRATION_VERSION,
        NATIVE_COMMAND_RECEIPT_BINDING_MIGRATION_VERSION,
        NATIVE_PROMPT_RECEIPT_MIGRATION_VERSION,
    )


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
        native_decision_receipt_schema_statement(prompt=True),
        *native_decision_receipt_index_statements(),
        "insert or ignore into schema_migrations (version, applied_at) values "
        f"({NATIVE_DECISION_RECEIPT_MIGRATION_VERSION}, datetime('now'))",
        "insert or ignore into schema_migrations (version, applied_at) values "
        f"({NATIVE_PROMPT_RECEIPT_MIGRATION_VERSION}, datetime('now'))",
    )


class StoreNativeDecisionReceiptsMixin:
    if TYPE_CHECKING:

        def _native_store_call(
            self, method: str, args: Mapping[str, object], *, busy_timeout_seconds: float | None = None
        ) -> Any: ...

    def record_native_decision_receipt(self, receipt: Mapping[str, object]) -> bool:
        """Store one validated receipt; duplicate decision IDs are harmless."""

        # The decision ID commits to a canonical encoding of the receipt's own
        # fields, so the resident validates the wire text rather than a shape
        # this process has already rebuilt.
        self._native_store_call(
            "record_native_decision_receipt",
            {"receipt": _receipt_wire(receipt), "now": datetime.now(timezone.utc).isoformat()},
        )
        return True

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
                row = connection.execute(
                    "select * from native_prompt_decision_receipts where decision_id = ?",
                    (decision_id,),
                ).fetchone()
        if row is None:
            return None
        return validate_stored_native_decision_receipt(dict(row))


def _receipt_wire(receipt: Mapping[str, object]) -> str:
    """Encode one receipt as the JSON text the resident validates."""
    try:
        return json.dumps(receipt, ensure_ascii=False, allow_nan=False, default=_mapping_as_object)
    except (TypeError, ValueError) as error:
        raise ValueError("native decision receipt is invalid") from error


def _mapping_as_object(value: object) -> dict[str, object]:
    # Callers hand us any mapping, and the command binding nested inside one is
    # a mapping of its own. JSON only knows how to write a dict, and a receipt
    # that reads like an object has always been storable whatever type carried
    # it, so keep that true rather than rejecting the carrier.
    if isinstance(value, Mapping):
        return dict(value)
    raise TypeError("native decision receipt is not JSON data")


def validate_stored_native_decision_receipt(row: Mapping[str, object]) -> dict[str, object] | None:
    """Validate one complete stored row, including its content-bound decision ID."""
    result = dict(row)
    result.pop("recorded_at", None)
    raw_binding = result.pop("command_extensions_json", None)
    if raw_binding is not None:
        if not isinstance(raw_binding, str) or len(raw_binding) > _MAX_COMMAND_BINDING_CHARACTERS:
            return None
        try:
            result["command_extensions"] = json.loads(raw_binding)
        except (ValueError, RecursionError):
            return None
    raw_risks = result.pop("prompt_risk_classes_json", None)
    if raw_risks is not None:
        if not isinstance(raw_risks, str) or len(raw_risks) > _MAX_PROMPT_RISK_CHARACTERS:
            return None
        try:
            classes = json.loads(raw_risks)
        except (ValueError, RecursionError):
            return None
        if classes:
            result["prompt_risk_classes"] = classes
    for field in ("workspace_bound", "source_ref_external_allowed", "observe_mode"):
        if result.get(field) not in (0, 1):
            return None
        result[field] = bool(result[field])
    return validate_native_decision_receipt(result)


__all__ = [
    "NATIVE_COMMAND_RECEIPT_BINDING_MIGRATION_VERSION",
    "NATIVE_DECISION_RECEIPT_MIGRATION_VERSION",
    "NATIVE_PROMPT_RECEIPT_MIGRATION_VERSION",
    "StoreNativeDecisionReceiptsMixin",
    "ensure_native_command_receipt_binding_schema",
    "native_decision_receipt_index_statements",
    "native_decision_receipt_migration_versions",
    "native_decision_receipt_schema_statement",
    "native_decision_receipt_schema_statements",
]
