"""Crash-safe validated SQLite schema for dormant workflow capabilities."""

# pyright: reportAny=false, reportUnusedCallResult=false

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from typing import Final

WORKFLOW_CAPABILITY_MIGRATION_VERSION: Final = 14

# The statements and the objects they own are declared once, in
# ``guard/contracts/workflow-capability-schema.v1.json``. The native store runs
# the same statements and checks the same objects before every operation.
SCHEMA_CONTRACT_PATH: Final = Path(__file__).resolve().parent / "contracts" / "workflow-capability-schema.v1.json"
_SCHEMA_CONTRACT: Final = "hol-guard.workflow-capability-schema.v1"


def _load_schema_contract() -> tuple[tuple[str, ...], tuple[tuple[str, str], ...]]:
    document = json.loads(SCHEMA_CONTRACT_PATH.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or document.get("schema") != _SCHEMA_CONTRACT:
        raise RuntimeError("invalid_workflow_capability_schema:contract")
    statements = document.get("statements")
    objects = document.get("objects")
    if (
        not isinstance(statements, list)
        or not isinstance(objects, list)
        or len(statements) != len(objects)
        or not all(isinstance(statement, str) for statement in statements)
        or not all(
            isinstance(item, list) and len(item) == 2 and all(isinstance(part, str) for part in item)
            for item in objects
        )
    ):
        raise RuntimeError("invalid_workflow_capability_schema:contract")
    return tuple(statements), tuple((item[0], item[1]) for item in objects)


_SCHEMA_STATEMENTS, _OBJECT_NAMES = _load_schema_contract()

# One-time follow-up migration that drops an index the workflow-capability
# schema owned and registered in an earlier release (it backed receipt-by-event
# lookups). The index was later retired from the schema, but databases created
# under the older version still own it, and the strict owned-object equality
# check then raises ``owned_objects`` on every reopen. This is a discrete
# migration step with its own ``schema_migrations`` version, not an ongoing
# compatibility surface: the drop is idempotent (``if exists``) so it runs on
# every schema ensure without effect on databases that never owned the index,
# while the strict tamper-detection guarantee (set(actual) == set(expected))
# stays intact.
WORKFLOW_CAPABILITY_RECEIPT_EVENT_INDEX_MIGRATION_VERSION: Final = 22
WORKFLOW_CAPABILITY_RETIRED_RECEIPT_EVENT_INDEX: Final = "idx_guard_workflow_receipt_event"


def ensure_workflow_capability_schema(connection: sqlite3.Connection, *, applied_at: str) -> None:
    """Apply the workflow-capability schema migrations and validate owned objects."""
    # Drop the retired receipt-event index before opening the validation savepoint. Doing the
    # drop inside the savepoint was unsafe: if validation raised, the savepoint rollback undid
    # the drop and the orphan index survived, failing every reopen on databases created under
    # the older schema. Run it first so it survives a validation rollback.
    _drop_retired_receipt_event_index_once(connection, applied_at=applied_at)
    connection.execute("savepoint workflow_capability_schema_v14")
    try:
        for statement in _SCHEMA_STATEMENTS:
            connection.execute(statement)
        _validate_schema_objects(connection)
        connection.execute(
            "insert or ignore into schema_migrations (version, applied_at) values (?, ?)",
            (WORKFLOW_CAPABILITY_MIGRATION_VERSION, applied_at),
        )
        version = connection.execute(
            "select applied_at from schema_migrations where version = ?",
            (WORKFLOW_CAPABILITY_MIGRATION_VERSION,),
        ).fetchone()
        if version is None or not str(version[0]):
            raise RuntimeError("workflow_capability_migration_not_recorded")
    except sqlite3.DatabaseError as error:
        connection.execute("rollback to workflow_capability_schema_v14")
        connection.execute("release workflow_capability_schema_v14")
        raise RuntimeError("invalid_workflow_capability_schema:migration") from error
    except Exception:
        connection.execute("rollback to workflow_capability_schema_v14")
        connection.execute("release workflow_capability_schema_v14")
        raise
    connection.execute("release workflow_capability_schema_v14")


def _drop_retired_receipt_event_index_once(connection: sqlite3.Connection, *, applied_at: str) -> None:
    """Drop the retired receipt-event index so the owned-object equality check passes.

    ``drop index if exists`` is idempotent and a no-op on databases that never owned the
    index, so it runs on every schema ensure. The distinct ``schema_migrations`` row records
    that this migration step exists; only the drop itself is what keeps validation strict on
    every reopen, because nothing in the current schema re-creates the index.
    """

    connection.execute(f"drop index if exists {WORKFLOW_CAPABILITY_RETIRED_RECEIPT_EVENT_INDEX}")
    connection.execute(
        "insert or ignore into schema_migrations (version, applied_at) values (?, ?)",
        (WORKFLOW_CAPABILITY_RECEIPT_EVENT_INDEX_MIGRATION_VERSION, applied_at),
    )


def _validate_schema_objects(connection: sqlite3.Connection) -> None:
    expected = {
        (object_type, name): _normalized_sql(statement)
        for (object_type, name), statement in zip(_OBJECT_NAMES, _SCHEMA_STATEMENTS, strict=True)
    }
    rows = connection.execute(
        """
        select type, name, sql from sqlite_master
        where name like 'guard_workflow_capabilit%'
           or name like 'idx_guard_workflow_%'
           or name like 'trg_guard_workflow_%'
        """
    ).fetchall()
    actual = {
        (str(row[0]), str(row[1])): _normalized_sql(str(row[2]))
        for row in rows
        if row[2] is not None and not str(row[1]).startswith("sqlite_autoindex")
    }
    if set(actual) != set(expected):
        raise RuntimeError("invalid_workflow_capability_schema:owned_objects")
    for identity, expected_sql in expected.items():
        if actual.get(identity) != expected_sql:
            raise RuntimeError(f"invalid_workflow_capability_schema:{identity[0]}:{identity[1]}")


def _normalized_sql(statement: str) -> str:
    normalized = re.sub(r"\s+", " ", statement.strip().lower())
    return normalized.replace(" if not exists", "")
