"""Shared helpers for the command-activity vector recorders."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable
from pathlib import Path

from codex_plugin_scanner.guard.runtime.command_shadow_evaluation import CommandShadowObservation


def shadow_wire(shadow: CommandShadowObservation | None) -> dict[str, object] | None:
    if shadow is None:
        return None
    return {
        "activity_id": shadow.activity_id,
        "occurred_at": shadow.occurred_at.isoformat(),
        "authoritative_action": shadow.authoritative_action,
        "current_action": shadow.current_action,
        "current_disposition": shadow.current_disposition.value,
        "proposed_action": shadow.proposed_action,
        "proposed_disposition": shadow.proposed_disposition.value,
        "comparison": shadow.comparison.value,
        "proposal_version": shadow.proposal_version,
        "evaluator_schema_version": shadow.evaluator_schema_version,
        "control_generation": shadow.control_generation,
        "sample_basis_points": shadow.sample_basis_points,
        "schema_version": shadow.schema_version,
        "cohorts": [cohort.value for cohort in shadow.cohorts],
    }


def tracked_tables(path: Path) -> dict[str, str]:
    """Each tracked table with a deterministic ORDER BY (primary key, else rowid)."""

    connection = sqlite3.connect(path)
    try:
        names = [
            row[0]
            for row in connection.execute(
                "select name from sqlite_master where type = 'table' and name like 'command_activity%' order by name"
            )
        ]
        order: dict[str, str] = {}
        for name in names:
            keys = sorted(
                (row for row in connection.execute(f"pragma table_info({name})") if row[5] > 0),
                key=lambda row: row[5],
            )
            order[name] = ", ".join(row[1] for row in keys) if keys else "rowid"
        return order
    finally:
        connection.close()


def dump(path: Path, order: dict[str, str]) -> dict[str, list[dict[str, object]]]:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    try:
        return {
            table: [dict(row) for row in connection.execute(f"select * from {table} order by {key}")]
            for table, key in order.items()
        }
    finally:
        connection.close()


def schema_sql(path: Path) -> list[str]:
    connection = sqlite3.connect(path)
    try:
        return [
            row[0]
            for row in connection.execute(
                "select sql from sqlite_master where sql is not null and tbl_name like 'command_activity%' "
                "order by case type when 'table' then 0 when 'index' then 1 else 2 end, rowid"
            )
        ]
    finally:
        connection.close()


def schema_sql_for_tables(path: Path, tables: Iterable[str]) -> list[str]:
    """Schema DDL for exactly the named tables and their indexes, in creation order."""

    names = tuple(tables)
    connection = sqlite3.connect(path)
    try:
        return [
            row[0]
            for row in connection.execute(
                f"select sql from sqlite_master where sql is not null and tbl_name in ({','.join('?' * len(names))}) "
                "order by case type when 'table' then 0 when 'index' then 1 else 2 end, rowid",
                names,
            )
        ]
    finally:
        connection.close()
