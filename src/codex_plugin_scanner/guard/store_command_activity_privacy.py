"""Atomic deletion and bounded diagnostics for command activity evidence."""

# pyright: reportAny=false, reportPrivateUsage=false, reportUnusedCallResult=false

from __future__ import annotations

import sqlite3
from contextlib import AbstractContextManager
from typing import Final, Protocol, cast

from .runtime.command_activity_api_contract import COMMAND_ACTIVITY_API_SCHEMA_VERSION
from .runtime.command_activity_contract import (
    COMMAND_ACTIVITY_HARNESSES,
    COMMAND_ACTIVITY_SCHEMA_VERSION,
    CommandProofLevel,
)
from .runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY
from .store_command_activity_health_schema import COMMAND_ACTIVITY_HEALTH_SCHEMA_VERSION
from .store_command_activity_maintenance_schema import COMMAND_ACTIVITY_MAINTENANCE_SCHEMA_VERSION

COMMAND_ACTIVITY_DIAGNOSTICS_SCHEMA_VERSION: Final = "guard.command-activity-diagnostics.v1"
_MAX_COUNTER: Final = 9_223_372_036_854_775_807
_ALLOWED_EXTENSION_IDS: Final = frozenset(
    extension.extension_id for extension in BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions
)
_ALLOWED_RULE_IDS: Final = frozenset(
    rule.rule_id for extension in BUILT_IN_COMMAND_EXTENSION_REGISTRY.extensions for rule in extension.rules
)
_ALLOWED_ERROR_CLASSES: Final = frozenset(
    {
        "cursor_observer_verify_failed",
        "maintenance_failed",
        "post_record_failed",
        "pre_record_failed",
    }
)
_COUNT_TABLES: Final = (
    ("activities", "command_activity"),
    ("matches", "command_activity_matches"),
    ("effects", "command_activity_match_effects"),
    ("correlations", "command_activity_correlations"),
    ("rollup_days", "command_activity_daily_totals"),
    ("rollup_cells", "command_activity_daily_rollups"),
    ("rollup_memberships", "command_activity_rollup_membership"),
    ("rollup_pending", "command_activity_rollup_pending"),
    ("feedback", "command_activity_feedback"),
    ("invalidations", "command_activity_invalidations"),
)
_DELETE_TABLES: Final = (
    "command_activity_feedback",
    "command_activity",
    "command_activity_match_effects",
    "command_activity_matches",
    "command_activity_correlations",
    "command_activity_rollup_membership",
    "command_activity_rollup_pending",
    "command_activity_daily_rollups",
    "command_activity_daily_totals",
    "command_activity_invalidations",
)


class _ConnectionOwner(Protocol):
    def _connect(self) -> AbstractContextManager[sqlite3.Connection]: ...


class StoreCommandActivityPrivacyMixin:
    def clear_command_activity_evidence(self: _ConnectionOwner) -> dict[str, object]:
        """Delete command evidence and derived state in one immediate transaction."""

        with self._connect() as connection:
            connection.execute("begin immediate")
            deleted = _table_counts(connection)
            for table in _DELETE_TABLES:
                connection.execute(f"delete from {table}")
            connection.execute("delete from sqlite_sequence where name = 'command_activity_invalidations'")
            connection.execute(
                """
                update command_activity_health
                set dropped_event_count = 0,
                    persistence_error_count = 0,
                    last_error_code = null,
                    last_error_at = null
                where singleton = 1
                """
            )
            connection.execute(
                """
                update command_activity_maintenance
                set last_completed_day = null,
                    last_run_at = null,
                    detail_compaction_started_at = null,
                    rollup_backfill_cursor_occurred_at = null,
                    rollup_backfill_cursor_activity_id = null,
                    rollup_backfill_complete = 0,
                    last_backfilled_rows = 0,
                    last_detail_rows_deleted = 0,
                    last_correlation_rows_deleted = 0,
                    last_aggregate_rows_deleted = 0
                where singleton = 1
                """
            )
        return {
            "schema_version": COMMAND_ACTIVITY_DIAGNOSTICS_SCHEMA_VERSION,
            "deleted": deleted,
        }

    def command_activity_diagnostics(self: _ConnectionOwner) -> dict[str, object]:
        """Return an allowlisted snapshot without command or opaque identity data."""

        with self._connect() as connection:
            connection.execute("begin")
            counts = _table_counts(connection)
            health = cast(
                sqlite3.Row | None,
                connection.execute(
                    """
                    select dropped_event_count, persistence_error_count, last_error_code
                    from command_activity_health where singleton = 1
                    """
                ).fetchone(),
            )
            proof_counts = {
                level.value: _count_matching(connection, "command_activity", "proof_level", level.value)
                for level in CommandProofLevel
            }
            stable_ids = {
                "harnesses": _stable_distinct(
                    connection,
                    "command_activity",
                    "harness",
                    allowed=COMMAND_ACTIVITY_HARNESSES,
                ),
                "extensions": _stable_distinct(
                    connection,
                    "command_activity_matches",
                    "extension_id",
                    allowed=_ALLOWED_EXTENSION_IDS,
                ),
                "rules": _stable_distinct(
                    connection,
                    "command_activity_matches",
                    "rule_id",
                    allowed=_ALLOWED_RULE_IDS,
                ),
            }
        dropped_events = _bounded_counter(health["dropped_event_count"] if health is not None else None)
        persistence_errors = _bounded_counter(health["persistence_error_count"] if health is not None else None)
        counts.update({"dropped_events": dropped_events, "persistence_errors": persistence_errors})
        error_code = health["last_error_code"] if health is not None else None
        error_classes: list[dict[str, object]] = []
        if error_code in _ALLOWED_ERROR_CLASSES and persistence_errors > 0:
            error_classes.append(
                {
                    "error_class": cast(str, error_code),
                    "count": persistence_errors,
                }
            )
        return {
            "schema_version": COMMAND_ACTIVITY_DIAGNOSTICS_SCHEMA_VERSION,
            "schemas": {
                "activity": COMMAND_ACTIVITY_SCHEMA_VERSION,
                "api": COMMAND_ACTIVITY_API_SCHEMA_VERSION,
                "health": COMMAND_ACTIVITY_HEALTH_SCHEMA_VERSION,
                "maintenance": COMMAND_ACTIVITY_MAINTENANCE_SCHEMA_VERSION,
            },
            "counts": counts,
            "proof_coverage": [
                {"proof_level": level.value, "count": proof_counts.get(level.value, 0)} for level in CommandProofLevel
            ],
            "stable_ids": stable_ids,
            "error_classes": error_classes,
        }


def _table_counts(connection: sqlite3.Connection) -> dict[str, int]:
    return {
        label: int(cast(sqlite3.Row, connection.execute(f"select count(*) from {table}").fetchone())[0])
        for label, table in _COUNT_TABLES
    }


def _stable_distinct(
    connection: sqlite3.Connection,
    table: str,
    column: str,
    *,
    allowed: frozenset[str],
) -> list[str]:
    if not allowed:
        return []
    ordered_allowed = tuple(sorted(allowed))
    placeholders = ", ".join("?" for _ in ordered_allowed)
    rows = cast(
        list[sqlite3.Row],
        connection.execute(
            f"select distinct {column} from {table} where {column} in ({placeholders}) order by {column} limit ?",
            (*ordered_allowed, len(ordered_allowed)),
        ).fetchall(),
    )
    return [str(row[0]) for row in rows]


def _count_matching(connection: sqlite3.Connection, table: str, column: str, value: str) -> int:
    row = cast(
        sqlite3.Row | None,
        connection.execute(f"select count(*) from {table} where {column} = ?", (value,)).fetchone(),
    )
    return _bounded_counter(row[0] if row is not None else None)


def _bounded_counter(value: object) -> int:
    return value if type(value) is int and 0 <= value <= _MAX_COUNTER else 0


__all__ = (
    "COMMAND_ACTIVITY_DIAGNOSTICS_SCHEMA_VERSION",
    "StoreCommandActivityPrivacyMixin",
)
