"""Regression coverage for the initial v18 command-shadow schema."""

# pyright: reportAny=false, reportPrivateUsage=false, reportUnusedCallResult=false

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from codex_plugin_scanner.guard import store_command_shadow_schema as shadow_schema
from codex_plugin_scanner.guard.store_command_shadow_schema_v18 import INITIAL_V18_SCHEMA_STATEMENTS

_OCCURRED_AT = datetime(2026, 7, 21, 12, 0, tzinfo=timezone.utc)


def test_migration_upgrades_initial_v18_evaluator_schema_and_preserves_rows(tmp_path: Path) -> None:
    with sqlite3.connect(tmp_path / "initial-v18.db") as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("create table schema_migrations (version integer primary key, applied_at text not null)")
        connection.execute(
            "create table command_activity (activity_id text primary key, occurred_at text not null) strict"
        )
        for statement in INITIAL_V18_SCHEMA_STATEMENTS:
            connection.execute(statement)
        occurred_at = _OCCURRED_AT.isoformat()
        connection.execute("insert into command_activity values (?, ?)", ("activity:initial-v18", occurred_at))
        connection.execute(
            """
            insert into command_activity_shadow_evaluations values (
              ?, ?, 'allow', 'allow', 'silent-verified', 'allow', 'silent-verified',
              'unchanged', 'proposal.initial.v18', '1.0.0', 1, 10000, 'guard.command-shadow.v1'
            )
            """,
            ("activity:initial-v18", occurred_at),
        )
        connection.execute(
            "insert into command_activity_shadow_cohorts values (?, 0, 'baseline')", ("activity:initial-v18",)
        )
        connection.execute(
            "insert into schema_migrations values (?, ?)",
            (shadow_schema.COMMAND_SHADOW_MIGRATION_VERSION, occurred_at),
        )

        assert shadow_schema._expected_schema(INITIAL_V18_SCHEMA_STATEMENTS) != shadow_schema._expected_schema(
            shadow_schema._SCHEMA_STATEMENTS
        )

        shadow_schema.ensure_command_shadow_schema(connection, applied_at=occurred_at)

        shadow_schema._validate_schema(connection)
        versions = connection.execute("select version from schema_migrations order by version").fetchall()
        evaluation = connection.execute(
            "select activity_id, evaluator_schema_version from command_activity_shadow_evaluations"
        ).fetchone()
        cohort = connection.execute(
            "select activity_id, ordinal, cohort from command_activity_shadow_cohorts"
        ).fetchone()
        temporary_tables = connection.execute(
            "select count(*) from sqlite_master where name in (?, ?)",
            (
                "command_activity_shadow_evaluations_initial_v18",
                "command_activity_shadow_cohorts_initial_v18",
            ),
        ).fetchone()

    assert [tuple(row) for row in versions] == [
        (shadow_schema.COMMAND_SHADOW_LEGACY_MIGRATION_VERSION,),
        (shadow_schema.COMMAND_SHADOW_PREVIOUS_MIGRATION_VERSION,),
        (shadow_schema.COMMAND_SHADOW_MIGRATION_VERSION,),
    ]
    assert tuple(evaluation) == ("activity:initial-v18", "1.0.0")
    assert tuple(cohort) == ("activity:initial-v18", 0, "baseline")
    assert tuple(temporary_tables) == (0,)
