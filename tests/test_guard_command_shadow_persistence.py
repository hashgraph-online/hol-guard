"""Atomic storage, replay, migration, and privacy tests for command shadow evidence."""

# pyright: reportAny=false, reportMissingImports=false, reportPrivateUsage=false
# pyright: reportUnknownMemberType=false, reportUnknownParameterType=false, reportUnusedCallResult=false

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import store_command_shadow_schema as shadow_schema
from codex_plugin_scanner.guard.store import GuardStore

_OCCURRED_AT = datetime(2026, 7, 19, 12, 0, tzinfo=timezone.utc)


def _legacy_shadow_database(
    path: Path,
    *,
    proposal_version: str = "proposal.multi.v1",
    statements: tuple[str, ...] = shadow_schema._LEGACY_SCHEMA_STATEMENTS,
    migration_version: int = shadow_schema.COMMAND_SHADOW_LEGACY_MIGRATION_VERSION,
) -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute("create table schema_migrations (version integer primary key, applied_at text not null)")
    connection.execute("create table command_activity (activity_id text primary key, occurred_at text not null) strict")
    for statement in statements:
        connection.execute(statement)
    occurred_at = _OCCURRED_AT.isoformat()
    connection.execute("insert into command_activity values (?, ?)", ("activity:legacy", occurred_at))
    connection.execute(
        """
        insert into command_activity_shadow_evaluations values (
          ?, ?, 'allow', 'allow', 'silent-verified', 'allow', 'silent-verified',
          'unchanged', ?, '1.0.0', 1, 10000, 'guard.command-shadow.v1'
        )
        """,
        ("activity:legacy", occurred_at, proposal_version),
    )
    connection.execute("insert into command_activity_shadow_cohorts values (?, 0, 'baseline')", ("activity:legacy",))
    connection.execute(
        "insert into schema_migrations values (?, ?)",
        (migration_version, occurred_at),
    )
    connection.commit()
    return connection


def _previous_shadow_database(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute("create table schema_migrations (version integer primary key, applied_at text not null)")
    connection.execute("create table command_activity (activity_id text primary key, occurred_at text not null) strict")
    for statement in shadow_schema._PREVIOUS_SCHEMA_STATEMENTS:
        connection.execute(statement)
    occurred_at = _OCCURRED_AT.isoformat()
    connection.execute("insert into command_activity values (?, ?)", ("activity:previous", occurred_at))
    connection.execute(
        """
        insert into command_activity_shadow_evaluations values (
          ?, ?, 'allow', 'allow', 'silent-verified', 'allow', 'silent-verified',
          'unchanged', 'proposal.previous.v1', '1.0.0', 1, 10000, 'guard.command-shadow.v1'
        )
        """,
        ("activity:previous", occurred_at),
    )
    connection.execute("insert into command_activity_shadow_cohorts values (?, 0, 'baseline')", ("activity:previous",))
    for version in (
        shadow_schema.COMMAND_SHADOW_LEGACY_MIGRATION_VERSION,
        shadow_schema.COMMAND_SHADOW_PREVIOUS_MIGRATION_VERSION,
    ):
        connection.execute("insert into schema_migrations values (?, ?)", (version, occurred_at))
    connection.commit()
    return connection


def test_migration_creates_validated_normalized_schema(tmp_path: Path) -> None:
    store = GuardStore(tmp_path / "guard-home", prime_policy_integrity=False)

    with sqlite3.connect(store.path) as connection:
        tables = {str(row[0]) for row in connection.execute("select name from sqlite_master").fetchall()}
        version = connection.execute(
            "select version from schema_migrations where version = ?",
            (shadow_schema.COMMAND_SHADOW_MIGRATION_VERSION,),
        ).fetchone()

    assert "command_activity_shadow_evaluations" in tables
    assert "command_activity_shadow_cohorts" in tables
    assert version == (shadow_schema.COMMAND_SHADOW_MIGRATION_VERSION,)


def test_migration_upgrades_exact_legacy_schema_and_preserves_rows(tmp_path: Path) -> None:
    with _legacy_shadow_database(tmp_path / "legacy.db") as connection:
        shadow_schema.ensure_command_shadow_schema(connection, applied_at=_OCCURRED_AT.isoformat())

        shadow_schema._validate_schema(connection)
        versions = connection.execute(
            "select version from schema_migrations where version in (?, ?, ?) order by version",
            (
                shadow_schema.COMMAND_SHADOW_LEGACY_MIGRATION_VERSION,
                shadow_schema.COMMAND_SHADOW_PREVIOUS_MIGRATION_VERSION,
                shadow_schema.COMMAND_SHADOW_MIGRATION_VERSION,
            ),
        ).fetchall()
        evaluation = connection.execute(
            "select activity_id, proposal_version from command_activity_shadow_evaluations"
        ).fetchone()
        cohort = connection.execute(
            "select activity_id, ordinal, cohort from command_activity_shadow_cohorts"
        ).fetchone()
        temporary_tables = connection.execute(
            "select count(*) from sqlite_master where name in (?, ?)",
            ("command_activity_shadow_evaluations_v15", "command_activity_shadow_cohorts_v15"),
        ).fetchone()

    assert [tuple(row) for row in versions] == [
        (shadow_schema.COMMAND_SHADOW_LEGACY_MIGRATION_VERSION,),
        (shadow_schema.COMMAND_SHADOW_PREVIOUS_MIGRATION_VERSION,),
        (shadow_schema.COMMAND_SHADOW_MIGRATION_VERSION,),
    ]
    assert tuple(evaluation) == ("activity:legacy", "proposal.multi.v1")
    assert tuple(cohort) == ("activity:legacy", 0, "baseline")
    assert tuple(temporary_tables) == (0,)


def test_migration_upgrades_v17_schema_and_preserves_historical_evaluator_version(tmp_path: Path) -> None:
    with _previous_shadow_database(tmp_path / "previous.db") as connection:
        shadow_schema.ensure_command_shadow_schema(connection, applied_at=_OCCURRED_AT.isoformat())

        shadow_schema._validate_schema(connection)
        versions = connection.execute("select version from schema_migrations order by version").fetchall()
        row = connection.execute("select * from command_activity_shadow_evaluations").fetchone()
        assert row is not None
        temporary_tables = connection.execute(
            "select count(*) from sqlite_master where name in (?, ?)",
            ("command_activity_shadow_evaluations_v17", "command_activity_shadow_cohorts_v17"),
        ).fetchone()

    assert [tuple(row) for row in versions] == [
        (shadow_schema.COMMAND_SHADOW_LEGACY_MIGRATION_VERSION,),
        (shadow_schema.COMMAND_SHADOW_PREVIOUS_MIGRATION_VERSION,),
        (shadow_schema.COMMAND_SHADOW_MIGRATION_VERSION,),
    ]
    assert row["activity_id"] == "activity:previous"
    assert row["evaluator_schema_version"] == "1.0.0"
    assert tuple(temporary_tables) == (0,)


def test_migration_rolls_back_exact_legacy_schema_when_a_row_is_invalid(tmp_path: Path) -> None:
    with _legacy_shadow_database(tmp_path / "legacy-invalid.db", proposal_version="INVALID!") as connection:
        expected_legacy = shadow_schema._expected_schema(shadow_schema._LEGACY_SCHEMA_STATEMENTS)
        current = shadow_schema._expected_schema(shadow_schema._SCHEMA_STATEMENTS)

        with pytest.raises(sqlite3.IntegrityError):
            shadow_schema.ensure_command_shadow_schema(connection, applied_at=_OCCURRED_AT.isoformat())

        actual = shadow_schema._read_schema(connection, frozenset(expected_legacy) | frozenset(current))
        versions = connection.execute("select version from schema_migrations order by version").fetchall()
        row = connection.execute(
            "select activity_id, proposal_version from command_activity_shadow_evaluations"
        ).fetchone()

    assert actual == expected_legacy
    assert [tuple(version) for version in versions] == [(shadow_schema.COMMAND_SHADOW_LEGACY_MIGRATION_VERSION,)]
    assert tuple(row) == ("activity:legacy", "INVALID!")


def test_migration_upgrades_previous_constrained_schema(tmp_path: Path) -> None:
    with _legacy_shadow_database(
        tmp_path / "previous.db",
        statements=shadow_schema._PREVIOUS_SCHEMA_STATEMENTS,
        migration_version=shadow_schema.COMMAND_SHADOW_PREVIOUS_MIGRATION_VERSION,
    ) as connection:
        shadow_schema.ensure_command_shadow_schema(connection, applied_at=_OCCURRED_AT.isoformat())

        shadow_schema._validate_schema(connection)
        evaluation = connection.execute(
            "select activity_id, evaluator_schema_version from command_activity_shadow_evaluations"
        ).fetchone()
        versions = connection.execute(
            "select version from schema_migrations where version in (?, ?) order by version",
            (
                shadow_schema.COMMAND_SHADOW_PREVIOUS_MIGRATION_VERSION,
                shadow_schema.COMMAND_SHADOW_MIGRATION_VERSION,
            ),
        ).fetchall()

    assert tuple(evaluation) == ("activity:legacy", "1.0.0")
    assert [tuple(row) for row in versions] == [
        (shadow_schema.COMMAND_SHADOW_PREVIOUS_MIGRATION_VERSION,),
        (shadow_schema.COMMAND_SHADOW_MIGRATION_VERSION,),
    ]


def test_migration_rejects_unknown_near_legacy_schema_without_changes(tmp_path: Path) -> None:
    with _legacy_shadow_database(tmp_path / "legacy-unknown.db") as connection:
        connection.execute("drop trigger trg_command_activity_shadow_require_activity")
        connection.execute(
            """create trigger trg_command_activity_shadow_require_activity
            before insert on command_activity_shadow_evaluations begin select 1; end"""
        )
        names = frozenset(shadow_schema._expected_schema(shadow_schema._LEGACY_SCHEMA_STATEMENTS)) | frozenset(
            shadow_schema._expected_schema(shadow_schema._SCHEMA_STATEMENTS)
        )
        before = shadow_schema._read_schema(connection, names)

        with pytest.raises(RuntimeError, match="incompatible command shadow schema objects"):
            shadow_schema.ensure_command_shadow_schema(connection, applied_at=_OCCURRED_AT.isoformat())

        after = shadow_schema._read_schema(connection, names)
        versions = connection.execute("select version from schema_migrations order by version").fetchall()

    assert after == before
    assert [tuple(version) for version in versions] == [(shadow_schema.COMMAND_SHADOW_LEGACY_MIGRATION_VERSION,)]


def _assert_extra_owned_object_is_rejected(connection: sqlite3.Connection, statement: str, name: str) -> None:
    connection.execute(statement)
    names = frozenset(shadow_schema._expected_schema(shadow_schema._LEGACY_SCHEMA_STATEMENTS)) | frozenset(
        shadow_schema._expected_schema(shadow_schema._SCHEMA_STATEMENTS)
    )
    before = shadow_schema._read_schema(connection, names)
    assert name in before

    with pytest.raises(RuntimeError, match="incompatible command shadow schema objects"):
        shadow_schema.ensure_command_shadow_schema(connection, applied_at=_OCCURRED_AT.isoformat())

    assert shadow_schema._read_schema(connection, names) == before
    versions = connection.execute("select version from schema_migrations order by version").fetchall()
    assert [tuple(version) for version in versions] == [(shadow_schema.COMMAND_SHADOW_LEGACY_MIGRATION_VERSION,)]


def test_migration_rejects_extra_trigger_on_owned_table_without_changes(tmp_path: Path) -> None:
    with _legacy_shadow_database(tmp_path / "legacy-extra-trigger.db") as connection:
        _assert_extra_owned_object_is_rejected(
            connection,
            """create trigger trg_command_activity_shadow_extra
            before insert on command_activity_shadow_evaluations begin select 1; end""",
            "trg_command_activity_shadow_extra",
        )


def test_migration_rejects_extra_index_on_owned_table_without_changes(tmp_path: Path) -> None:
    with _legacy_shadow_database(tmp_path / "legacy-extra-index.db") as connection:
        _assert_extra_owned_object_is_rejected(
            connection,
            "create index idx_command_activity_shadow_extra on command_activity_shadow_cohorts (ordinal)",
            "idx_command_activity_shadow_extra",
        )


def test_migration_rolls_back_objects_and_version_on_validation_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "migration.db"
    with sqlite3.connect(path) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("create table schema_migrations (version integer primary key, applied_at text not null)")
        connection.execute("create table command_activity (activity_id text primary key) strict")
        statements = shadow_schema._SCHEMA_STATEMENTS
        monkeypatch.setattr(shadow_schema, "_SCHEMA_STATEMENTS", (*statements, "create table"))
        with pytest.raises(RuntimeError, match="unrecognized command shadow schema statement"):
            shadow_schema.ensure_command_shadow_schema(connection, applied_at=_OCCURRED_AT.isoformat())
        tables = {str(row[0]) for row in connection.execute("select name from sqlite_master").fetchall()}
        version = connection.execute(
            "select version from schema_migrations where version = ?",
            (shadow_schema.COMMAND_SHADOW_MIGRATION_VERSION,),
        ).fetchone()

    assert "command_activity_shadow_evaluations" not in tables
    assert "command_activity_shadow_cohorts" not in tables
    assert version is None
