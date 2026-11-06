"""Foreign-key preflight tests for command shadow schema upgrades."""

# pyright: reportAny=false, reportMissingImports=false, reportPrivateUsage=false
# pyright: reportUnknownMemberType=false, reportUnusedCallResult=false

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

from codex_plugin_scanner.guard import store_command_shadow_schema as shadow_schema

_OCCURRED_AT = datetime(2026, 7, 19, 12, 0, tzinfo=timezone.utc).isoformat()


def _legacy_database(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute("create table schema_migrations (version integer primary key, applied_at text not null)")
    connection.execute("create table command_activity (activity_id text primary key, occurred_at text not null) strict")
    for statement in shadow_schema._LEGACY_SCHEMA_STATEMENTS:
        connection.execute(statement)
    connection.execute("insert into command_activity values ('activity:legacy', ?)", (_OCCURRED_AT,))
    connection.execute(
        """insert into command_activity_shadow_evaluations values (
          'activity:legacy', ?, 'allow', 'allow', 'silent-verified', 'allow',
          'silent-verified', 'unchanged', 'proposal.multi.v1', '1.0.0', 1,
          10000, 'guard.command-shadow.v1'
        )""",
        (_OCCURRED_AT,),
    )
    connection.execute("insert into command_activity_shadow_cohorts values ('activity:legacy', 0, 'baseline')")
    connection.execute(
        "insert into schema_migrations values (?, ?)",
        (shadow_schema.COMMAND_SHADOW_LEGACY_MIGRATION_VERSION, _OCCURRED_AT),
    )
    connection.commit()
    return connection


def _snapshot(connection: sqlite3.Connection) -> tuple[object, ...]:
    schema = connection.execute(
        """select type, name, tbl_name, sql from sqlite_master
        where name not like 'sqlite_autoindex_%' order by type, name"""
    ).fetchall()
    data = (
        connection.execute("select * from command_activity order by activity_id").fetchall(),
        connection.execute("select * from command_activity_shadow_evaluations order by activity_id").fetchall(),
        connection.execute("select * from command_activity_shadow_cohorts order by activity_id, ordinal").fetchall(),
        connection.execute("select * from external_shadow_links order by link_id").fetchall(),
    )
    versions = connection.execute("select * from schema_migrations order by version").fetchall()
    return (
        tuple(tuple(row) for row in schema),
        tuple(tuple(tuple(row) for row in table) for table in data),
        tuple(tuple(row) for row in versions),
    )


def _assert_external_foreign_key_is_rejected(path: Path, *, foreign_keys: bool) -> None:
    with _legacy_database(path) as connection:
        connection.execute(f"pragma foreign_keys={int(foreign_keys)}")
        assert bool(connection.execute("pragma foreign_keys").fetchone()[0]) is foreign_keys
        connection.execute(
            """create table external_shadow_links (
              link_id text primary key,
              shadow_id text not null references COMMAND_ACTIVITY_SHADOW_EVALUATIONS(activity_id) on delete cascade
            ) strict"""
        )
        connection.execute("insert into external_shadow_links values ('link:legacy', 'activity:legacy')")
        connection.commit()
        before = _snapshot(connection)

        with pytest.raises(RuntimeError, match="incompatible command shadow external foreign key"):
            shadow_schema.ensure_command_shadow_schema(connection, applied_at=_OCCURRED_AT)

        assert _snapshot(connection) == before
        assert bool(connection.execute("pragma foreign_keys").fetchone()[0]) is foreign_keys


def test_migration_rejects_external_foreign_key_without_mutation_when_foreign_keys_are_off(tmp_path: Path) -> None:
    _assert_external_foreign_key_is_rejected(tmp_path / "external-fk-off.db", foreign_keys=False)


def test_migration_rejects_external_foreign_key_without_mutation_when_foreign_keys_are_on(tmp_path: Path) -> None:
    _assert_external_foreign_key_is_rejected(tmp_path / "external-fk-on.db", foreign_keys=True)


def _assert_external_sql_dependency_is_rejected(path: Path, statement: str) -> None:
    with _legacy_database(path) as connection:
        connection.execute("create table external_shadow_links (link_id text primary key, shadow_id text) strict")
        connection.execute("insert into external_shadow_links values ('link:legacy', 'activity:legacy')")
        connection.execute(statement)
        connection.commit()
        before = _snapshot(connection)

        with pytest.raises(RuntimeError, match="incompatible command shadow external schema dependency"):
            shadow_schema.ensure_command_shadow_schema(connection, applied_at=_OCCURRED_AT)

        assert _snapshot(connection) == before


def test_migration_rejects_external_view_dependency_without_mutation(tmp_path: Path) -> None:
    _assert_external_sql_dependency_is_rejected(
        tmp_path / "external-view.db",
        """create view external_shadow_view as
        select activity_id from COMMAND_ACTIVITY_SHADOW_EVALUATIONS""",
    )


def test_migration_rejects_external_trigger_dependency_without_mutation(tmp_path: Path) -> None:
    _assert_external_sql_dependency_is_rejected(
        tmp_path / "external-trigger.db",
        """create trigger external_shadow_trigger after insert on external_shadow_links
        begin select count(*) from command_activity_shadow_cohorts; end""",
    )


def test_migration_rejects_sparse_external_content_fts_without_mutation(tmp_path: Path) -> None:
    with _legacy_database(tmp_path / "external-fts.db") as connection:
        connection.execute("create table external_shadow_links (link_id text primary key, shadow_id text) strict")
        connection.execute("insert into external_shadow_links values ('link:legacy', 'activity:legacy')")
        connection.execute("insert into command_activity values ('activity:sparse', ?)", (_OCCURRED_AT,))
        connection.execute(
            """insert into command_activity_shadow_evaluations (
              rowid, activity_id, occurred_at, authoritative_action, current_action,
              current_disposition, proposed_action, proposed_disposition, comparison,
              proposal_version, evaluator_schema_version, control_generation,
              sample_basis_points, schema_version
            ) values (
              101, 'activity:sparse', ?, 'allow', 'allow', 'silent-verified',
              'allow', 'silent-verified', 'unchanged', 'proposal.sparse.v1',
              '1.0.0', 1, 10000, 'guard.command-shadow.v1'
            )""",
            (_OCCURRED_AT,),
        )
        try:
            connection.execute(
                """create virtual table external_shadow_fts using fts5(
                  proposal_version,
                  content='COMMAND_ACTIVITY_SHADOW_EVALUATIONS',
                  content_rowid='rowid'
                )"""
            )
        except sqlite3.OperationalError as error:
            if "no such module: fts5" in str(error).casefold():
                pytest.skip("SQLite FTS5 is unavailable")
            raise
        connection.execute("insert into external_shadow_fts(external_shadow_fts) values ('rebuild')")
        connection.commit()
        before = _snapshot(connection)
        query_before = connection.execute(
            """select rowid, proposal_version from external_shadow_fts
            where external_shadow_fts match 'proposal' order by rowid"""
        ).fetchall()
        assert [tuple(row) for row in query_before] == [
            (1, "proposal.multi.v1"),
            (101, "proposal.sparse.v1"),
        ]

        with pytest.raises(RuntimeError, match="incompatible command shadow external schema dependency"):
            shadow_schema.ensure_command_shadow_schema(connection, applied_at=_OCCURRED_AT)

        assert _snapshot(connection) == before
        query_after = connection.execute(
            """select rowid, proposal_version from external_shadow_fts
            where external_shadow_fts match 'proposal' order by rowid"""
        ).fetchall()
        assert [tuple(row) for row in query_after] == [tuple(row) for row in query_before]
