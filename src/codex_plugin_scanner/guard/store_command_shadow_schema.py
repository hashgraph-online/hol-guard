"""Crash-safe schema for privacy-safe command decision shadow evidence."""

# pyright: reportAny=false, reportUnusedCallResult=false

from __future__ import annotations

import re
import sqlite3
from typing import Final, cast

COMMAND_SHADOW_LEGACY_MIGRATION_VERSION: Final = 15
COMMAND_SHADOW_PREVIOUS_MIGRATION_VERSION: Final = 17
COMMAND_SHADOW_MIGRATION_VERSION: Final = 18

_ACTIONS: Final = "'allow', 'warn', 'review', 'require-reapproval', 'sandbox-required', 'block'"
_DISPOSITIONS: Final = (
    "'silent-verified', 'silent-contained', 'workflow-authorized', 'warn', 'review', "
    "'require-reapproval', 'sandbox-required', 'block'"
)
_COHORTS: Final = (
    "'baseline', 'cdx-060-verified-reads', 'cdx-061-contained-checks', "
    "'cdx-062-contained-writes', 'cdx-063-task-capabilities', "
    "'cdx-064-remote-mutation-floors', 'cdx-065-package-provenance-floors', "
    "'cdx-066-critical-block-floors'"
)
_OWNED_TABLES: Final = (
    "command_activity_shadow_evaluations",
    "command_activity_shadow_cohorts",
)
_OWNED_IDENTIFIER_PATTERN: Final = re.compile(
    r"(?<![a-z0-9_])(?:" + "|".join(re.escape(table) for table in _OWNED_TABLES) + r")(?![a-z0-9_])",
    re.IGNORECASE,
)

_SCHEMA_STATEMENTS: Final = (
    f"""create table if not exists command_activity_shadow_evaluations (
      activity_id text primary key references command_activity(activity_id) on delete cascade,
      occurred_at text not null,
      authoritative_action text not null check (authoritative_action in ({_ACTIONS})),
      current_action text not null check (current_action in ({_ACTIONS})),
      current_disposition text not null check (current_disposition in ({_DISPOSITIONS})),
      proposed_action text not null check (proposed_action in ({_ACTIONS})),
      proposed_disposition text not null check (proposed_disposition in ({_DISPOSITIONS})),
      comparison text not null check (comparison in ('lowered', 'unchanged', 'strengthened')),
      proposal_version text not null check (
        length(proposal_version) between 1 and 128
        and proposal_version glob '[a-z]*'
        and proposal_version not glob '*[^a-z0-9.-]*'
      ),
      evaluator_schema_version text not null check (evaluator_schema_version in ('1.0.0', '1.1.0')),
      control_generation integer not null check (control_generation = 1),
      sample_basis_points integer not null check (sample_basis_points between 1 and 10000),
      schema_version text not null check (schema_version = 'guard.command-shadow.v1'),
      check (
        (current_action = 'allow' and current_disposition in (
          'silent-verified', 'silent-contained', 'workflow-authorized'
        )) or (current_action != 'allow' and current_disposition = current_action)
      ),
      check (
        (proposed_action = 'allow' and proposed_disposition in (
          'silent-verified', 'silent-contained', 'workflow-authorized'
        )) or (proposed_action != 'allow' and proposed_disposition = proposed_action)
      )
    ) strict""",
    f"""create table if not exists command_activity_shadow_cohorts (
      activity_id text not null references command_activity_shadow_evaluations(activity_id) on delete cascade,
      ordinal integer not null check (ordinal >= 0),
      cohort text not null check (cohort in ({_COHORTS})),
      primary key (activity_id, ordinal),
      unique (activity_id, cohort)
    ) strict""",
    """create index if not exists idx_command_activity_shadow_comparison
    on command_activity_shadow_evaluations (comparison, occurred_at desc, activity_id desc)""",
    """create index if not exists idx_command_activity_shadow_cohort
    on command_activity_shadow_cohorts (cohort, activity_id)""",
    """create trigger if not exists trg_command_activity_shadow_evaluations_immutable
    before update on command_activity_shadow_evaluations
    begin select raise(abort, 'command_activity_shadow_evaluations_immutable'); end""",
    """create trigger if not exists trg_command_activity_shadow_cohorts_immutable
    before update on command_activity_shadow_cohorts
    begin select raise(abort, 'command_activity_shadow_cohorts_immutable'); end""",
    """create trigger if not exists trg_command_activity_shadow_require_activity
    before insert on command_activity_shadow_evaluations
    begin
      select case when not exists (
        select 1 from command_activity
        where activity_id = new.activity_id and occurred_at = new.occurred_at
      ) then raise(abort, 'command_activity_shadow_activity_missing') end;
    end""",
    """create trigger if not exists trg_command_activity_shadow_require_evaluation
    before insert on command_activity_shadow_cohorts
    begin
      select case when not exists (
        select 1 from command_activity_shadow_evaluations where activity_id = new.activity_id
      ) then raise(abort, 'command_activity_shadow_evaluation_missing') end;
      select case when new.ordinal != (
        select count(*) from command_activity_shadow_cohorts where activity_id = new.activity_id
      ) then raise(abort, 'command_activity_shadow_cohort_ordinal_invalid') end;
    end""",
    """create trigger if not exists trg_command_activity_shadow_require_comparison
    before insert on command_activity_shadow_evaluations
    begin
      select case when new.comparison != case
        when (
          case new.proposed_action
            when 'allow' then 0 when 'warn' then 1 when 'review' then 2
            when 'require-reapproval' then 3 when 'sandbox-required' then 4 else 5 end
        ) < (
          case new.current_action
            when 'allow' then 0 when 'warn' then 1 when 'review' then 2
            when 'require-reapproval' then 3 when 'sandbox-required' then 4 else 5 end
        ) then 'lowered'
        when new.proposed_action = new.current_action then 'unchanged'
        else 'strengthened'
      end then raise(abort, 'command_activity_shadow_comparison_invalid') end;
    end""",
    """create trigger if not exists trg_command_activity_shadow_delete_cohorts
    after delete on command_activity_shadow_evaluations
    begin
      delete from command_activity_shadow_cohorts where activity_id = old.activity_id;
    end""",
    """create trigger if not exists trg_command_activity_shadow_delete_evaluation
    after delete on command_activity
    begin
      delete from command_activity_shadow_evaluations where activity_id = old.activity_id;
    end""",
)

_LEGACY_SCHEMA_STATEMENTS: Final = (
    f"""create table command_activity_shadow_evaluations (
      activity_id text primary key references command_activity(activity_id) on delete cascade,
      occurred_at text not null,
      authoritative_action text not null check (authoritative_action in ({_ACTIONS})),
      current_action text not null check (current_action in ({_ACTIONS})),
      current_disposition text not null check (current_disposition in ({_DISPOSITIONS})),
      proposed_action text not null check (proposed_action in ({_ACTIONS})),
      proposed_disposition text not null check (proposed_disposition in ({_DISPOSITIONS})),
      comparison text not null check (comparison in ('lowered', 'unchanged', 'strengthened')),
      proposal_version text not null,
      evaluator_schema_version text not null,
      control_generation integer not null check (control_generation = 1),
      sample_basis_points integer not null check (sample_basis_points between 1 and 10000),
      schema_version text not null
    ) strict""",
    f"""create table command_activity_shadow_cohorts (
      activity_id text not null references command_activity_shadow_evaluations(activity_id) on delete cascade,
      ordinal integer not null check (ordinal >= 0),
      cohort text not null check (cohort in ({_COHORTS})),
      primary key (activity_id, ordinal),
      unique (activity_id, cohort)
    ) strict""",
    """create index idx_command_activity_shadow_comparison
    on command_activity_shadow_evaluations (comparison, occurred_at desc, activity_id desc)""",
    """create index idx_command_activity_shadow_cohort
    on command_activity_shadow_cohorts (cohort, activity_id)""",
    """create trigger trg_command_activity_shadow_evaluations_immutable
    before update on command_activity_shadow_evaluations
    begin select raise(abort, 'command_activity_shadow_evaluations_immutable'); end""",
    """create trigger trg_command_activity_shadow_cohorts_immutable
    before update on command_activity_shadow_cohorts
    begin select raise(abort, 'command_activity_shadow_cohorts_immutable'); end""",
    """create trigger trg_command_activity_shadow_require_activity
    before insert on command_activity_shadow_evaluations
    begin
      select case when not exists (
        select 1 from command_activity where activity_id = new.activity_id
      ) then raise(abort, 'command_activity_shadow_activity_missing') end;
    end""",
    """create trigger trg_command_activity_shadow_require_evaluation
    before insert on command_activity_shadow_cohorts
    begin
      select case when not exists (
        select 1 from command_activity_shadow_evaluations where activity_id = new.activity_id
      ) then raise(abort, 'command_activity_shadow_evaluation_missing') end;
    end""",
    """create trigger trg_command_activity_shadow_delete_cohorts
    after delete on command_activity_shadow_evaluations
    begin
      delete from command_activity_shadow_cohorts where activity_id = old.activity_id;
    end""",
    """create trigger trg_command_activity_shadow_delete_evaluation
    after delete on command_activity
    begin
      delete from command_activity_shadow_evaluations where activity_id = old.activity_id;
    end""",
)

_PREVIOUS_SCHEMA_STATEMENTS: Final = (
    _SCHEMA_STATEMENTS[0].replace(
        "evaluator_schema_version in ('1.0.0', '1.1.0')",
        "evaluator_schema_version = '1.0.0'",
    ),
    *_SCHEMA_STATEMENTS[1:],
)


def ensure_command_shadow_schema(connection: sqlite3.Connection, *, applied_at: str) -> None:
    """Apply the current schema atomically, upgrading either supported legacy shape."""

    connection.execute("savepoint command_shadow_schema_v18")
    try:
        current = _expected_schema(_SCHEMA_STATEMENTS)
        legacy = _expected_schema(_LEGACY_SCHEMA_STATEMENTS)
        previous = _expected_schema(_PREVIOUS_SCHEMA_STATEMENTS)
        actual = _read_schema(connection, frozenset(current) | frozenset(legacy) | frozenset(previous))
        _reject_external_foreign_keys(connection)
        _reject_external_sql_dependencies(connection, (current, legacy, previous))
        if actual == legacy:
            _upgrade_legacy_schema(connection, _LEGACY_SCHEMA_STATEMENTS)
        elif actual == previous:
            _upgrade_legacy_schema(connection, _PREVIOUS_SCHEMA_STATEMENTS)
        elif actual and actual != current:
            raise RuntimeError("incompatible command shadow schema objects")
        elif not actual:
            for statement in _SCHEMA_STATEMENTS:
                connection.execute(statement)
        _validate_schema(connection)
        for version in (
            COMMAND_SHADOW_LEGACY_MIGRATION_VERSION,
            COMMAND_SHADOW_PREVIOUS_MIGRATION_VERSION,
            COMMAND_SHADOW_MIGRATION_VERSION,
        ):
            connection.execute(
                "insert or ignore into schema_migrations (version, applied_at) values (?, ?)",
                (version, applied_at),
            )
        row = connection.execute(
            "select applied_at from schema_migrations where version = ?",
            (COMMAND_SHADOW_MIGRATION_VERSION,),
        ).fetchone()
        if row is None or not str(row[0]):
            raise RuntimeError("command_shadow_migration_not_recorded")
    except BaseException:
        connection.execute("rollback to command_shadow_schema_v18")
        connection.execute("release command_shadow_schema_v18")
        raise
    connection.execute("release command_shadow_schema_v18")


def _upgrade_legacy_schema(
    connection: sqlite3.Connection,
    source_statements: tuple[str, ...],
) -> None:
    for object_type, name in _schema_object_identities(source_statements):
        if object_type != "table":
            connection.execute(f"drop {object_type} {name}")
    connection.execute("alter table command_activity_shadow_cohorts rename to command_activity_shadow_cohorts_v15")
    connection.execute(
        "alter table command_activity_shadow_evaluations rename to command_activity_shadow_evaluations_v15"
    )
    for statement in _SCHEMA_STATEMENTS:
        connection.execute(statement)
    connection.execute(
        "insert into command_activity_shadow_evaluations select * from command_activity_shadow_evaluations_v15"
    )
    connection.execute(
        """insert into command_activity_shadow_cohorts
        select * from command_activity_shadow_cohorts_v15 order by activity_id, ordinal"""
    )
    connection.execute("drop table command_activity_shadow_cohorts_v15")
    connection.execute("drop table command_activity_shadow_evaluations_v15")


def _validate_schema(connection: sqlite3.Connection) -> None:
    expected = _expected_schema(_SCHEMA_STATEMENTS)
    actual = _read_schema(connection, frozenset(expected))
    if actual != expected:
        raise RuntimeError("incompatible command shadow schema objects")
    expected_columns = {
        "command_activity_shadow_evaluations": (
            "activity_id",
            "occurred_at",
            "authoritative_action",
            "current_action",
            "current_disposition",
            "proposed_action",
            "proposed_disposition",
            "comparison",
            "proposal_version",
            "evaluator_schema_version",
            "control_generation",
            "sample_basis_points",
            "schema_version",
        ),
        "command_activity_shadow_cohorts": ("activity_id", "ordinal", "cohort"),
    }
    expected_primary_keys = {
        "command_activity_shadow_evaluations": ("activity_id",),
        "command_activity_shadow_cohorts": ("activity_id", "ordinal"),
    }
    for table, names in expected_columns.items():
        columns = cast(list[sqlite3.Row], connection.execute(f"pragma table_info({table})").fetchall())
        if tuple(str(row["name"]) for row in columns) != names:
            raise RuntimeError("incompatible command shadow schema columns")
        primary_key_columns = sorted(
            (column for column in columns if int(column["pk"]) > 0),
            key=lambda column: int(column["pk"]),
        )
        primary_key = tuple(str(column["name"]) for column in primary_key_columns)
        if primary_key != expected_primary_keys[table]:
            raise RuntimeError("incompatible command shadow primary key")


def _expected_schema(statements: tuple[str, ...]) -> dict[str, str]:
    expected: dict[str, str] = {}
    for statement in statements:
        canonical = _canonical_sql(statement)
        match = re.match(r"create (table|index|trigger)(?: if not exists)? ([a-z0-9_]+)", canonical)
        if match is None:
            raise RuntimeError("unrecognized command shadow schema statement")
        expected[match.group(2)] = canonical.replace(" if not exists", "", 1)
    return expected


def _schema_object_identities(statements: tuple[str, ...]) -> tuple[tuple[str, str], ...]:
    identities: list[tuple[str, str]] = []
    for statement in statements:
        match = re.match(r"create (table|index|trigger)(?: if not exists)? ([a-z0-9_]+)", _canonical_sql(statement))
        if match is None:
            raise RuntimeError("unrecognized command shadow schema statement")
        identities.append((match.group(1), match.group(2)))
    return tuple(identities)


def _read_schema(connection: sqlite3.Connection, names: frozenset[str]) -> dict[str, str]:
    placeholders = ", ".join("?" for _ in names)
    owned_placeholders = ", ".join("?" for _ in _OWNED_TABLES)
    rows = cast(
        list[sqlite3.Row],
        connection.execute(
            f"""select name, sql from sqlite_master
            where name in ({placeholders})
               or (
                 type in ('index', 'trigger')
                 and tbl_name in ({owned_placeholders})
                 and sql is not null
               )""",
            (*sorted(names), *_OWNED_TABLES),
        ).fetchall(),
    )
    return {str(row["name"]): _canonical_sql(str(row["sql"])) for row in rows}


def _reject_external_foreign_keys(connection: sqlite3.Connection) -> None:
    rows = cast(
        list[sqlite3.Row],
        connection.execute(
            "select name from sqlite_master where type = 'table' and name not in (?, ?) order by name",
            _OWNED_TABLES,
        ).fetchall(),
    )
    for row in rows:
        table = str(row["name"])
        foreign_keys = connection.execute(
            'select "table" from pragma_foreign_key_list(?)',
            (table,),
        ).fetchall()
        if any(str(foreign_key[0]).casefold() in _OWNED_TABLES for foreign_key in foreign_keys):
            raise RuntimeError("incompatible command shadow external foreign key")


def _reject_external_sql_dependencies(
    connection: sqlite3.Connection,
    allowed_schemas: tuple[dict[str, str], ...],
) -> None:
    rows = cast(
        list[sqlite3.Row],
        connection.execute(
            """select type, name, tbl_name, sql from sqlite_master
            where sql is not null
              and (
                type = 'view'
                or (type = 'trigger' and lower(tbl_name) not in (?, ?))
                or (
                  type = 'table'
                  and (
                    instr(lower(sql), 'create virtual table') > 0
                    or name in (
                      select name from pragma_table_list
                      where schema = 'main' and type = 'virtual'
                    )
                  )
                )
              )
            order by type, name""",
            _OWNED_TABLES,
        ).fetchall(),
    )
    for row in rows:
        name = str(row["name"])
        sql = _canonical_sql(str(row["sql"]))
        if _OWNED_IDENTIFIER_PATTERN.search(sql) is None:
            continue
        if any(schema.get(name) == sql for schema in allowed_schemas):
            continue
        raise RuntimeError("incompatible command shadow external schema dependency")


def _canonical_sql(value: str) -> str:
    return " ".join(value.strip().lower().split())


__all__ = (
    "COMMAND_SHADOW_LEGACY_MIGRATION_VERSION",
    "COMMAND_SHADOW_MIGRATION_VERSION",
    "ensure_command_shadow_schema",
)
