"""Crash-safe schema for privacy-safe command decision shadow evidence."""

# pyright: reportAny=false, reportUnusedCallResult=false

from __future__ import annotations

import re
import sqlite3
from typing import Final, cast

COMMAND_SHADOW_MIGRATION_VERSION: Final = 15

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
      evaluator_schema_version text not null check (evaluator_schema_version = '1.0.0'),
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


def ensure_command_shadow_schema(connection: sqlite3.Connection, *, applied_at: str) -> None:
    """Apply migration 15 atomically and validate every owned object."""

    connection.execute("savepoint command_shadow_schema_v15")
    try:
        for statement in _SCHEMA_STATEMENTS:
            connection.execute(statement)
        _validate_schema(connection)
        connection.execute(
            "insert or ignore into schema_migrations (version, applied_at) values (?, ?)",
            (COMMAND_SHADOW_MIGRATION_VERSION, applied_at),
        )
        row = connection.execute(
            "select applied_at from schema_migrations where version = ?",
            (COMMAND_SHADOW_MIGRATION_VERSION,),
        ).fetchone()
        if row is None or not str(row[0]):
            raise RuntimeError("command_shadow_migration_not_recorded")
    except BaseException:
        connection.execute("rollback to command_shadow_schema_v15")
        connection.execute("release command_shadow_schema_v15")
        raise
    connection.execute("release command_shadow_schema_v15")


def _validate_schema(connection: sqlite3.Connection) -> None:
    expected: dict[str, str] = {}
    for statement in _SCHEMA_STATEMENTS:
        canonical = _canonical_sql(statement)
        match = re.match(r"create (?:table|index|trigger) if not exists ([a-z0-9_]+)", canonical)
        if match is None:
            raise RuntimeError("unrecognized command shadow schema statement")
        expected[match.group(1)] = canonical.replace(" if not exists", "", 1)
    placeholders = ", ".join("?" for _ in expected)
    rows = cast(
        list[sqlite3.Row],
        connection.execute(
            f"select name, sql from sqlite_master where name in ({placeholders})",
            tuple(expected),
        ).fetchall(),
    )
    actual = {str(row["name"]): _canonical_sql(str(row["sql"])) for row in rows}
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


def _canonical_sql(value: str) -> str:
    return " ".join(value.strip().lower().split())


__all__ = (
    "COMMAND_SHADOW_MIGRATION_VERSION",
    "ensure_command_shadow_schema",
)
