"""Schema migration for privacy-safe command activity evidence."""

# pyright: reportUnusedCallResult=false

from __future__ import annotations

import re
import sqlite3
from typing import cast

COMMAND_ACTIVITY_SCHEMA_MIGRATION_VERSION = 10


def command_activity_schema_statements() -> tuple[str, ...]:
    return (
        """
        create table if not exists command_activity (
          activity_id text primary key,
          occurred_at text not null,
          harness text not null,
          hook_phase text not null,
          execution_status text not null,
          proof_level text not null,
          policy_action text,
          decision_reason_code text,
          controlling_rule_id text,
          parse_confidence text,
          uncertainty_class text,
          match_count integer not null check (match_count >= 0),
          prompted integer not null check (prompted in (0, 1)),
          approval_reuse_status text not null,
          receipt_link_status text not null,
          receipt_id text,
          evaluation_latency_bucket text not null,
          persistence_latency_bucket text not null,
          schema_version text not null
        )
        """,
        """
        create table if not exists command_activity_matches (
          activity_id text not null references command_activity(activity_id) on delete cascade,
          ordinal integer not null check (ordinal >= 0),
          extension_id text not null,
          extension_version text not null,
          rule_id text not null,
          rule_version text not null,
          match_class text not null,
          severity text not null,
          default_floor text not null,
          safe_variant_id text,
          schema_version text not null,
          primary key (activity_id, ordinal),
          unique (activity_id, rule_id)
        )
        """,
        """
        create table if not exists command_activity_match_effects (
          activity_id text not null,
          ordinal integer not null,
          effect_class text not null,
          primary key (activity_id, ordinal, effect_class),
          foreign key (activity_id, ordinal)
            references command_activity_matches(activity_id, ordinal) on delete cascade
        )
        """,
        """
        create table if not exists command_activity_correlations (
          activity_id text not null references command_activity(activity_id) on delete cascade,
          kind text not null,
          harness text not null,
          key_id text not null,
          digest text not null,
          primary key (activity_id, kind)
        )
        """,
        """
        create table if not exists command_activity_daily_totals (
          day text primary key,
          total integer not null default 0 check (total >= 0)
        )
        """,
        """
        create table if not exists command_activity_daily_rollups (
          day text not null,
          dimension text not null,
          dimension_value text not null,
          count integer not null default 0 check (count >= 0),
          primary key (day, dimension, dimension_value)
        )
        """,
        """
        create index if not exists idx_command_activity_occurred_at
        on command_activity (occurred_at desc, activity_id desc)
        """,
        """
        create index if not exists idx_command_activity_harness_occurred_at
        on command_activity (harness, occurred_at desc, activity_id desc)
        """,
        """
        create index if not exists idx_command_activity_match_rule
        on command_activity_matches (rule_id, activity_id)
        """,
        """
        create index if not exists idx_command_activity_match_extension
        on command_activity_matches (extension_id, activity_id)
        """,
        """
        create index if not exists idx_command_activity_correlation_lookup
        on command_activity_correlations (kind, harness, key_id, digest)
        """,
        """
        create unique index if not exists idx_command_activity_request_correlation_unique
        on command_activity_correlations (harness, key_id, digest)
        where kind = 'request'
        """,
        """
        create trigger if not exists trg_command_activity_matches_parent
        before insert on command_activity_matches
        when not exists (
          select 1 from command_activity where activity_id = new.activity_id
        )
        begin
          select raise(abort, 'command activity match requires parent activity');
        end
        """,
        """
        create trigger if not exists trg_command_activity_effects_parent
        before insert on command_activity_match_effects
        when not exists (
          select 1 from command_activity_matches
          where activity_id = new.activity_id and ordinal = new.ordinal
        )
        begin
          select raise(abort, 'command activity effect requires parent match');
        end
        """,
        """
        create trigger if not exists trg_command_activity_correlations_parent
        before insert on command_activity_correlations
        when not exists (
          select 1 from command_activity where activity_id = new.activity_id
        )
        begin
          select raise(abort, 'command activity correlation requires parent activity');
        end
        """,
        """
        create trigger if not exists trg_command_activity_delete_children
        after delete on command_activity
        begin
          delete from command_activity_correlations where activity_id = old.activity_id;
          delete from command_activity_matches where activity_id = old.activity_id;
        end
        """,
        """
        create trigger if not exists trg_command_activity_match_delete_effects
        after delete on command_activity_matches
        begin
          delete from command_activity_match_effects
          where activity_id = old.activity_id and ordinal = old.ordinal;
        end
        """,
        """
        create trigger if not exists trg_command_activity_id_immutable
        before update of activity_id on command_activity
        when new.activity_id != old.activity_id
        begin
          select raise(abort, 'command activity identity is immutable');
        end
        """,
        """
        create trigger if not exists trg_command_activity_match_parent_immutable
        before update of activity_id, ordinal on command_activity_matches
        when new.activity_id != old.activity_id or new.ordinal != old.ordinal
        begin
          select raise(abort, 'command activity match parent is immutable');
        end
        """,
        """
        create trigger if not exists trg_command_activity_effect_parent_immutable
        before update of activity_id, ordinal on command_activity_match_effects
        when new.activity_id != old.activity_id or new.ordinal != old.ordinal
        begin
          select raise(abort, 'command activity effect parent is immutable');
        end
        """,
        """
        create trigger if not exists trg_command_activity_correlation_parent_immutable
        before update of activity_id on command_activity_correlations
        when new.activity_id != old.activity_id
        begin
          select raise(abort, 'command activity correlation parent is immutable');
        end
        """,
    )


def ensure_command_activity_schema(connection: sqlite3.Connection, *, applied_at: str) -> None:
    """Apply and version the complete v1 schema as one crash-safe migration."""

    connection.execute("savepoint command_activity_schema_v1")
    try:
        for statement in command_activity_schema_statements():
            connection.execute(statement)
        _validate_command_activity_schema(connection, command_activity_schema_statements())
        connection.execute(
            "insert or ignore into schema_migrations (version, applied_at) values (?, ?)",
            (COMMAND_ACTIVITY_SCHEMA_MIGRATION_VERSION, applied_at),
        )
    except BaseException:
        connection.execute("rollback to command_activity_schema_v1")
        connection.execute("release command_activity_schema_v1")
        raise
    connection.execute("release command_activity_schema_v1")


def _validate_command_activity_schema(
    connection: sqlite3.Connection,
    statements: tuple[str, ...],
) -> None:
    expected_columns = {
        "command_activity": {
            "activity_id",
            "occurred_at",
            "harness",
            "hook_phase",
            "execution_status",
            "proof_level",
            "policy_action",
            "decision_reason_code",
            "controlling_rule_id",
            "parse_confidence",
            "uncertainty_class",
            "match_count",
            "prompted",
            "approval_reuse_status",
            "receipt_link_status",
            "receipt_id",
            "evaluation_latency_bucket",
            "persistence_latency_bucket",
            "schema_version",
        },
        "command_activity_matches": {
            "activity_id",
            "ordinal",
            "extension_id",
            "extension_version",
            "rule_id",
            "rule_version",
            "match_class",
            "severity",
            "default_floor",
            "safe_variant_id",
            "schema_version",
        },
        "command_activity_match_effects": {"activity_id", "ordinal", "effect_class"},
        "command_activity_correlations": {"activity_id", "kind", "harness", "key_id", "digest"},
        "command_activity_daily_totals": {"day", "total"},
        "command_activity_daily_rollups": {"day", "dimension", "dimension_value", "count"},
    }
    expected_primary_keys = {
        "command_activity": ("activity_id",),
        "command_activity_matches": ("activity_id", "ordinal"),
        "command_activity_match_effects": ("activity_id", "ordinal", "effect_class"),
        "command_activity_correlations": ("activity_id", "kind"),
        "command_activity_daily_totals": ("day",),
        "command_activity_daily_rollups": ("day", "dimension", "dimension_value"),
    }
    for table, expected in expected_columns.items():
        rows = cast(
            list[tuple[int, str, str, int, object | None, int]],
            connection.execute(f"pragma table_info({table})").fetchall(),
        )
        actual = {str(row[1]) for row in rows}
        if actual != expected:
            raise RuntimeError(f"incompatible {table} schema")
        primary_key = tuple(str(row[1]) for row in sorted(rows, key=lambda item: int(item[5])) if int(row[5]) > 0)
        if primary_key != expected_primary_keys[table]:
            raise RuntimeError(f"incompatible {table} primary key")
    expected_indexes = {
        "idx_command_activity_occurred_at": ("command_activity", ("occurred_at", "activity_id"), 0, 0),
        "idx_command_activity_harness_occurred_at": (
            "command_activity",
            ("harness", "occurred_at", "activity_id"),
            0,
            0,
        ),
        "idx_command_activity_match_rule": (
            "command_activity_matches",
            ("rule_id", "activity_id"),
            0,
            0,
        ),
        "idx_command_activity_match_extension": (
            "command_activity_matches",
            ("extension_id", "activity_id"),
            0,
            0,
        ),
        "idx_command_activity_correlation_lookup": (
            "command_activity_correlations",
            ("kind", "harness", "key_id", "digest"),
            0,
            0,
        ),
        "idx_command_activity_request_correlation_unique": (
            "command_activity_correlations",
            ("harness", "key_id", "digest"),
            1,
            1,
        ),
    }
    actual_indexes: dict[str, tuple[str, tuple[str, ...], int, int]] = {}
    for table in ("command_activity", "command_activity_matches", "command_activity_correlations"):
        rows = cast(
            list[tuple[int, str, int, str, int]],
            connection.execute(f"pragma index_list({table})").fetchall(),
        )
        for _, name, unique, _, partial in rows:
            columns = cast(
                list[tuple[int, int, str]],
                connection.execute(f"pragma index_info({name})").fetchall(),
            )
            actual_indexes[name] = (table, tuple(row[2] for row in columns), unique, partial)
    for name, expected in expected_indexes.items():
        if actual_indexes.get(name) != expected:
            raise RuntimeError(f"incompatible command activity index: {name}")
    _validate_schema_object_sql(connection, statements)


def _validate_schema_object_sql(
    connection: sqlite3.Connection,
    statements: tuple[str, ...],
) -> None:
    expected: dict[str, str] = {}
    for statement in statements:
        canonical = _canonical_sql(statement)
        match = re.match(
            r"create (?:unique )?(?:table|index|trigger) if not exists ([a-z0-9_]+)",
            canonical,
        )
        if match is None:
            raise RuntimeError("unrecognized command activity schema statement")
        expected[match.group(1)] = canonical.replace(" if not exists", "", 1)
    placeholders = ", ".join("?" for _ in expected)
    rows = cast(
        list[tuple[str, str]],
        connection.execute(
            f"select name, sql from sqlite_schema where name in ({placeholders})",
            tuple(expected),
        ).fetchall(),
    )
    actual = {name: _canonical_sql(sql) for name, sql in rows}
    for name, expected_sql in expected.items():
        if actual.get(name) != expected_sql:
            raise RuntimeError(f"incompatible command activity schema object: {name}")


def _canonical_sql(value: str) -> str:
    return " ".join(value.strip().lower().split())
