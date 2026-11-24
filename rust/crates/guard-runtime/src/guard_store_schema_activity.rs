//! The command activity schema (version 10) and its health singletons
//! (versions 11 and 19): a mirror of `ensure_command_activity_schema` and
//! `ensure_command_activity_health_schema`.

use rusqlite::{Connection, OptionalExtension};

use super::activity_sql::{
    ACTIVITY_STATEMENTS, HEALTH_ACTIVE_SEED, HEALTH_ACTIVE_TABLE, HEALTH_SEED, HEALTH_TABLE,
};
use super::objects;
use super::tables::{check_indexes, check_table, in_savepoint, IndexShape};
use crate::guard_store_db::{StoreError, StoreResult};

pub(super) const ACTIVITY_VERSION: i64 = 10;
pub(super) const HEALTH_VERSION: i64 = 11;
pub(super) const HEALTH_ACTIVE_VERSION: i64 = 19;
pub(super) const HEALTH_SCHEMA_VERSION: &str = "1.0.0";

const RECORD: &str =
    "insert or ignore into schema_migrations (version, applied_at) values (?1, ?2)";

/// Each activity table, its columns and its primary key.
pub(super) const ACTIVITY_TABLES: [(&str, &[&str], &[&str]); 6] = [
    (
        "command_activity",
        &[
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
        ],
        &["activity_id"],
    ),
    (
        "command_activity_matches",
        &[
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
        ],
        &["activity_id", "ordinal"],
    ),
    (
        "command_activity_match_effects",
        &["activity_id", "ordinal", "effect_class"],
        &["activity_id", "ordinal", "effect_class"],
    ),
    (
        "command_activity_correlations",
        &["activity_id", "kind", "harness", "key_id", "digest"],
        &["activity_id", "kind"],
    ),
    ("command_activity_daily_totals", &["day", "total"], &["day"]),
    (
        "command_activity_daily_rollups",
        &["day", "dimension", "dimension_value", "count"],
        &["day", "dimension", "dimension_value"],
    ),
];

const fn index(
    name: &'static str,
    table: &'static str,
    columns: &'static [&'static str],
    unique: bool,
    partial: bool,
) -> IndexShape {
    IndexShape {
        name,
        table,
        columns,
        unique,
        partial,
    }
}

pub(super) const ACTIVITY_INDEXES: [IndexShape; 6] = [
    index(
        "idx_command_activity_occurred_at",
        "command_activity",
        &["occurred_at", "activity_id"],
        false,
        false,
    ),
    index(
        "idx_command_activity_harness_occurred_at",
        "command_activity",
        &["harness", "occurred_at", "activity_id"],
        false,
        false,
    ),
    index(
        "idx_command_activity_match_rule",
        "command_activity_matches",
        &["rule_id", "activity_id"],
        false,
        false,
    ),
    index(
        "idx_command_activity_match_extension",
        "command_activity_matches",
        &["extension_id", "activity_id"],
        false,
        false,
    ),
    index(
        "idx_command_activity_correlation_lookup",
        "command_activity_correlations",
        &["kind", "harness", "key_id", "digest"],
        false,
        false,
    ),
    index(
        "idx_command_activity_request_correlation_unique",
        "command_activity_correlations",
        &["harness", "key_id", "digest"],
        true,
        true,
    ),
];

/// `ensure_command_activity_schema`: create, check and version the activity
/// tables as one savepoint.
pub(super) fn ensure_activity(connection: &Connection, now: &str) -> StoreResult<()> {
    in_savepoint(connection, "command_activity_schema_v1", || {
        for statement in ACTIVITY_STATEMENTS {
            connection.execute_batch(statement)?;
        }
        for (table, columns, key) in ACTIVITY_TABLES {
            check_table(connection, table, columns, key)?;
        }
        check_indexes(
            connection,
            &[
                "command_activity",
                "command_activity_matches",
                "command_activity_correlations",
            ],
            &ACTIVITY_INDEXES,
            "incompatible command activity index: ",
        )?;
        objects::validate(connection, &ACTIVITY_STATEMENTS, "", true)?;
        connection.execute(RECORD, (ACTIVITY_VERSION, now))?;
        Ok(())
    })
}

fn check_table_sql(connection: &Connection, table: &str, declared: &str) -> StoreResult<()> {
    let stored: Option<String> = connection
        .query_row(
            "select sql from sqlite_schema where type = 'table' and name = ?1",
            [table],
            |row| row.get(0),
        )
        .optional()?;
    let expected = objects::canonical(declared).replacen(" if not exists", "", 1);
    if stored.map(|sql| objects::canonical(&sql)) != Some(expected) {
        return Err(StoreError::Runtime(format!(
            "incompatible {table} schema object"
        )));
    }
    Ok(())
}

fn require_singleton(
    connection: &Connection,
    table: &str,
    expected: Option<&str>,
) -> StoreResult<()> {
    let column = if expected.is_some() {
        "schema_version"
    } else {
        "null"
    };
    let found: Option<Option<String>> = connection
        .query_row(
            &format!("select {column} from {table} where singleton = 1"),
            [],
            |row| row.get(0),
        )
        .optional()?;
    let valid = match (found, expected) {
        (Some(_), None) => true,
        (Some(Some(version)), Some(wanted)) => version == wanted,
        _ => false,
    };
    if !valid {
        return Err(StoreError::Runtime(format!(
            "incompatible {table} singleton"
        )));
    }
    Ok(())
}

/// `ensure_command_activity_health_schema`: create, check and seed both
/// health singletons, then record versions 11 and 19, as one savepoint.
pub(super) fn ensure_health(connection: &Connection, now: &str) -> StoreResult<()> {
    in_savepoint(connection, "command_activity_health_schema_v1", || {
        connection.execute_batch(HEALTH_TABLE)?;
        check_table(
            connection,
            "command_activity_health",
            &[
                "singleton",
                "dropped_event_count",
                "persistence_error_count",
                "last_error_code",
                "last_error_at",
                "schema_version",
            ],
            &["singleton"],
        )?;
        check_table_sql(connection, "command_activity_health", HEALTH_TABLE)?;
        connection.execute(HEALTH_SEED, [HEALTH_SCHEMA_VERSION])?;
        require_singleton(
            connection,
            "command_activity_health",
            Some(HEALTH_SCHEMA_VERSION),
        )?;
        connection.execute_batch(HEALTH_ACTIVE_TABLE)?;
        check_table(
            connection,
            "command_activity_health_active",
            &[
                "singleton",
                "command_error_active",
                "shadow_error_active",
                "maintenance_error_active",
            ],
            &["singleton"],
        )?;
        check_table_sql(
            connection,
            "command_activity_health_active",
            HEALTH_ACTIVE_TABLE,
        )?;
        connection.execute(HEALTH_ACTIVE_SEED, [])?;
        require_singleton(connection, "command_activity_health_active", None)?;
        connection.execute(RECORD, (HEALTH_VERSION, now))?;
        connection.execute(RECORD, (HEALTH_ACTIVE_VERSION, now))?;
        Ok(())
    })
}
