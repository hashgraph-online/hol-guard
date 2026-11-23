//! The command activity maintenance (version 12), API (version 13) and
//! display (version 27) schemas: a mirror of
//! `ensure_command_activity_maintenance_schema`,
//! `ensure_command_activity_api_schema` and
//! `ensure_command_activity_display_schema`.

use rusqlite::{Connection, OptionalExtension};

use super::activity_extra_sql::{
    API_STATEMENTS, DISPLAY_STATEMENTS, MAINTENANCE_SEED, MAINTENANCE_STATEMENTS,
};
use super::objects;
use super::tables::{check_table, in_savepoint};
use crate::guard_store_db::{StoreError, StoreResult};

pub(super) const MAINTENANCE_VERSION: i64 = 12;
pub(super) const MAINTENANCE_SCHEMA_VERSION: &str = "guard.command-activity-maintenance.v1";
pub(super) const API_VERSION: i64 = 13;
pub(super) const DISPLAY_VERSION: i64 = 27;

const RECORD: &str =
    "insert or ignore into schema_migrations (version, applied_at) values (?1, ?2)";

fn run_all(connection: &Connection, statements: &[&str]) -> StoreResult<()> {
    for statement in statements {
        connection.execute_batch(statement)?;
    }
    Ok(())
}

/// `ensure_command_activity_maintenance_schema`: create the rollup and
/// retention state, seed its singleton, check both, and record version 12.
pub(super) fn ensure_maintenance(connection: &Connection, now: &str) -> StoreResult<()> {
    in_savepoint(connection, "command_activity_maintenance_schema_v1", || {
        run_all(connection, &MAINTENANCE_STATEMENTS)?;
        connection.execute(MAINTENANCE_SEED, [MAINTENANCE_SCHEMA_VERSION])?;
        check_table(
            connection,
            "command_activity_rollup_membership",
            &[
                "activity_id",
                "day",
                "occurred_at",
                "rolled_at",
                "detail_present",
            ],
            &["activity_id"],
        )?;
        check_table(
            connection,
            "command_activity_maintenance",
            &[
                "singleton",
                "last_completed_day",
                "last_run_at",
                "detail_compaction_started_at",
                "rollup_backfill_cursor_occurred_at",
                "rollup_backfill_cursor_activity_id",
                "rollup_backfill_complete",
                "last_backfilled_rows",
                "last_detail_rows_deleted",
                "last_correlation_rows_deleted",
                "last_aggregate_rows_deleted",
                "schema_version",
            ],
            &["singleton"],
        )?;
        check_table(
            connection,
            "command_activity_rollup_pending",
            &["activity_id", "occurred_at"],
            &["activity_id"],
        )?;
        objects::validate(connection, &MAINTENANCE_STATEMENTS, "maintenance ", false)?;
        let version = connection
            .query_row(
                "select schema_version from command_activity_maintenance where singleton = 1",
                [],
                |row| row.get::<_, Option<String>>(0),
            )
            .optional()?
            .flatten();
        if version.as_deref() != Some(MAINTENANCE_SCHEMA_VERSION) {
            return Err(StoreError::Runtime(
                "incompatible command_activity_maintenance singleton".to_owned(),
            ));
        }
        connection.execute(RECORD, (MAINTENANCE_VERSION, now))?;
        Ok(())
    })
}

/// `ensure_command_activity_api_schema`: create the feedback and
/// invalidation state and its indexes and triggers, check them, and record
/// version 13.
pub(super) fn ensure_api(connection: &Connection, now: &str) -> StoreResult<()> {
    in_savepoint(connection, "command_activity_api_schema_v1", || {
        run_all(connection, &API_STATEMENTS)?;
        check_table(
            connection,
            "command_activity_feedback",
            &[
                "activity_id",
                "label",
                "created_at",
                "updated_at",
                "schema_version",
            ],
            &["activity_id"],
        )?;
        check_table(
            connection,
            "command_activity_invalidations",
            &["sequence", "activity_id"],
            &["sequence"],
        )?;
        objects::validate(connection, &API_STATEMENTS, "API ", false)?;
        connection.execute(RECORD, (API_VERSION, now))?;
        Ok(())
    })
}

/// `ensure_command_activity_display_schema`: create the local-only
/// invocation preview table and its guard triggers, check them, and record
/// version 27.
pub(super) fn ensure_display(connection: &Connection, now: &str) -> StoreResult<()> {
    in_savepoint(connection, "command_activity_display_schema_v1", || {
        run_all(connection, &DISPLAY_STATEMENTS)?;
        check_table(
            connection,
            "command_activity_invocation",
            &["activity_id", "invocation_preview"],
            &["activity_id"],
        )?;
        objects::validate(connection, &DISPLAY_STATEMENTS, "display ", false)?;
        connection.execute(RECORD, (DISPLAY_VERSION, now))?;
        Ok(())
    })
}
