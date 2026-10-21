//! Command-activity privacy: atomic evidence deletion, the allowlisted
//! diagnostics snapshot, and bounded shadow-evaluation reads. Python sends the
//! allowlists (stable ids, proof levels, error classes) it owns; every
//! persisted fact is read and counted here.

use rusqlite::Connection;
use serde_json::{json, Map, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{
    exec, int, is_null, placeholders, query_all, query_one, text, StoreError, StoreResult,
};

const INVALID: StoreError = StoreError::Invalid("native_guard_store_args_invalid");
const MAX_SHADOW_LIMIT: i64 = 10_000;

const COUNT_TABLES: [(&str, &str); 12] = [
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
    ("shadow_evaluations", "command_activity_shadow_evaluations"),
    ("shadow_cohorts", "command_activity_shadow_cohorts"),
];

const DELETE_TABLES: [&str; 13] = [
    "command_activity_shadow_cohorts",
    "command_activity_shadow_evaluations",
    "command_activity_feedback",
    "command_activity_invocation",
    "command_activity",
    "command_activity_match_effects",
    "command_activity_matches",
    "command_activity_correlations",
    "command_activity_rollup_membership",
    "command_activity_rollup_pending",
    "command_activity_daily_rollups",
    "command_activity_daily_totals",
    "command_activity_invalidations",
];

fn table_counts(connection: &Connection) -> StoreResult<Map<String, Value>> {
    let mut counts = Map::new();
    for (label, table) in COUNT_TABLES {
        let row = query_one(
            connection,
            &format!("select count(*) as total from {table}"),
            &[],
        )?
        .ok_or(INVALID)?;
        counts.insert(label.to_owned(), Value::from(int(&row, "total")));
    }
    Ok(counts)
}

pub(crate) fn clear_evidence(connection: &Connection) -> StoreResult<Value> {
    let deleted = table_counts(connection)?;
    for table in DELETE_TABLES {
        exec(connection, &format!("delete from {table}"), &[])?;
    }
    for statement in [
        "delete from sqlite_sequence where name = 'command_activity_invalidations'",
        "update command_activity_health \
         set dropped_event_count = 0, persistence_error_count = 0, \
             last_error_code = null, last_error_at = null \
         where singleton = 1",
        "update command_activity_health_active \
         set command_error_active = 0, shadow_error_active = 0, maintenance_error_active = 0 \
         where singleton = 1",
        "update command_activity_maintenance \
         set last_completed_day = null, last_run_at = null, \
             detail_compaction_started_at = null, \
             rollup_backfill_cursor_occurred_at = null, \
             rollup_backfill_cursor_activity_id = null, \
             rollup_backfill_complete = 0, last_backfilled_rows = 0, \
             last_detail_rows_deleted = 0, last_correlation_rows_deleted = 0, \
             last_aggregate_rows_deleted = 0 \
         where singleton = 1",
    ] {
        exec(connection, statement, &[])?;
    }
    Ok(json!({ "deleted": deleted }))
}

fn string_list(args: &Args, key: &str) -> StoreResult<Vec<String>> {
    Ok(args
        .strings(key)?
        .ok_or(INVALID)?
        .into_iter()
        .map(str::to_owned)
        .collect())
}

/// Distinct persisted values of `column` that are allowlisted, sorted.
fn stable_distinct(
    connection: &Connection,
    table: &str,
    column: &str,
    allowed: &[String],
) -> StoreResult<Vec<Value>> {
    if allowed.is_empty() {
        return Ok(Vec::new());
    }
    let mut ordered: Vec<&String> = allowed.iter().collect();
    ordered.sort_unstable();
    ordered.dedup();
    let mut params: Vec<Value> = ordered
        .iter()
        .map(|value| Value::from(value.as_str()))
        .collect();
    params.push(Value::from(ordered.len() as i64));
    let rows = query_all(
        connection,
        &format!(
            "select distinct {column} as value from {table} \
             where {column} in ({}) order by {column} limit ?",
            placeholders(ordered.len())
        ),
        &params,
    )?;
    Ok(rows.iter().map(|row| json!(text(row, "value"))).collect())
}

pub(crate) fn diagnostics(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let harnesses = string_list(args, "harnesses")?;
    let extension_ids = string_list(args, "extension_ids")?;
    let rule_ids = string_list(args, "rule_ids")?;
    let proof_levels = string_list(args, "proof_levels")?;
    let error_classes = string_list(args, "error_classes")?;
    let mut counts = table_counts(connection)?;
    let health = query_one(
        connection,
        "select dropped_event_count, persistence_error_count, last_error_code \
         from command_activity_health where singleton = 1",
        &[],
    )?;
    let mut proof_coverage = Vec::new();
    for level in &proof_levels {
        let row = query_one(
            connection,
            "select count(*) as total from command_activity where proof_level = ?",
            &[Value::from(level.as_str())],
        )?
        .ok_or(INVALID)?;
        proof_coverage.push(json!({ "proof_level": level, "count": int(&row, "total") }));
    }
    let stable_ids = json!({
        "harnesses": stable_distinct(connection, "command_activity", "harness", &harnesses)?,
        "extensions": stable_distinct(connection, "command_activity_matches", "extension_id", &extension_ids)?,
        "rules": stable_distinct(connection, "command_activity_matches", "rule_id", &rule_ids)?,
    });
    let counter = |name: &str| {
        health
            .as_ref()
            .filter(|row| !is_null(row, name))
            .map_or(0, |row| int(row, name).max(0))
    };
    let (dropped_events, persistence_errors) = (
        counter("dropped_event_count"),
        counter("persistence_error_count"),
    );
    counts.insert("dropped_events".to_owned(), Value::from(dropped_events));
    counts.insert(
        "persistence_errors".to_owned(),
        Value::from(persistence_errors),
    );
    let error_code = health
        .as_ref()
        .filter(|row| !is_null(row, "last_error_code"))
        .map(|row| text(row, "last_error_code").to_owned());
    let classes: Vec<Value> = match error_code {
        Some(code) if persistence_errors > 0 && error_classes.contains(&code) => {
            vec![json!({ "error_class": code, "count": persistence_errors })]
        }
        _ => Vec::new(),
    };
    Ok(json!({
        "counts": counts,
        "proof_coverage": proof_coverage,
        "stable_ids": stable_ids,
        "error_classes": classes,
    }))
}

pub(crate) fn count_shadow(connection: &Connection) -> StoreResult<Value> {
    let row = query_one(
        connection,
        "select count(*) as total from command_activity_shadow_evaluations",
        &[],
    )?
    .ok_or(INVALID)?;
    Ok(json!(int(&row, "total")))
}

pub(crate) fn list_shadow(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let limit = args.int("limit")?;
    if !(1..=MAX_SHADOW_LIMIT).contains(&limit) {
        return Err(INVALID);
    }
    let rows = query_all(
        connection,
        "select * from command_activity_shadow_evaluations \
         order by occurred_at, activity_id limit ?",
        &[Value::from(limit)],
    )?;
    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let cohorts = query_all(
            connection,
            "select cohort from command_activity_shadow_cohorts \
             where activity_id = ? order by ordinal",
            &[row.get("activity_id").cloned().unwrap_or(Value::Null)],
        )?;
        let mut item = row;
        item.insert(
            "cohorts".to_owned(),
            Value::Array(
                cohorts
                    .iter()
                    .map(|cohort| json!(text(cohort, "cohort")))
                    .collect(),
            ),
        );
        items.push(Value::Object(item));
    }
    Ok(Value::Array(items))
}
