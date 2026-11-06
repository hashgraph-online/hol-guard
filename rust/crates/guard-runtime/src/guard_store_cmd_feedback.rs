//! Command-activity feedback upserts and invalidation-cursor pages. Python
//! validates the inputs and supplies timestamps; persisted facts are decided
//! here.

use rusqlite::Connection;
use serde_json::{json, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{
    exec, int, is_null, query_all, query_one, text, StoreError, StoreResult,
};

const INVALID: StoreError = StoreError::Invalid("native_guard_store_args_invalid");
const MAX_PAGE: i64 = 100;

pub(crate) fn record_feedback(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let (activity_id, label) = (args.str("activity_id")?, args.str("label")?);
    let (timestamp, schema_version) = (args.str("recorded_at")?, args.str("schema_version")?);
    let known = query_one(
        connection,
        "select 1 as present from command_activity where activity_id = ?",
        &[Value::from(activity_id)],
    )?;
    if known.is_none() {
        return Ok(json!({ "not_found": true }));
    }
    let existing = query_one(
        connection,
        "select label, created_at, updated_at from command_activity_feedback where activity_id = ?",
        &[Value::from(activity_id)],
    )?;
    let (changed, created_at, updated_at) = match &existing {
        Some(row) if text(row, "label") == label => (
            false,
            text(row, "created_at").to_owned(),
            text(row, "updated_at").to_owned(),
        ),
        _ => {
            let created_at = existing.as_ref().map_or_else(
                || timestamp.to_owned(),
                |row| text(row, "created_at").to_owned(),
            );
            exec(
                connection,
                "insert into command_activity_feedback ( \
                   activity_id, label, created_at, updated_at, schema_version \
                 ) values (?, ?, ?, ?, ?) \
                 on conflict(activity_id) do update set \
                   label = excluded.label, \
                   updated_at = excluded.updated_at, \
                   schema_version = excluded.schema_version",
                &[
                    Value::from(activity_id),
                    Value::from(label),
                    Value::from(created_at.as_str()),
                    Value::from(timestamp),
                    Value::from(schema_version),
                ],
            )?;
            (true, created_at, timestamp.to_owned())
        }
    };
    Ok(json!({
        "activity_id": activity_id,
        "label": label,
        "created_at": created_at,
        "updated_at": updated_at,
        "changed": changed,
    }))
}

pub(crate) fn list_invalidations(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let cursor = args.int("cursor")?;
    let limit = args.int("limit")?;
    if cursor < 0 || !(1..=MAX_PAGE).contains(&limit) {
        return Err(INVALID);
    }
    let bounds = query_one(
        connection,
        "select min(sequence) as minimum, max(sequence) as maximum \
         from command_activity_invalidations",
        &[],
    )?
    .ok_or(INVALID)?;
    let (minimum, maximum) = (
        (!is_null(&bounds, "minimum")).then(|| int(&bounds, "minimum")),
        (!is_null(&bounds, "maximum")).then(|| int(&bounds, "maximum")),
    );
    let reset_required = match (minimum, maximum) {
        (None, _) | (_, None) => cursor > 0,
        (Some(min), Some(max)) => cursor < min - 1 || cursor > max,
    };
    let effective = match (reset_required, minimum, maximum) {
        (false, _, _) => cursor,
        (true, Some(min), Some(max)) => {
            if cursor > max {
                max
            } else {
                min - 1
            }
        }
        (true, _, _) => 0,
    };
    let rows = query_all(
        connection,
        "select sequence, activity_id from command_activity_invalidations \
         where sequence > ? order by sequence limit ?",
        &[Value::from(effective), Value::from(limit)],
    )?;
    let items: Vec<Value> = rows
        .iter()
        .map(|row| json!({ "sequence": int(row, "sequence"), "activity_id": text(row, "activity_id") }))
        .collect();
    Ok(json!({
        "reset_required": reset_required,
        "reset_cursor": if reset_required { json!(effective) } else { Value::Null },
        "items": items,
    }))
}
