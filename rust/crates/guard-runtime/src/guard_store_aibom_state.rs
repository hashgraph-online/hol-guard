//! The `sync_state` rows behind AI-BOM inventory sync: the last sync summary,
//! the guard-events endpoint backoff, the user-wide inventory collection, the
//! workspace context the daemon refreshes inventory for, and the daemon's last
//! refresh record.
//!
//! Port of the raw sync-payload reads and writes in `aibom_cli.py`,
//! `aibom_commands.py`, `aibom_sync.py`, `workers/ticks.py` and
//! `runtime/runner.py`, together with the timing rules that read them: when a
//! sync is due again, whether the missing-endpoint backoff still holds, and
//! whether the user-wide inventory was collected recently.

use rusqlite::Connection;
use serde_json::{json, Map, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{value_error, StoreError, StoreResult};
use crate::guard_store_local_cli::parse_utc;
use crate::guard_store_sync_state::{read_payload, write_encoded};

/// The last AI-BOM sync attempt.
const SYNC_SUMMARY_KEY: &str = "aibom_sync_summary";
/// `_AIBOM_GUARD_EVENTS_BACKOFF_KEY`.
const BACKOFF_KEY: &str = "aibom_guard_events_backoff";
/// `_AIBOM_USER_INVENTORY_KEY`.
const USER_INVENTORY_KEY: &str = "aibom_user_inventory_collection";
/// The home and workspace the last cloud sync ran for.
const CONTEXT_KEY: &str = "aibom_inventory_context";
/// The daemon's last inventory refresh.
const DAEMON_KEY: &str = "aibom_inventory_daemon";
/// `_AIBOM_EMPTY_SYNC_RETRY_SECONDS`: an empty inventory is retried sooner.
const EMPTY_SYNC_RETRY_SECONDS: i64 = 2 * 60;
/// `_AIBOM_GUARD_EVENTS_BACKOFF_MINUTES`.
const BACKOFF_SECONDS: i64 = 5 * 60;
/// The reason a missing guard-events endpoint records.
const ENDPOINT_UNAVAILABLE: &str = "guard_events_endpoint_unavailable";
const MICROS: i64 = 1_000_000;

/// Whether `method` is one of the AI-BOM sync row methods.
pub(crate) fn handles(method: &str) -> bool {
    matches!(
        method,
        "aibom_sync_schedule"
            | "aibom_sync_summary"
            | "aibom_guard_events_backoff_active"
            | "aibom_user_inventory_recency"
            | "aibom_inventory_context"
            | "record_aibom_sync_summary"
            | "record_aibom_guard_events_unavailable"
            | "record_aibom_user_inventory"
            | "record_aibom_inventory_context"
            | "record_aibom_inventory_daemon"
    )
}

pub(crate) fn dispatch(
    connection: &Connection,
    method: &str,
    args: &Args<'_>,
) -> StoreResult<Value> {
    match method {
        "aibom_sync_schedule" => sync_schedule(connection, args),
        "aibom_sync_summary" => {
            Ok(object_row(connection, SYNC_SUMMARY_KEY)?.map_or(Value::Null, Value::Object))
        }
        "aibom_guard_events_backoff_active" => backoff_active(connection, args),
        "aibom_user_inventory_recency" => user_inventory_recency(connection, args),
        "aibom_inventory_context" => inventory_context(connection, args),
        "record_aibom_sync_summary" => write_object(connection, SYNC_SUMMARY_KEY, args),
        "record_aibom_guard_events_unavailable" => record_unavailable(connection, args),
        "record_aibom_user_inventory" => write_object(connection, USER_INVENTORY_KEY, args),
        "record_aibom_inventory_context" => write_object(connection, CONTEXT_KEY, args),
        "record_aibom_inventory_daemon" => write_object(connection, DAEMON_KEY, args),
        _ => Err(StoreError::Invalid("native_guard_store_method_unknown")),
    }
}

/// `_aibom_sync_is_due`, plus the last sync time the skip answer reports. A
/// sync is due when none succeeded, its time is missing or unreadable, or the
/// interval has passed. A sync that found no snapshots is retried after at
/// most two minutes.
fn sync_schedule(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    let generated_at = text_arg(args, "generated_at", "invalid_generated_at")?;
    let min_interval = args.int("min_interval_seconds")?;
    let prior = object_row(connection, SYNC_SUMMARY_KEY)?;
    let last_sync_at = prior
        .as_ref()
        .and_then(|row| row.get("synced_at"))
        .filter(|value| value.is_string())
        .cloned()
        .unwrap_or(Value::Null);
    let due = prior.as_ref().is_none_or(|row| {
        if row.get("synced") != Some(&Value::Bool(true)) {
            return true;
        }
        let retry = if row.get("snapshots").and_then(Value::as_f64) == Some(0.0) {
            min_interval.min(EMPTY_SYNC_RETRY_SECONDS)
        } else {
            min_interval
        };
        match elapsed_micros(row.get("synced_at"), generated_at) {
            Some(elapsed) => i128::from(elapsed) >= i128::from(retry) * i128::from(MICROS),
            None => true,
        }
    });
    Ok(json!({ "due": due, "last_sync_at": last_sync_at }))
}

/// `_aibom_guard_events_endpoint_unavailable_recently`: the endpoint was
/// recorded missing less than five minutes before `now`.
fn backoff_active(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    let now = text_arg(args, "now", "invalid_now")?;
    let active = object_row(connection, BACKOFF_KEY)?.is_some_and(|row| {
        row.get("sync_reason").and_then(Value::as_str) == Some(ENDPOINT_UNAVAILABLE)
            && elapsed_micros(row.get("synced_at"), now)
                .is_some_and(|elapsed| elapsed < BACKOFF_SECONDS * MICROS)
    });
    Ok(Value::Bool(active))
}

/// Whether the user-wide inventory was collected within the interval before
/// `generated_at`, and when.
fn user_inventory_recency(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    let generated_at = text_arg(args, "generated_at", "invalid_generated_at")?;
    let min_interval = args.int("min_interval_seconds")?;
    let collected_at = object_row(connection, USER_INVENTORY_KEY)?
        .and_then(|mut row| row.remove("collected_at"))
        .filter(|value| value.as_str().is_some_and(|text| !text.trim().is_empty()));
    let recent = elapsed_micros(collected_at.as_ref(), generated_at).is_some_and(|elapsed| {
        elapsed >= 0 && i128::from(elapsed) < i128::from(min_interval) * i128::from(MICROS)
    });
    Ok(json!({ "recent": recent, "collected_at": collected_at.unwrap_or(Value::Null) }))
}

/// The stored inventory context when it was recorded for `workspace_id`, else
/// an empty object. With no current workspace nothing is bound.
fn inventory_context(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    let Some(workspace_id) = args.opt_str("workspace_id")? else {
        return Ok(json!({}));
    };
    let bound = object_row(connection, CONTEXT_KEY)?
        .filter(|row| row.get("workspace_id").and_then(Value::as_str) == Some(workspace_id));
    Ok(Value::Object(bound.unwrap_or_default()))
}

/// The backoff row a missing guard-events endpoint leaves: the events not yet
/// sent are counted as skipped.
fn record_unavailable(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    let now = text_arg(args, "now", "invalid_now")?;
    let events = args.int("events")?;
    let row = json!({
        "synced_at": now,
        "events": events,
        "accepted": args.int("accepted")?,
        "skipped": events,
        "sync_skipped": true,
        "sync_reason": ENDPOINT_UNAVAILABLE,
    });
    write(connection, BACKOFF_KEY, &row, now)
}

/// Microseconds from the recorded `stamp` to `now`, when both read as times.
fn elapsed_micros(stamp: Option<&Value>, now: &str) -> Option<i64> {
    let then = parse_utc(stamp?)?;
    parse_utc(&Value::from(now))?.checked_sub(then)
}

/// The stored object under `state_key`, if any.
fn object_row(connection: &Connection, state_key: &str) -> StoreResult<Option<Map<String, Value>>> {
    Ok(match read_payload(connection, state_key)? {
        Some(Value::Object(row)) => Some(row),
        _ => None,
    })
}

/// A required, non-empty text argument.
fn text_arg<'a>(args: &Args<'a>, key: &str, code: &'static str) -> StoreResult<&'a str> {
    match args.raw(key).and_then(Value::as_str) {
        Some(value) if !value.trim().is_empty() => Ok(value),
        _ => value_error(code),
    }
}

/// Upsert the `payload` object argument under `state_key`.
fn write_object(connection: &Connection, state_key: &str, args: &Args<'_>) -> StoreResult<Value> {
    let now = text_arg(args, "now", "invalid_now")?;
    let Some(payload) = args.raw("payload").filter(|payload| payload.is_object()) else {
        return value_error("invalid_payload");
    };
    write(connection, state_key, payload, now)
}

fn write(connection: &Connection, state_key: &str, row: &Value, now: &str) -> StoreResult<Value> {
    let encoded = serde_json::to_string(row)
        .map_err(|_| StoreError::Invalid("native_aibom_state_row_invalid"))?;
    write_encoded(connection, state_key, &encoded, now)?;
    Ok(Value::Null)
}

#[cfg(test)]
#[path = "guard_store_aibom_state_tests.rs"]
mod tests;
