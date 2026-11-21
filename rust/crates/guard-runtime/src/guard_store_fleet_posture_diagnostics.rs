//! `fleet_posture_cached_diagnostics` and `record_fleet_posture_diagnostics`:
//! the short-lived per-tool diagnostics cache the fleet posture report reads.
//!
//! Port of the freshness check and save `runtime/fleet_posture_tools.py`
//! (`DiagnosticsCache`) kept in Python. Python still probes a tool and
//! summarizes what it found; the store decides which cached summaries are
//! fresh and merges new ones into the stored row.

use rusqlite::Connection;
use serde_json::{json, Map, Value};

use super::{object_row, write};
use crate::guard_store_args::Args;
use crate::guard_store_db::{value_error, StoreResult};
use crate::guard_store_json::epoch_micros;

/// `DIAGNOSTICS_STATE_KEY`.
const DIAGNOSTICS_KEY: &str = "fleet_posture_diagnostics";

/// `parse_timestamp`: trimmed ISO-8601 text, a trailing `Z` read as UTC and
/// an instant without an offset read as UTC.
fn instant(value: Option<&Value>) -> Option<i128> {
    let text = value?.as_str()?.trim();
    if text.is_empty() {
        return None;
    }
    let text = text
        .strip_suffix(['Z', 'z'])
        .map_or_else(|| text.to_owned(), |head| format!("{head}+00:00"));
    epoch_micros(&text)
}

fn ttl_micros(args: &Args<'_>) -> StoreResult<i128> {
    let seconds = args.int("ttl_seconds")?;
    Ok(i128::from(seconds) * 1_000_000)
}

/// The cached summary for one entry while it is younger than the TTL. An
/// entry stamped in the future (a clock moved back) is not fresh.
fn fresh_summary(entry: &Value, now: i128, ttl: i128) -> Option<&Map<String, Value>> {
    let entry = entry.as_object()?;
    let summary = entry.get("diagnostics")?.as_object()?;
    let age = now - instant(entry.get("at"))?;
    (0..ttl).contains(&age).then_some(summary)
}

/// `fleet_posture_cached_diagnostics`: every cached summary still fresh at
/// `now`, keyed by harness. A TTL of zero or less turns the cache off.
pub(crate) fn cached_method(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    let ttl = ttl_micros(args)?;
    let now = instant(args.raw("now")).map_or_else(|| value_error("invalid_now"), Ok)?;
    let mut fresh = Map::new();
    if ttl > 0 {
        for (harness, entry) in object_row(connection, DIAGNOSTICS_KEY)?.unwrap_or_default() {
            if let Some(summary) = fresh_summary(&entry, now, ttl) {
                fresh.insert(harness, Value::Object(summary.clone()));
            }
        }
    }
    Ok(json!({"diagnostics": fresh}))
}

/// `record_fleet_posture_diagnostics`: stamp each new summary with `now` and
/// merge it into the stored row. Entries for other harnesses are kept, so a
/// concurrent build that probed another tool is not overwritten.
pub(crate) fn record_method(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    let entries = args
        .raw("entries")
        .and_then(Value::as_object)
        .filter(|entries| !entries.is_empty())
        .map_or_else(|| value_error("invalid_entries"), Ok)?;
    let now = args.str("now")?;
    if instant(Some(&Value::from(now))).is_none() {
        return value_error("invalid_now");
    }
    let mut stored = object_row(connection, DIAGNOSTICS_KEY)?.unwrap_or_default();
    for (harness, summary) in entries {
        if harness.is_empty() || !summary.is_object() {
            return value_error("invalid_entries");
        }
        stored.insert(harness.clone(), json!({"at": now, "diagnostics": summary}));
    }
    write(connection, DIAGNOSTICS_KEY, &Value::Object(stored), now)?;
    Ok(Value::Null)
}

#[cfg(test)]
#[path = "guard_store_fleet_posture_diagnostics_tests.rs"]
mod tests;
