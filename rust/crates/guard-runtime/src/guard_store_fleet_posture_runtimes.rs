//! `fleet_posture_cached_runtimes` and `record_fleet_posture_runtimes`: the
//! hourly cache of the fleet posture report's `runtimes` section.
//!
//! Port of the cache check and save `runtime/fleet_posture_runtimes.py`
//! (`runtimes_section`) kept in Python. Python still observes launches, builds
//! the section and computes the keyed scope; the store decides whether the
//! cached section still answers for that scope and stores a new one.

use rusqlite::Connection;
use serde_json::{json, Map, Value};

use super::diagnostics::instant;
use super::{object_row, write};
use crate::guard_store_args::Args;
use crate::guard_store_db::{value_error, StoreResult};

/// `RUNTIMES_STATE_KEY`.
const RUNTIMES_KEY: &str = "fleet_posture_runtimes";

fn scope<'a>(args: &'a Args<'_>) -> StoreResult<&'a str> {
    args.opt_str("scope")?
        .filter(|scope| !scope.is_empty())
        .map_or_else(|| value_error("invalid_scope"), Ok)
}

/// Matches from an advisory bundle are good only until that bundle expires.
/// No expiry means the section matched no bundle, so it never lapses this way.
fn bundle_fresh(valid_until: Option<&Value>, now: i128) -> bool {
    match valid_until {
        None | Some(Value::Null) => true,
        // Same float comparison as Python's `now.timestamp() < valid_until`.
        Some(Value::Number(until)) => until
            .as_f64()
            .is_some_and(|until| (now as f64) / 1_000_000.0 < until),
        Some(_) => false,
    }
}

/// The cached section when the row was built for `scope`, its bundle has not
/// expired and it is younger than the TTL. A row stamped in the future (a
/// clock moved back) is not fresh.
fn fresh_section(
    row: &Map<String, Value>,
    scope: &str,
    now: i128,
    ttl: i128,
) -> Option<Map<String, Value>> {
    if row.get("scope").and_then(Value::as_str) != Some(scope) {
        return None;
    }
    let section = row.get("section")?.as_object()?;
    let age = now - instant(row.get("at"))?;
    let fresh = bundle_fresh(row.get("valid_until"), now) && (0..ttl).contains(&age);
    fresh.then(|| section.clone())
}

/// `fleet_posture_cached_runtimes`: the cached `runtimes` section while it
/// still answers for `scope` at `now`, or `null`. A TTL of zero or less turns
/// the cache off.
pub(crate) fn cached_method(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    let scope = scope(args)?;
    let ttl = i128::from(args.int("ttl_seconds")?) * 1_000_000;
    let now = instant(args.raw("now")).map_or_else(|| value_error("invalid_now"), Ok)?;
    let section = if ttl > 0 {
        object_row(connection, RUNTIMES_KEY)?
            .and_then(|row| fresh_section(&row, scope, now, ttl))
            .map_or(Value::Null, Value::Object)
    } else {
        Value::Null
    };
    Ok(json!({"section": section}))
}

/// `record_fleet_posture_runtimes`: store a freshly built section for
/// `scope`, stamped with `now` and the expiry of the bundle it matched.
pub(crate) fn record_method(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    let scope = scope(args)?;
    let section = args
        .raw("section")
        .and_then(Value::as_object)
        .map_or_else(|| value_error("invalid_section"), Ok)?;
    let valid_until = match args.raw("valid_until") {
        None | Some(Value::Null) => Value::Null,
        Some(Value::Number(until)) if until.as_f64().is_some_and(f64::is_finite) => {
            Value::Number(until.clone())
        }
        Some(_) => return value_error("invalid_valid_until"),
    };
    let now = args.str("now")?;
    if instant(Some(&Value::from(now))).is_none() {
        return value_error("invalid_now");
    }
    let entry = json!({
        "at": now,
        "scope": scope,
        "section": section,
        "valid_until": valid_until,
    });
    write(connection, RUNTIMES_KEY, &entry, now)?;
    Ok(Value::Null)
}

#[cfg(test)]
#[path = "guard_store_fleet_posture_runtimes_tests.rs"]
mod tests;
