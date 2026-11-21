//! Native workspace review replay scan cursor: one `sync_state` row per
//! source that records how far the replay loop got through a finite snapshot
//! of pending Cloud Review requests.
//!
//! Port of `_scan_bounds` and `_save_scan_cursor` in
//! `runtime/native_workspace_review_replay.py`. Python still lists the pending
//! requests and probes them; the store decides where the next batch starts and
//! when a snapshot is finished.

use rusqlite::Connection;
use serde_json::{json, Map, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{value_error, StoreResult};
use crate::guard_store_sync_state::write_encoded;

use super::{stored, MARKER};

const SCHEMA: &str = "guard-cloud-review-native-workspace-review-scan.v1";

/// `_scan_key`: one scan row per source.
pub(crate) fn scan_key(source: &str) -> String {
    format!("{MARKER}:scan:{source}")
}

struct Scan<'a> {
    key: String,
    binding: &'a Map<String, Value>,
}

fn scan<'a>(args: &Args<'a>) -> StoreResult<Scan<'a>> {
    let source = args.str("source")?;
    if source.is_empty() {
        return value_error("invalid_request");
    }
    let binding = args.object("binding")?;
    if binding.is_empty() || !binding.values().all(Value::is_string) {
        return value_error("invalid_binding");
    }
    Ok(Scan {
        key: scan_key(source),
        binding,
    })
}

fn non_empty(state: &Map<String, Value>, field: &str) -> Option<String> {
    state
        .get(field)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
}

/// `native_workspace_review_replay_scan`: where the next batch starts. A row
/// for another binding, or one without an upper bound, starts a new snapshot.
pub(crate) fn read_method(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    let scan = scan(args)?;
    let state = stored(connection, &scan.key)?
        .filter(|state| state.get("binding").and_then(Value::as_object) == Some(scan.binding));
    let through = state
        .as_ref()
        .and_then(|state| non_empty(state, "through_request_id"));
    let cursor = state
        .as_ref()
        .filter(|_| through.is_some())
        .and_then(|state| non_empty(state, "cursor"));
    Ok(json!({"cursor": cursor, "through_request_id": through}))
}

/// The cursor after a finished batch: its last request while the batch was
/// full and the snapshot's upper bound lies beyond it, otherwise none, so the
/// next batch takes a new snapshot.
fn next_cursor<'a>(request_ids: &[&'a str], limit: i64, through: Option<&str>) -> Option<&'a str> {
    let full = usize::try_from(limit).is_ok_and(|limit| request_ids.len() == limit);
    let last = request_ids.last().copied()?;
    through.filter(|upper| full && last < *upper).map(|_| last)
}

/// `record_native_workspace_review_replay_scan`: save progress once a batch
/// has completed.
pub(crate) fn record_method(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    let scan = scan(args)?;
    let request_ids = args.strings("request_ids")?.unwrap_or_default();
    let limit = args.int("limit")?;
    if limit < 1 {
        return value_error("invalid_limit");
    }
    let through = args.opt_str("through_request_id")?;
    let changed_at = args.str("changed_at")?;
    let cursor = next_cursor(&request_ids, limit, through);
    let state = json!({
        "schema": SCHEMA,
        "binding": scan.binding,
        "cursor": cursor,
        "through_request_id": cursor.and(through),
    });
    let encoded =
        serde_json::to_string(&state).map_or_else(|_| value_error("invalid_payload"), Ok)?;
    write_encoded(connection, &scan.key, &encoded, changed_at)?;
    Ok(state)
}

#[cfg(test)]
#[path = "guard_store_review_replay_scan_tests.rs"]
mod tests;
