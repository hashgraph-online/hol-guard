//! Per-source counters of how often Cloud rejected each outbox event, kept in
//! `sync_state` so an event that can never be accepted is dead-lettered after
//! a bounded number of deliveries.

use std::collections::BTreeMap;

use rusqlite::Connection;
use serde_json::Value;

use crate::guard_store_args::Args;
use crate::guard_store_db::{exec, query_one, text, value_error, StoreResult};

const COUNTS_KEY: &str = "guard_cloud_review_rejection_counts";

/// `forget_review_rejection_counts`: drop the counters of events that left
/// the retry path.
pub(crate) fn forget_counts(
    connection: &Connection,
    source: &str,
    args: &Args,
) -> StoreResult<Value> {
    let sequences = args.ints("sequences")?;
    let changed_at = args.str("changed_at")?;
    let original = load_counts(connection, source)?;
    let mut counts = original.clone();
    for sequence in sequences {
        counts.remove(&sequence.to_string());
    }
    save_counts(connection, source, &counts, &original, changed_at)?;
    Ok(Value::Null)
}

fn counts_key(source: &str) -> String {
    format!("{COUNTS_KEY}:{source}")
}

/// The stored counters; entries that are not a decimal name with a positive
/// count are dropped.
pub(super) fn load_counts(
    connection: &Connection,
    source: &str,
) -> StoreResult<BTreeMap<String, i64>> {
    let Some(row) = query_one(
        connection,
        "select payload_json from sync_state where state_key = ?",
        &[Value::from(counts_key(source))],
    )?
    else {
        return Ok(BTreeMap::new());
    };
    let Ok(stored) = serde_json::from_str::<Value>(text(&row, "payload_json")) else {
        return value_error("invalid stored JSON");
    };
    Ok(stored
        .as_object()
        .into_iter()
        .flatten()
        .filter(|(name, _)| !name.is_empty() && name.bytes().all(|byte| byte.is_ascii_digit()))
        .filter_map(|(name, count)| {
            count
                .as_i64()
                .filter(|count| *count > 0)
                .map(|count| (name.clone(), count))
        })
        .collect())
}

pub(super) fn save_counts(
    connection: &Connection,
    source: &str,
    counts: &BTreeMap<String, i64>,
    original: &BTreeMap<String, i64>,
    changed_at: &str,
) -> StoreResult<()> {
    if counts == original {
        return Ok(());
    }
    let payload = serde_json::to_string(counts).or_else(|_| value_error("invalid counters"))?;
    exec(
        connection,
        "insert into sync_state (state_key, payload_json, updated_at) values (?, ?, ?) \
         on conflict(state_key) do update set \
         payload_json = excluded.payload_json, updated_at = excluded.updated_at",
        &[
            Value::from(counts_key(source)),
            Value::from(payload),
            Value::from(changed_at),
        ],
    )?;
    Ok(())
}
