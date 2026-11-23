//! The receipts of one drained page, composed before the store is opened.

use serde_json::Value;

use super::{compose, remember, Composed, Stamp};

/// Compose each record's receipt. A record whose stamp could not be drawn
/// (the random source failed) is handed back whole, `remember` intact, so the
/// drain retries it instead of counting it written. A record that is not
/// plain, or that no receipt composes from, is dropped as `write` documents:
/// a retry would compose it no better.
pub(super) fn prepare(
    guard_home: &str,
    records: Vec<(u64, Value)>,
) -> (Vec<Composed>, Vec<(u64, Value)>) {
    prepare_with(guard_home, records, Stamp::fresh)
}

fn prepare_with(
    guard_home: &str,
    records: Vec<(u64, Value)>,
    stamp: impl Fn() -> Option<Stamp>,
) -> (Vec<Composed>, Vec<(u64, Value)>) {
    let mut composed = Vec::new();
    let mut retry = Vec::new();
    for (sequence, record) in records {
        let Some(stamp) = stamp() else {
            retry.push((sequence, record));
            continue;
        };
        let (record, remembered) = match record.get(remember::KEY) {
            Some(_) => match remember::stripped(&record) {
                Some(stripped) => (stripped, true),
                None => continue,
            },
            None => (record, false),
        };
        let Some((receipt, row)) = compose(guard_home, &record, &stamp) else {
            if record.get("kind").and_then(Value::as_str) == Some("mcp_tool_call") {
                retry.push((sequence, record));
            }
            continue;
        };
        composed.push((
            sequence,
            record,
            receipt,
            row,
            remembered.then_some(stamp.store_now),
        ));
    }
    (composed, retry)
}

#[cfg(test)]
#[path = "mcp_relay_receipt_prepare_tests.rs"]
mod tests;
