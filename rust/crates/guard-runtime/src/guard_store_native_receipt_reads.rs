//! `store_native_decision_receipts.get_native_decision_receipt`: one stored
//! receipt row, looked up by its decision ID in the hook table and then the
//! prompt table.
//!
//! The row comes back as stored, column by column. Python still checks it
//! with `validate_stored_native_decision_receipt`, which recomputes the
//! content-bound decision ID, so a changed row reads as no receipt there.

use rusqlite::Connection;
use serde_json::Value;

use crate::guard_store_args::Args;
use crate::guard_store_db::{query_one, StoreResult};

/// The hook table first, as the Python read looked there first.
const TABLES: [&str; 2] = [
    "native_hook_decision_receipts",
    "native_prompt_decision_receipts",
];

pub(super) fn handles(method: &str) -> bool {
    method == "get_native_decision_receipt"
}

pub(super) fn dispatch(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let decision_id = args.str("decision_id")?;
    if !is_decision_id(decision_id) {
        return Ok(Value::Null);
    }
    for table in TABLES {
        let row = query_one(
            connection,
            &format!("select * from {table} where decision_id = ?"),
            &[Value::from(decision_id)],
        )?;
        if let Some(row) = row {
            return Ok(Value::Object(row));
        }
    }
    Ok(Value::Null)
}

/// A decision ID is 64 lowercase hex characters; anything else names no row.
fn is_decision_id(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(test)]
#[path = "guard_store_native_receipt_reads_tests.rs"]
mod tests;
