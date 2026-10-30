//! The local evidence log behind the dashboard's Evidence view, its exports
//! and `hol-guard receipts`.
//!
//! Rows carry `details_json` as stored, so the caller decodes it with the
//! key order it was written in. A read fits in one native store response:
//! it returns as many rows as fit the byte budget, at least one, and says
//! whether more remain so the caller reads on from the next offset.

use serde_json::{json, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{exec, int, query_all, query_one, StoreError, StoreResult};

const ARGS_INVALID: StoreError = StoreError::Invalid("native_guard_store_args_invalid");

/// Half the 2 MiB response limit, which leaves room for the envelope.
const READ_BYTES_BUDGET: usize = 1024 * 1024;

const SUMMARY_COLUMNS: &str = "evidence_id, action_id, request_id, harness, workspace, \
     signal_id, category, severity, confidence, summary";

const TEXT_COLUMNS: [&str; 8] = [
    "evidence_id",
    "action_id",
    "request_id",
    "harness",
    "workspace",
    "signal_id",
    "category",
    "severity",
];

/// `add_evidence`: store one record, replacing any with the same id. The
/// caller sends `details` already encoded as `details_json`.
pub(crate) fn add(connection: &rusqlite::Connection, args: &Args<'_>) -> StoreResult<Value> {
    let mut params = Vec::with_capacity(13);
    for key in TEXT_COLUMNS {
        params.push(Value::from(args.str(key)?));
    }
    params.push(
        args.raw("confidence")
            .filter(|value| value.is_number())
            .cloned()
            .ok_or(ARGS_INVALID)?,
    );
    params.push(Value::from(args.str("summary")?));
    params.push(Value::from(args.str("details_json")?));
    params.push(
        args.opt_str("action_identity")?
            .map_or(Value::Null, Value::from),
    );
    params.push(Value::from(args.str("created_at")?));
    exec(
        connection,
        "insert or replace into guard_evidence \
           (evidence_id, action_id, request_id, harness, workspace, signal_id, \
            category, severity, confidence, summary, details_json, action_identity, created_at) \
         values (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        &params,
    )?;
    Ok(Value::Null)
}

const COUNT_FILTERS: [(&str, &str); 3] = [
    ("harness", "harness = ?"),
    ("category", "category = ?"),
    ("severity", "severity = ?"),
];

const LIST_FILTERS: [(&str, &str); 6] = [
    ("harness", "harness = ?"),
    ("category", "category = ?"),
    ("severity", "severity = ?"),
    ("request_id", "request_id = ?"),
    ("action_identity", "action_identity = ?"),
    ("before_cursor", "created_at < ?"),
];

/// The `where` clause for the filters present, in the order Python built it.
fn filters(args: &Args<'_>, keys: &[(&str, &str)]) -> StoreResult<(String, Vec<Value>)> {
    let mut clauses = Vec::new();
    let mut params = Vec::new();
    for (key, clause) in keys {
        if let Some(value) = args.opt_str(key)? {
            clauses.push(*clause);
            params.push(Value::from(value));
        }
    }
    let clause = if clauses.is_empty() {
        String::new()
    } else {
        format!("where {}", clauses.join(" and "))
    };
    Ok((clause, params))
}

/// `list_evidence`: newest first, with `details_json` only when asked for.
pub(crate) fn list(connection: &rusqlite::Connection, args: &Args<'_>) -> StoreResult<Value> {
    let (clause, mut params) = filters(args, &LIST_FILTERS)?;
    let limit = args.int("limit")?;
    let offset = match args.raw("offset") {
        None => 0,
        Some(_) => args.int("offset")?,
    };
    params.push(Value::from(limit));
    params.push(Value::from(offset));
    let details = if args.flag("include_details")? {
        ", details_json"
    } else {
        ""
    };
    let rows = query_all(
        connection,
        &format!(
            "select {SUMMARY_COLUMNS}{details}, action_identity, created_at \
             from guard_evidence {clause} order by created_at desc limit ? offset ?"
        ),
        &params,
    )?;
    let mut kept = Vec::new();
    let mut size = 0;
    let mut more = false;
    for row in rows {
        let row = Value::Object(row);
        let row_size = serde_json::to_string(&row).map_or(0, |text| text.len());
        if !kept.is_empty() && size + row_size > READ_BYTES_BUDGET {
            more = true;
            break;
        }
        size += row_size;
        kept.push(row);
    }
    Ok(json!({"rows": kept, "more": more}))
}

/// `count_evidence`.
pub(crate) fn count(connection: &rusqlite::Connection, args: &Args<'_>) -> StoreResult<Value> {
    let (clause, params) = filters(args, &COUNT_FILTERS)?;
    let row = query_one(
        connection,
        &format!("select count(*) as count from guard_evidence {clause}"),
        &params,
    )?;
    Ok(Value::from(row.map_or(0, |row| int(&row, "count"))))
}

/// `clear_evidence`: the number of records removed.
pub(crate) fn clear(connection: &rusqlite::Connection, _args: &Args<'_>) -> StoreResult<Value> {
    Ok(Value::from(exec(
        connection,
        "delete from guard_evidence",
        &[],
    )?))
}

#[cfg(test)]
#[path = "guard_store_evidence_tests.rs"]
mod tests;
