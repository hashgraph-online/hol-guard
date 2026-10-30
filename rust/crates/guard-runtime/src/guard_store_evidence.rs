//! The local evidence log behind the dashboard's Evidence view, its exports
//! and `hol-guard receipts`.
//!
//! Rows carry `details_json` as stored, so the caller decodes it with the
//! key order it was written in. A read fits in one native store response:
//! it returns as many rows as fit the byte budget, at least one, and hands
//! back a cursor after the last row so the caller reads on from there. A
//! record added or removed between two reads never shifts the next page.

use serde_json::{json, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{exec, int, query_each, query_one, StoreError, StoreResult};

const ARGS_INVALID: StoreError = StoreError::Invalid("native_guard_store_args_invalid");

/// Half the 2 MiB response limit, which leaves room for the envelope.
const READ_BYTES_BUDGET: usize = 1024 * 1024;

/// The most one row may carry and still fit a response on its own. A row
/// stored larger is read with its details left out.
const ROW_BYTES_LIMIT: usize = 3 * 512 * 1024;

const DETAILS_OMITTED: &str = "{\"details_omitted\": \"too_large\"}";

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

/// The filters present, in the order Python built them.
fn filters(
    args: &Args<'_>,
    keys: &[(&str, &'static str)],
) -> StoreResult<(Vec<&'static str>, Vec<Value>)> {
    let mut clauses = Vec::new();
    let mut params = Vec::new();
    for (key, clause) in keys {
        if let Some(value) = args.opt_str(key)? {
            clauses.push(*clause);
            params.push(Value::from(value));
        }
    }
    Ok((clauses, params))
}

fn where_clause(clauses: &[&str]) -> String {
    if clauses.is_empty() {
        String::new()
    } else {
        format!("where {}", clauses.join(" and "))
    }
}

/// The `[created_at, rowid]` of the last row a previous read returned.
fn after(args: &Args<'_>) -> StoreResult<Option<(String, i64)>> {
    match args.raw("after") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(pair)) => match pair.as_slice() {
            [Value::String(created_at), Value::Number(rowid)] => Ok(Some((
                created_at.clone(),
                rowid.as_i64().ok_or(ARGS_INVALID)?,
            ))),
            _ => Err(ARGS_INVALID),
        },
        Some(_) => Err(ARGS_INVALID),
    }
}

/// `list_evidence`: newest first, with `details_json` only when asked for.
///
/// Rows that share a `created_at` come in rowid order, which every evidence
/// index already carries, so the cursor needs no extra sort.
pub(crate) fn list(connection: &rusqlite::Connection, args: &Args<'_>) -> StoreResult<Value> {
    let (mut clauses, mut params) = filters(args, &LIST_FILTERS)?;
    if let Some((created_at, rowid)) = after(args)? {
        clauses.push("created_at <= ? and (created_at < ? or rowid > ?)");
        params.extend([
            Value::from(created_at.clone()),
            Value::from(created_at),
            Value::from(rowid),
        ]);
    }
    params.push(Value::from(args.int("limit")?));
    let details = if args.flag("include_details")? {
        ", details_json"
    } else {
        ""
    };
    let clause = where_clause(&clauses);
    let mut kept = Vec::new();
    let mut size = 0;
    let mut more = false;
    let mut cursor = Value::Null;
    query_each(
        connection,
        &format!(
            "select {SUMMARY_COLUMNS}{details}, action_identity, created_at, rowid as row_order \
             from guard_evidence {clause} order by created_at desc, rowid asc limit ?"
        ),
        &params,
        |mut row| {
            let row_order = row.remove("row_order").unwrap_or(Value::Null);
            let mut row_size = encoded_len(&row);
            if row_size > ROW_BYTES_LIMIT && row.contains_key("details_json") {
                row.insert("details_json".to_owned(), Value::from(DETAILS_OMITTED));
                row_size = encoded_len(&row);
            }
            if !kept.is_empty() && size + row_size > READ_BYTES_BUDGET {
                more = true;
                return Ok(false);
            }
            size += row_size;
            cursor = json!([
                row.get("created_at").cloned().unwrap_or(Value::Null),
                row_order
            ]);
            kept.push(Value::Object(row));
            Ok(true)
        },
    )?;
    Ok(json!({"rows": kept, "more": more, "after": cursor}))
}

fn encoded_len(row: &crate::guard_store_db::Row) -> usize {
    serde_json::to_string(row).map_or(0, |text| text.len())
}

/// `count_evidence`.
pub(crate) fn count(connection: &rusqlite::Connection, args: &Args<'_>) -> StoreResult<Value> {
    let (clauses, params) = filters(args, &COUNT_FILTERS)?;
    let row = query_one(
        connection,
        &format!(
            "select count(*) as count from guard_evidence {}",
            where_clause(&clauses)
        ),
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
