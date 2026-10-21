//! `guard.db` access for the Codex request-resume op: the approval and
//! operation reads it needs and the `guard_request_resumes` statements of
//! `store_resume.py`.

use rusqlite::Connection;
use serde_json::{json, Map, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{exec, query_all, query_one, StoreError, StoreResult};
use crate::guard_store_json::py_str;
use crate::guard_store_sessions::operation_for_approval_request;

const RESUME_COLUMNS: &str = "request_id, operation_id, harness, resolution_action, strategy, \
     supported, status, thread_id, reason, message, last_error, attempt_count, created_at, \
     updated_at, last_attempt_at, sent_at, continuation_contract_version, continuation_capability, \
     continuation_status, continuation_reason, continuation_evidence_json, \
     continuation_offer_hash, continuation_action, continuation_completed_at, \
     continuation_cancelled_at";
const OPERATION_SCAN_LIMIT: i64 = 1000;

/// The approval fields the resume flow reads: harness and resolution.
pub(crate) struct Approval {
    pub(crate) harness: String,
    pub(crate) resolution_action: Option<String>,
}

/// One `update_request_resume` call. Continuation columns are left as stored.
pub(crate) struct ResumeUpdate<'a> {
    pub(crate) resolution_action: &'a str,
    pub(crate) strategy: Option<&'a str>,
    pub(crate) supported: Option<bool>,
    pub(crate) status: &'a str,
    pub(crate) reason: Option<&'a str>,
    pub(crate) message: Option<&'a str>,
    pub(crate) last_error: Option<&'a str>,
    pub(crate) attempt_count: i64,
    pub(crate) sent_at: Option<&'a str>,
}

pub(crate) fn approval(connection: &Connection, request_id: &str) -> StoreResult<Option<Approval>> {
    let row = query_one(
        connection,
        "select harness, resolution_action from approval_requests where request_id = ?",
        &[Value::from(request_id)],
    )?;
    Ok(row.map(|row| Approval {
        harness: row.get("harness").and_then(py_str).unwrap_or_default(),
        resolution_action: row
            .get("resolution_action")
            .and_then(Value::as_str)
            .filter(|text| !text.is_empty())
            .map(str::to_owned),
    }))
}

/// `get_guard_operation_for_approval_request` with its metadata decoded.
pub(crate) fn operation(connection: &Connection, request_id: &str) -> StoreResult<Option<Value>> {
    let args = Map::from_iter([("request_id".to_owned(), Value::from(request_id))]);
    match operation_for_approval_request(connection, &Args(&args))? {
        Value::Object(row) => decode_operation(row).map(Some),
        _ => Ok(None),
    }
}

/// `_find_codex_operation_for_request`: the operation found for the request
/// when it is a Codex one, else the newest of the latest operations that
/// lists the request.
pub(crate) fn codex_operation(
    connection: &Connection,
    request_id: &str,
) -> StoreResult<Option<Value>> {
    if let Some(found) = operation(connection, request_id)? {
        if found.get("harness").and_then(py_str).as_deref() == Some("codex") {
            return Ok(Some(found));
        }
    }
    let rows = query_all(
        connection,
        "select operation_id, harness, approval_request_ids_json, metadata_json \
         from guard_operations order by updated_at desc, operation_id desc limit ?",
        &[Value::from(OPERATION_SCAN_LIMIT)],
    )?;
    for row in rows {
        if row.get("harness").and_then(py_str).as_deref() != Some("codex") {
            continue;
        }
        let operation = decode_operation(row)?;
        let listed = operation["approval_request_ids"]
            .as_array()
            .is_some_and(|ids| {
                ids.iter()
                    .any(|id| py_str(id).as_deref() == Some(request_id))
            });
        if listed {
            return Ok(Some(operation));
        }
    }
    Ok(None)
}

fn decode_operation(mut row: Map<String, Value>) -> StoreResult<Value> {
    for (column, key) in [
        ("metadata_json", "metadata"),
        ("approval_request_ids_json", "approval_request_ids"),
    ] {
        let decoded = match row.remove(column) {
            Some(Value::String(text)) => serde_json::from_str(&text).map_err(|_| {
                StoreError::Invalid("native_codex_request_resume_operation_invalid")
            })?,
            _ => {
                return Err(StoreError::Invalid(
                    "native_codex_request_resume_operation_invalid",
                ))
            }
        };
        row.insert(key.to_owned(), decoded);
    }
    Ok(Value::Object(row))
}

pub(crate) fn resume(connection: &Connection, request_id: &str) -> StoreResult<Option<Value>> {
    let sql = format!("select {RESUME_COLUMNS} from guard_request_resumes where request_id = ?");
    let row = query_one(connection, &sql, &[Value::from(request_id)])?;
    Ok(row.map(resume_payload))
}

/// `_row_to_payload`.
fn resume_payload(mut row: Map<String, Value>) -> Value {
    let supported = row
        .get("supported")
        .and_then(Value::as_i64)
        .is_some_and(|flag| flag != 0);
    row.insert("supported".to_owned(), Value::Bool(supported));
    let evidence = match row.remove("continuation_evidence_json") {
        Some(Value::String(text)) => match serde_json::from_str::<Value>(&text) {
            Ok(Value::Array(items)) => items.into_iter().filter(Value::is_object).collect(),
            _ => Vec::new(),
        },
        _ => Vec::new(),
    };
    row.insert("continuation_evidence".to_owned(), Value::Array(evidence));
    Value::Object(row)
}

pub(crate) struct ResumeSeed<'a> {
    pub(crate) operation_id: Option<&'a str>,
    pub(crate) strategy: &'a str,
    pub(crate) thread_id: Option<&'a str>,
}

pub(crate) fn seed(
    connection: &Connection,
    request_id: &str,
    seed: &ResumeSeed<'_>,
    now: &str,
) -> StoreResult<()> {
    exec(
        connection,
        "insert into guard_request_resumes ( \
           request_id, operation_id, harness, resolution_action, strategy, supported, status, \
           thread_id, reason, message, last_error, attempt_count, created_at, updated_at, \
           last_attempt_at, sent_at \
         ) \
         values (?, ?, 'codex', null, ?, ?, 'pending', ?, null, null, null, 0, ?, ?, null, null) \
         on conflict(request_id) do update set \
           operation_id = excluded.operation_id, \
           harness = excluded.harness, \
           strategy = excluded.strategy, \
           supported = excluded.supported, \
           thread_id = coalesce(excluded.thread_id, guard_request_resumes.thread_id), \
           updated_at = excluded.updated_at",
        &[
            Value::from(request_id),
            json!(seed.operation_id),
            Value::from(seed.strategy),
            Value::from(i64::from(seed.thread_id.is_some())),
            json!(seed.thread_id),
            Value::from(now),
            Value::from(now),
        ],
    )?;
    Ok(())
}

pub(crate) fn update(
    connection: &Connection,
    request_id: &str,
    update: &ResumeUpdate<'_>,
    now: &str,
) -> StoreResult<()> {
    exec(
        connection,
        "update guard_request_resumes \
         set resolution_action = ?, \
             strategy = coalesce(?, strategy), \
             supported = coalesce(?, supported), \
             status = ?, \
             reason = ?, \
             message = ?, \
             last_error = ?, \
             attempt_count = ?, \
             updated_at = ?, \
             last_attempt_at = ?, \
             sent_at = ? \
         where request_id = ?",
        &[
            Value::from(update.resolution_action),
            json!(update.strategy),
            json!(update.supported.map(i64::from)),
            Value::from(update.status),
            json!(update.reason),
            json!(update.message),
            json!(update.last_error),
            Value::from(update.attempt_count),
            Value::from(now),
            Value::from(now),
            json!(update.sent_at),
            Value::from(request_id),
        ],
    )?;
    Ok(())
}
