//! Guard sessions, operations and operation items. Python supplies every
//! timestamp and the JSON text of structured values; rows come back as raw
//! columns and Python shapes them for its callers.

use rusqlite::Connection;
use serde_json::Value;

use crate::guard_store_args::Args;
use crate::guard_store_db::{
    exec, query_all, query_one, runtime_error, text, StoreError, StoreResult,
};
use crate::guard_store_json::py_str;
use crate::guard_store_lineage::persisted_metadata;

const SESSION_COLUMNS: &str = "session_id, harness, surface, status, client_name, client_title, \
     client_version, workspace, capabilities_json, created_at, updated_at";
const OPERATION_COLUMNS: &str = "operation_id, session_id, harness, operation_type, status, \
     approval_request_ids_json, resume_token, metadata_json, created_at, updated_at";
const ITEM_COLUMNS: &str = "item_id, operation_id, item_type, lifecycle, payload_json, created_at";

fn opt(value: Option<&str>) -> Value {
    value.map_or(Value::Null, Value::from)
}

fn row_or_null(row: Option<serde_json::Map<String, Value>>) -> Value {
    row.map_or(Value::Null, Value::Object)
}

fn rows_value(rows: Vec<serde_json::Map<String, Value>>) -> Value {
    Value::Array(rows.into_iter().map(Value::Object).collect())
}

fn fetch_session(connection: &Connection, session_id: &str) -> StoreResult<Value> {
    let sql = format!("select {SESSION_COLUMNS} from guard_sessions where session_id = ?");
    Ok(row_or_null(query_one(
        connection,
        &sql,
        &[Value::from(session_id)],
    )?))
}

pub(crate) fn upsert_session(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let session_id = args.str("session_id")?;
    let now = args.str("now")?;
    exec(
        connection,
        "insert into guard_sessions ( \
           session_id, harness, surface, status, client_name, client_title, client_version, \
           workspace, capabilities_json, created_at, updated_at \
         ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
         on conflict(session_id) do update set \
           harness = excluded.harness, \
           surface = excluded.surface, \
           status = excluded.status, \
           client_name = excluded.client_name, \
           client_title = excluded.client_title, \
           client_version = excluded.client_version, \
           workspace = excluded.workspace, \
           capabilities_json = excluded.capabilities_json, \
           updated_at = excluded.updated_at",
        &[
            Value::from(session_id),
            Value::from(args.str("harness")?),
            Value::from(args.str("surface")?),
            Value::from(args.str("status")?),
            Value::from(args.str("client_name")?),
            opt(args.opt_str("client_title")?),
            opt(args.opt_str("client_version")?),
            opt(args.opt_str("workspace")?),
            Value::from(args.str("capabilities_json")?),
            Value::from(now),
            Value::from(now),
        ],
    )?;
    match fetch_session(connection, session_id)? {
        Value::Null => runtime_error(&format!("Guard session {session_id} was not persisted.")),
        row => Ok(row),
    }
}

pub(crate) fn get_session(connection: &Connection, args: &Args) -> StoreResult<Value> {
    fetch_session(connection, args.str("session_id")?)
}

pub(crate) fn list_sessions(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let mut sql = format!("select {SESSION_COLUMNS} from guard_sessions");
    let mut params = Vec::new();
    if let Some(status) = args.opt_str("status")? {
        sql.push_str(" where status = ?");
        params.push(Value::from(status));
    }
    sql.push_str(" order by updated_at desc, session_id desc limit ?");
    params.push(Value::from(args.int("limit")?));
    Ok(rows_value(query_all(connection, &sql, &params)?))
}

fn fetch_operation(connection: &Connection, operation_id: &str) -> StoreResult<Value> {
    let sql = format!("select {OPERATION_COLUMNS} from guard_operations where operation_id = ?");
    Ok(row_or_null(query_one(
        connection,
        &sql,
        &[Value::from(operation_id)],
    )?))
}

pub(crate) fn upsert_operation(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let operation_id = args.str("operation_id")?;
    let now = args.str("now")?;
    let requested = args.str("metadata_json")?;
    let existing = query_one(
        connection,
        "select metadata_json from guard_operations where operation_id = ?",
        &[Value::from(operation_id)],
    )?;
    let persisted = match &existing {
        Some(row) => persisted_metadata(text(row, "metadata_json"), requested)?,
        None => requested.to_owned(),
    };
    exec(
        connection,
        "insert into guard_operations ( \
           operation_id, session_id, harness, operation_type, status, \
           approval_request_ids_json, resume_token, metadata_json, created_at, updated_at \
         ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) \
         on conflict(operation_id) do update set \
           session_id = excluded.session_id, \
           harness = excluded.harness, \
           operation_type = excluded.operation_type, \
           status = excluded.status, \
           approval_request_ids_json = excluded.approval_request_ids_json, \
           resume_token = excluded.resume_token, \
           metadata_json = excluded.metadata_json, \
           updated_at = excluded.updated_at",
        &[
            Value::from(operation_id),
            Value::from(args.str("session_id")?),
            Value::from(args.str("harness")?),
            Value::from(args.str("operation_type")?),
            Value::from(args.str("status")?),
            Value::from(args.str("approval_request_ids_json")?),
            opt(args.opt_str("resume_token")?),
            Value::from(persisted),
            Value::from(now),
            Value::from(now),
        ],
    )?;
    match fetch_operation(connection, operation_id)? {
        Value::Null => runtime_error(&format!(
            "Guard operation {operation_id} was not persisted."
        )),
        row => Ok(row),
    }
}

pub(crate) fn get_operation(connection: &Connection, args: &Args) -> StoreResult<Value> {
    fetch_operation(connection, args.str("operation_id")?)
}

pub(crate) fn list_operations(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let mut sql = format!("select {OPERATION_COLUMNS} from guard_operations");
    let mut params = Vec::new();
    if let Some(session_id) = args.opt_str("session_id")? {
        sql.push_str(" where session_id = ?");
        params.push(Value::from(session_id));
    }
    sql.push_str(" order by updated_at desc, operation_id desc limit ?");
    params.push(Value::from(args.int("limit")?));
    Ok(rows_value(query_all(connection, &sql, &params)?))
}

/// Whether the decoded `approval_request_ids` list contains `request_id` once
/// every element is rendered with `str()`, as the Python membership test did.
fn lists_request(ids_json: &str, request_id: &str) -> StoreResult<bool> {
    let decoded: Value = serde_json::from_str(ids_json)
        .map_err(|error| StoreError::Value(format!("Invalid approval request ids: {error}")))?;
    let rendered = |item: &Value| py_str(item).is_some_and(|text| text == request_id);
    match &decoded {
        Value::Array(items) => Ok(items.iter().any(rendered)),
        Value::Object(map) => Ok(map.keys().any(|key| key == request_id)),
        Value::String(text) => Ok(text.chars().any(|c| c.to_string() == request_id)),
        _ => Err(StoreError::Invalid(
            "native_guard_store_stored_value_invalid",
        )),
    }
}

pub(crate) fn operation_for_approval_request(
    connection: &Connection,
    args: &Args,
) -> StoreResult<Value> {
    let request_id = args.str("request_id")?;
    let sql = format!(
        "select {OPERATION_COLUMNS} from guard_operations \
         where approval_request_ids_json like ? \
         order by updated_at desc, operation_id desc"
    );
    let rows = query_all(connection, &sql, &[Value::from(format!("%{request_id}%"))])?;
    for row in rows {
        if lists_request(text(&row, "approval_request_ids_json"), request_id)? {
            return Ok(Value::Object(row));
        }
    }
    Ok(Value::Null)
}

fn list_items(
    connection: &Connection,
    operation_id: &str,
) -> StoreResult<Vec<crate::guard_store_db::Row>> {
    let sql = format!(
        "select {ITEM_COLUMNS} from guard_operation_items where operation_id = ? \
         order by created_at asc, item_id asc"
    );
    query_all(connection, &sql, &[Value::from(operation_id)])
}

pub(crate) fn add_operation_item(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let (item_id, operation_id) = (args.str("item_id")?, args.str("operation_id")?);
    exec(
        connection,
        "insert into guard_operation_items ( \
           item_id, operation_id, item_type, lifecycle, payload_json, created_at \
         ) values (?, ?, ?, ?, ?, ?)",
        &[
            Value::from(item_id),
            Value::from(operation_id),
            Value::from(args.str("item_type")?),
            Value::from(args.str("lifecycle")?),
            Value::from(args.str("payload_json")?),
            Value::from(args.str("now")?),
        ],
    )?;
    list_items(connection, operation_id)?
        .into_iter()
        .find(|row| text(row, "item_id") == item_id)
        .map(Value::Object)
        .map_or_else(
            || {
                runtime_error(&format!(
                    "Guard operation item {item_id} was not persisted."
                ))
            },
            Ok,
        )
}

pub(crate) fn list_operation_items(connection: &Connection, args: &Args) -> StoreResult<Value> {
    Ok(rows_value(list_items(
        connection,
        args.str("operation_id")?,
    )?))
}
