//! The `sync_state` rows the daemon's request handlers and its worker host use
//! to hand work to each other: approval attention, the worker refresh request
//! and its answer, and the repair self-check status.
//!
//! Port of the raw sync-payload reads and writes in `workers/host.py` and the
//! repair status read in `routes/request_host.py`. A request handler does not
//! own the long-lived workers, so it leaves a row here and the worker host
//! takes it. Taking the attention rows reads and deletes them in one write
//! transaction, so two takers never both schedule the same operation.

use rusqlite::Connection;
use serde_json::{json, Map, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{
    exec, placeholders, query_each, text, value_error, StoreError, StoreResult,
};
use crate::guard_store_sync_state::{read_payload, write_encoded};

/// `ATTENTION_PREFIX`; the operation id follows it.
const ATTENTION_PREFIX: &str = "daemon_approval_attention:";
/// `REFRESH_REQUEST_KEY`.
const REFRESH_REQUEST_KEY: &str = "daemon_worker_refresh_request";
/// `REFRESH_STATUS_KEY`.
const REFRESH_STATUS_KEY: &str = "daemon_worker_refresh_status";
/// `REPAIR_SELF_CHECK_KEY`.
const REPAIR_SELF_CHECK_KEY: &str = "daemon_repair_self_check_status";
/// Row text one attention take may return, well inside the store client's
/// response limit.
const ATTENTION_BATCH_BYTES: usize = 1024 * 1024;
/// Keys removed per delete statement.
const DELETE_CHUNK: usize = 200;

/// Whether `method` is one of the worker-host handoff methods.
pub(crate) fn handles(method: &str) -> bool {
    matches!(
        method,
        "queue_approval_attention"
            | "take_approval_attention"
            | "request_worker_refresh"
            | "worker_refresh_status"
            | "take_worker_refresh_request"
            | "record_worker_refresh_status"
            | "record_repair_self_check"
            | "repair_self_check_status"
    )
}

pub(crate) fn dispatch(
    connection: &Connection,
    method: &str,
    args: &Args<'_>,
) -> StoreResult<Value> {
    match method {
        "queue_approval_attention" => queue_attention(connection, args),
        "take_approval_attention" => take_attention(connection),
        "request_worker_refresh" => {
            let nonce = text_arg(args, "nonce", "invalid_nonce")?;
            write(
                connection,
                REFRESH_REQUEST_KEY,
                &json!({ "nonce": nonce }),
                args,
            )
        }
        "worker_refresh_status" => refresh_status(connection, args),
        "take_worker_refresh_request" => take_refresh_request(connection),
        "record_worker_refresh_status" => {
            let row = json!({
                "nonce": text_arg(args, "nonce", "invalid_nonce")?,
                "running": args.flag("running")?,
                "sync_running": args.flag("sync_running")?,
            });
            write(connection, REFRESH_STATUS_KEY, &row, args)
        }
        "record_repair_self_check" => {
            let status = Value::Object(args.object("status")?.clone());
            write(connection, REPAIR_SELF_CHECK_KEY, &status, args)
        }
        "repair_self_check_status" => Ok(read_payload(connection, REPAIR_SELF_CHECK_KEY)?
            .filter(Value::is_object)
            .unwrap_or(Value::Null)),
        _ => Err(StoreError::Invalid("native_guard_store_method_unknown")),
    }
}

/// A required, non-empty text argument.
fn text_arg<'a>(args: &Args<'a>, key: &str, code: &'static str) -> StoreResult<&'a str> {
    match args.raw(key).and_then(Value::as_str) {
        Some(value) if !value.is_empty() => Ok(value),
        _ => value_error(code),
    }
}

/// Upsert `row` under `state_key`, stamped with the `now` argument.
fn write(
    connection: &Connection,
    state_key: &str,
    row: &Value,
    args: &Args<'_>,
) -> StoreResult<Value> {
    let now = text_arg(args, "now", "invalid_now")?;
    let encoded = serde_json::to_string(row)
        .map_err(|_| StoreError::Invalid("native_worker_host_row_invalid"))?;
    write_encoded(connection, state_key, &encoded, now)?;
    Ok(Value::Null)
}

/// `queue_approval_attention`: an operation waiting on approval, for the
/// worker host's attention loop. Each request keeps only what the attention
/// coordinator reads, so the row stays small however large the approval
/// records are: the request id, approval address and workspace, and the
/// severity of each decision signal. Entries that are not objects are dropped.
/// Requests that would take the row past [`ATTENTION_BATCH_BYTES`] are left
/// off the end, so every queued row fits one take's answer and queueing never
/// fails after the caller has saved its approvals.
fn queue_attention(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    let operation_id = text_arg(args, "operation_id", "invalid_operation_id")?;
    let Some(requests) = args.raw("requests").filter(|value| value.is_array()) else {
        return value_error("invalid_requests");
    };
    let mut used = json!({ "operation_id": operation_id, "requests": [] })
        .to_string()
        .len();
    let mut kept = Vec::new();
    for request in requests
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
    {
        let request = attention_request(request);
        let size = request.to_string().len() + 1;
        if used + size > ATTENTION_BATCH_BYTES {
            break;
        }
        used += size;
        kept.push(request);
    }
    let row = json!({ "operation_id": operation_id, "requests": kept });
    write(
        connection,
        &format!("{ATTENTION_PREFIX}{operation_id}"),
        &row,
        args,
    )
}

/// The parts of one approval request the attention coordinator reads.
fn attention_request(request: &Map<String, Value>) -> Value {
    let mut kept = Map::new();
    for key in ["request_id", "approval_url", "workspace"] {
        if let Some(value) = request.get(key).filter(|value| value.is_string()) {
            kept.insert(key.to_owned(), value.clone());
        }
    }
    let signals = request
        .get("decision_v2_json")
        .and_then(|decision| decision.get("signals"))
        .and_then(Value::as_array);
    if let Some(signals) = signals {
        let severities: Vec<Value> = signals
            .iter()
            .filter_map(|signal| signal.get("severity").filter(|value| value.is_string()))
            .map(|severity| json!({ "severity": severity }))
            .collect();
        kept.insert(
            "decision_v2_json".to_owned(),
            json!({ "signals": severities }),
        );
    }
    Value::Object(kept)
}

/// `_take_attention`: queued attention rows in operation-id order, removed in
/// the same write that reads them. One take returns at most
/// [`ATTENTION_BATCH_BYTES`] of row text so the answer always fits the store
/// client's response limit; the rest stays queued for the next take. A take
/// always returns its first row whatever its size, so no queued row is ever
/// dropped undelivered. A row whose
/// text is not a JSON object is removed without being returned.
fn take_attention(connection: &Connection) -> StoreResult<Value> {
    let pattern = [Value::from(format!(
        "{}%",
        ATTENTION_PREFIX.replace('_', "\\_")
    ))];
    let mut taken = Vec::new();
    let mut removed = Vec::new();
    let mut used = 0usize;
    query_each(
        connection,
        "select state_key, payload_json from sync_state \
         where state_key like ? escape '\\' order by state_key",
        &pattern,
        |row| {
            let payload = text(&row, "payload_json");
            if used > 0 && used + payload.len() > ATTENTION_BATCH_BYTES {
                return Ok(false);
            }
            used += payload.len();
            if let Ok(value) = serde_json::from_str::<Value>(payload) {
                if value.is_object() {
                    taken.push(value);
                }
            }
            removed.push(Value::from(text(&row, "state_key")));
            Ok(true)
        },
    )?;
    for keys in removed.chunks(DELETE_CHUNK) {
        exec(
            connection,
            &format!(
                "delete from sync_state where state_key in ({})",
                placeholders(keys.len())
            ),
            keys,
        )?;
    }
    Ok(Value::Array(taken))
}

/// The worker host's answer to the refresh request with this nonce, if it
/// has answered: `{running, sync_running}`, else `null`.
fn refresh_status(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    let nonce = text_arg(args, "nonce", "invalid_nonce")?;
    let Some(status) = read_payload(connection, REFRESH_STATUS_KEY)? else {
        return Ok(Value::Null);
    };
    if status.get("nonce").and_then(Value::as_str) != Some(nonce) {
        return Ok(Value::Null);
    }
    Ok(json!({
        "running": status.get("running") == Some(&Value::Bool(true)),
        "sync_running": status.get("sync_running") == Some(&Value::Bool(true)),
    }))
}

/// The pending refresh request's nonce, removing the request; `null` when no
/// well-formed request is waiting. A malformed request is left in place.
fn take_refresh_request(connection: &Connection) -> StoreResult<Value> {
    let nonce = read_payload(connection, REFRESH_REQUEST_KEY)?.and_then(|request| {
        request
            .get("nonce")
            .and_then(Value::as_str)
            .map(str::to_owned)
    });
    let Some(nonce) = nonce else {
        return Ok(Value::Null);
    };
    exec(
        connection,
        "delete from sync_state where state_key = ?",
        &[Value::from(REFRESH_REQUEST_KEY)],
    )?;
    Ok(Value::String(nonce))
}

#[cfg(test)]
#[path = "guard_store_worker_host_tests.rs"]
mod tests;
