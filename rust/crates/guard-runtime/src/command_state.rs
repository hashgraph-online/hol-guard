//! `command-state --stdin`: the local ledger behind Guard Cloud's command
//! queue.
//!
//! Port of the state half of `runtime/command_capability.py`: the jobs waiting
//! for a local confirmation, the signed grants a user writes when they confirm
//! one, and the replay rows that keep a leased job from running twice. Each row
//! list is read, changed and written back whole, so every operation runs in one
//! immediate SQLite transaction. That makes each change atomic across processes,
//! where the Python ledger only serialized the threads of one process.
//!
//! The caller reads the policy integrity key out of its secret store and passes
//! it for the two operations that sign or verify a grant. It still writes the
//! audit events itself. Error codes are the Python ones where one existed,
//! because `hol-guard commands approve` and the job results surface them.

use std::io::Read;
use std::path::PathBuf;

use guard_contracts::utc_timestamp_micros;
use rusqlite::Connection;
use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::command_capability_op::{envelope_digest, sign_envelope, verify_signed_envelope};
use crate::sync_state_ledger::{read_payload, write_payload, LedgerCodes, SyncStateLedger};

pub(crate) const COMMAND: &str = "command-state";
pub(crate) const FEATURE: &str = "native-command-state-v1";
const SCHEMA: &str = "command-state.v1";
const MAX_REQUEST_BYTES: u64 = 1024 * 1024;

const PENDING_KEY: &str = "guard_command_pending_approvals_v1";
const LOCAL_APPROVALS_KEY: &str = "guard_command_local_approvals_v1";
const REPLAY_KEY: &str = "guard_command_replay_state_v1";
const APPROVALS_MAX_ITEMS: usize = 64;
const REPLAY_MAX_ITEMS: usize = 512;

/// The identity fields a grant names, in `approve_pending_command`'s order.
const GRANT_IDENTITY_FIELDS: [&str; 9] = [
    "id",
    "operation",
    "schemaVersion",
    "deviceId",
    "workspaceId",
    "nonce",
    "expiresAt",
    "idempotencyKey",
    "payloadDigest",
];

const INVALID: &str = "command_state_request_invalid";
const UNAVAILABLE: &str = "command_state_unavailable";
const UNREADABLE: &str = "command_state_unreadable";
const BUSY: &str = "command_state_busy";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    schema: String,
    guard_home: PathBuf,
    op: String,
    /// The caller's clock, already in the ISO form the rows store.
    now: String,
    #[serde(default)]
    identity: Option<Map<String, Value>>,
    /// The digest the caller already holds for `identity`. When present it
    /// must match the one computed here.
    #[serde(default)]
    identity_digest: Option<String>,
    #[serde(default)]
    operation: Option<String>,
    #[serde(default)]
    job_id: Option<String>,
    #[serde(default)]
    issuer: Option<String>,
    #[serde(default)]
    approve_command: Option<String>,
    #[serde(default)]
    integrity_key_b64: Option<String>,
    #[serde(default)]
    integrity_key_id: Option<String>,
    /// `consume` also records the job's replay row, in the same transaction
    /// that spends the grant, so a spent grant never lacks its replay row.
    #[serde(default)]
    record_replay: bool,
}

pub(crate) fn is_command(command: &str) -> bool {
    command == COMMAND
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "command_state_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("command_state_request_too_large".to_owned());
    }
    let request: Request = serde_json::from_slice(&bytes).map_err(|_| INVALID.to_owned())?;
    let response = match handle(&request) {
        Ok(result) => json!({"ok": true, "result": result}),
        Err(code) => json!({"ok": false, "error": code}),
    };
    serde_json::to_vec(&response).map_err(|_| "command_state_response_encode_failed".to_owned())
}

pub(crate) fn handle(request: &Request) -> Result<Value, String> {
    if request.schema != SCHEMA {
        return Err(INVALID.to_owned());
    }
    let now = utc_timestamp_micros(request.now.trim()).ok_or("invalid_current_time")?;
    let ledger = SyncStateLedger::new(
        &request.guard_home,
        LedgerCodes {
            busy: BUSY,
            unavailable: UNAVAILABLE,
        },
    );
    match request.op.as_str() {
        // A home whose store was never created has nothing waiting. Only the
        // read answers that way; every write still needs the store.
        "pending" if !ledger.store_exists() => Ok(Value::Array(Vec::new())),
        "pending" => ledger.transact(|tx| Ok(Value::Array(pending(tx, now)?))),
        "register_pending" => ledger.transact(|tx| register_pending(tx, request)),
        "approve" => ledger.transact(|tx| approve(tx, request, now)),
        "consume" => ledger.transact(|tx| consume(tx, request, now).map(Value::Bool)),
        "mark_consumed" => ledger.transact(|tx| mark_consumed(tx, request, now)),
        _ => Err(INVALID.to_owned()),
    }
}

/// `_state_items(store.get_sync_payload(key))`: the object rows of a saved
/// `{"items": [...]}` payload, or none.
fn state_items(conn: &Connection, key: &str) -> Result<Vec<Map<String, Value>>, String> {
    let raw = read_payload(conn, key).map_err(|()| UNAVAILABLE.to_owned())?;
    let Some(raw) = raw else {
        return Ok(Vec::new());
    };
    let payload: Value = serde_json::from_str(&raw).map_err(|_| UNREADABLE.to_owned())?;
    let Some(items) = payload.get("items").and_then(Value::as_array) else {
        return Ok(Vec::new());
    };
    Ok(items
        .iter()
        .filter_map(|item| item.as_object().cloned())
        .collect())
}

/// `set_sync_payload(key, {"version": 1, "items": items[-limit:]}, now)`.
fn save_items(
    conn: &Connection,
    key: &str,
    mut items: Vec<Map<String, Value>>,
    limit: Option<usize>,
    now: &str,
) -> Result<(), String> {
    if let Some(limit) = limit {
        let excess = items.len().saturating_sub(limit);
        items.drain(..excess);
    }
    let payload = json!({"version": 1, "items": items});
    write_payload(conn, key, &payload, now).map_err(|()| UNAVAILABLE.to_owned())
}

fn unexpired(item: &Map<String, Value>, now: i64) -> bool {
    item.get("expiresAt")
        .and_then(Value::as_str)
        .and_then(|value| utc_timestamp_micros(value.trim()))
        .is_some_and(|expires| expires > now)
}

fn names_job(item: &Map<String, Value>, job_id: &Value) -> bool {
    item.get("id") == Some(job_id)
}

/// `pending_command_approvals`: the waiting jobs that have not expired.
fn pending(conn: &Connection, now: i64) -> Result<Vec<Value>, String> {
    Ok(state_items(conn, PENDING_KEY)?
        .into_iter()
        .filter(|item| unexpired(item, now))
        .map(Value::Object)
        .collect())
}

fn identity(request: &Request) -> Result<&Map<String, Value>, String> {
    let identity = request.identity.as_ref().ok_or(INVALID)?;
    match identity.get("id") {
        Some(Value::String(id)) if !id.is_empty() => Ok(identity),
        _ => Err(INVALID.to_owned()),
    }
}

/// The digest grants and replay rows name `identity` by. A digest the caller
/// computed earlier has to be this one, or it names some other job.
fn identity_digest(request: &Request, identity: &Map<String, Value>) -> Result<String, String> {
    let digest = envelope_digest(&Value::Object(identity.clone())).map_err(str::to_owned)?;
    match request.identity_digest.as_deref() {
        Some(claimed) if claimed != digest => Err("command_identity_digest_mismatch".to_owned()),
        _ => Ok(digest),
    }
}

/// `register_pending_command`: replaces any earlier row for the job.
fn register_pending(conn: &Connection, request: &Request) -> Result<Value, String> {
    let identity = identity(request)?;
    let issuer = request.issuer.as_deref().ok_or(INVALID)?;
    let approve_command = request.approve_command.as_deref().ok_or(INVALID)?;
    let job_id = &identity["id"];
    let mut items = state_items(conn, PENDING_KEY)?;
    items.retain(|item| !names_job(item, job_id));
    let mut item = identity.clone();
    item.insert("issuer".to_owned(), Value::from(issuer));
    item.insert("recordedAt".to_owned(), Value::from(request.now.as_str()));
    item.insert("approveCommand".to_owned(), Value::from(approve_command));
    items.push(item.clone());
    save_items(
        conn,
        PENDING_KEY,
        items,
        Some(APPROVALS_MAX_ITEMS),
        &request.now,
    )?;
    Ok(Value::Object(item))
}

/// `approve_pending_command`: signs a grant for one unexpired waiting job.
fn approve(conn: &Connection, request: &Request, now: i64) -> Result<Value, String> {
    let job_id = request.job_id.as_deref().ok_or(INVALID)?;
    let issuer = request.issuer.as_deref().ok_or(INVALID)?;
    let pending = pending(conn, now)?
        .into_iter()
        .find(|item| item.get("id").and_then(Value::as_str) == Some(job_id))
        .ok_or("pending_command_not_found")?;
    let mut identity = Map::new();
    for field in GRANT_IDENTITY_FIELDS {
        let value = pending.get(field).ok_or("pending_command_invalid")?;
        identity.insert(field.to_owned(), value.clone());
    }
    let digest = envelope_digest(&Value::Object(identity.clone())).map_err(str::to_owned)?;
    let grant = sign_envelope(
        &json!({
            "version": 1,
            "identity": identity,
            "identityDigest": digest,
            "issuer": issuer,
            "approvedAt": request.now,
        }),
        request.integrity_key_b64.as_deref(),
        request.integrity_key_id.as_deref(),
    )
    .map_err(str::to_owned)?;
    let mut items = state_items(conn, LOCAL_APPROVALS_KEY)?;
    items
        .retain(|item| item.get("identityDigest").and_then(Value::as_str) != Some(digest.as_str()));
    items.push(grant);
    save_items(
        conn,
        LOCAL_APPROVALS_KEY,
        items,
        Some(APPROVALS_MAX_ITEMS),
        &request.now,
    )?;
    Ok(json!({
        "approved": true,
        "job_id": job_id,
        "operation": identity["operation"],
        "issuer": issuer,
    }))
}

/// `consume_local_command_approval`: spends the grant that is genuine and
/// names exactly this identity, and drops the job's waiting row with it.
fn consume(conn: &Connection, request: &Request, now: i64) -> Result<bool, String> {
    let identity = identity(request)?;
    let digest = identity_digest(request, identity)?;
    let mut items = state_items(conn, LOCAL_APPROVALS_KEY)?;
    let key = request.integrity_key_b64.as_deref();
    let key_id = request.integrity_key_id.as_deref();
    let matched = items.iter().position(|item| {
        item.get("identityDigest").and_then(Value::as_str) == Some(digest.as_str())
            && verify_signed_envelope(&Value::Object(item.clone()), key, key_id).is_ok_and(
                |verified| {
                    verified
                        .get("identity")
                        .is_some_and(|named| py_equal(named, &Value::Object(identity.clone())))
                },
            )
    });
    let Some(index) = matched else {
        return Ok(false);
    };
    items.remove(index);
    save_items(conn, LOCAL_APPROVALS_KEY, items, None, &request.now)?;
    let mut waiting = state_items(conn, PENDING_KEY)?;
    waiting.retain(|item| !names_job(item, &identity["id"]));
    save_items(conn, PENDING_KEY, waiting, None, &request.now)?;
    if request.record_replay {
        // A refusal here rolls the whole transaction back, grant included.
        mark_consumed(conn, request, now)?;
    }
    Ok(true)
}

/// `mark_command_job_consumed`: records the job's replay row and drops rows
/// whose job has expired.
fn mark_consumed(conn: &Connection, request: &Request, now: i64) -> Result<Value, String> {
    let identity = identity(request)?;
    let operation = request.operation.as_deref().ok_or(INVALID)?;
    let digest = identity_digest(request, identity)?;
    let mut items = state_items(conn, REPLAY_KEY)?;
    items.retain(|item| unexpired(item, now));
    let field = |name: &str| identity.get(name).cloned().unwrap_or(Value::Null);
    let mut row = Map::new();
    row.insert("identityDigest".to_owned(), Value::from(digest));
    row.insert("jobId".to_owned(), field("id"));
    row.insert("idempotencyKey".to_owned(), field("idempotencyKey"));
    row.insert("operation".to_owned(), Value::from(operation));
    row.insert("expiresAt".to_owned(), field("expiresAt"));
    row.insert("consumedAt".to_owned(), Value::from(request.now.as_str()));
    items.push(row);
    save_items(
        conn,
        REPLAY_KEY,
        items,
        Some(REPLAY_MAX_ITEMS),
        &request.now,
    )?;
    Ok(Value::Null)
}

/// Python `==` over decoded JSON: an integer equals the same value written as
/// a float, which `serde_json::Value` equality does not allow.
fn py_equal(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Number(left), Value::Number(right)) => match (left.as_f64(), right.as_f64()) {
            (Some(left), Some(right)) => left == right,
            _ => left == right,
        },
        (Value::Array(left), Value::Array(right)) => {
            left.len() == right.len() && left.iter().zip(right).all(|(l, r)| py_equal(l, r))
        }
        (Value::Object(left), Value::Object(right)) => {
            left.len() == right.len()
                && left
                    .iter()
                    .all(|(key, value)| right.get(key).is_some_and(|other| py_equal(value, other)))
        }
        _ => left == right,
    }
}

#[cfg(test)]
#[path = "command_state_tests.rs"]
mod tests;
