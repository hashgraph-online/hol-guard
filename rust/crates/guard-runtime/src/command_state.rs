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
//! The two operations that sign or verify a grant use the policy integrity
//! key. A home kept in the plain encrypted-file vault asks for `vault_key`, and
//! the ledger reads the key from that vault itself, so it never crosses the
//! request; any other caller passes its own copy. The caller still writes the
//! audit events itself. Error codes are the Python ones where one existed,
//! because `hol-guard commands approve` and the job results surface them.

use std::io::Read;
use std::path::PathBuf;

use guard_contracts::utc_timestamp_micros;
use rusqlite::Connection;
use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::command_capability_op::{envelope_digest, sign_envelope, verify_signed_envelope};
use crate::command_queue_repair::queue_repair;
use crate::sync_state_ledger::{
    delete_payload, read_payload, write_payload, LedgerCodes, SyncStateLedger,
};
use key::SigningKey;

pub(crate) const COMMAND: &str = "command-state";
pub(crate) const FEATURE: &str = "native-command-state-v4";
const SCHEMA: &str = "command-state.v1";
const MAX_REQUEST_BYTES: u64 = 1024 * 1024;

const PENDING_KEY: &str = "guard_command_pending_approvals_v1";
const LOCAL_APPROVALS_KEY: &str = "guard_command_local_approvals_v1";
const REPLAY_KEY: &str = "guard_command_replay_state_v1";
const CAPABILITY_KEY: &str = "guard_command_capability_v1";
const QUEUE_RUNTIME_KEY: &str = "guard_command_queue_state";
/// Every row `clear` removes when the user revokes the command capability.
const CLEARED_KEYS: [&str; 5] = [
    CAPABILITY_KEY,
    LOCAL_APPROVALS_KEY,
    PENDING_KEY,
    REPLAY_KEY,
    QUEUE_RUNTIME_KEY,
];
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

pub(crate) const INVALID: &str = "command_state_request_invalid";
pub(crate) const UNAVAILABLE: &str = "command_state_unavailable";
pub(crate) const UNREADABLE: &str = "command_state_unreadable";
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
    /// Read the key from `guard_home`'s own vault instead. A request that
    /// also names a key or a key id is refused.
    #[serde(default)]
    vault_key: bool,
    /// `consume` also records the job's replay row, in the same transaction
    /// that spends the grant, so a spent grant never lacks its replay row.
    #[serde(default)]
    record_replay: bool,
    /// `replay_rows`: the job or replay identity a verdict will be asked
    /// about. Anything but an object keeps every row.
    #[serde(default)]
    subject: Option<Value>,
    /// `issue`: the signed capability envelope to install.
    #[serde(default)]
    capability: Option<Map<String, Value>>,
    /// `queue_repair`: the queue lane's state row. The main worker's row when
    /// absent.
    #[serde(default)]
    state_key: Option<String>,
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
    let key = key::signing_key(request)?;
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
        "approve" => ledger.transact(|tx| approve(tx, request, &key, now)),
        "consume" => ledger.transact(|tx| consume(tx, request, &key, now).map(Value::Bool)),
        "mark_consumed" => ledger.transact(|tx| mark_consumed(tx, request, now)),
        "replay_rows" if !ledger.store_exists() => Ok(Value::Array(Vec::new())),
        "replay_rows" => ledger.transact(|tx| replay_rows(tx, request.subject.as_ref())),
        "clear" if !ledger.store_exists() => Ok(Value::Null),
        "clear" => ledger.transact(clear),
        "issue" => ledger.transact(|tx| issue(tx, request)),
        "queue_repair" if !ledger.store_exists() => Ok(json!({"repaired": []})),
        "queue_repair" => {
            ledger.transact(|tx| queue_repair(tx, request.state_key.as_deref(), &request.now))
        }
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
fn approve(
    conn: &Connection,
    request: &Request,
    key: &SigningKey,
    now: i64,
) -> Result<Value, String> {
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
        key.b64(),
        key.id(),
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
fn consume(
    conn: &Connection,
    request: &Request,
    key: &SigningKey,
    now: i64,
) -> Result<bool, String> {
    let identity = identity(request)?;
    let digest = identity_digest(request, identity)?;
    let mut items = state_items(conn, LOCAL_APPROVALS_KEY)?;
    let (key, key_id) = (key.b64(), key.id());
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

/// `issue_command_capability`: installs a newly signed capability. A new
/// capability never inherits a queue result, an active lease, a grant or a
/// waiting job from the queue before it, so those go in the same
/// transaction. Replay rows stay: a job that already ran must not run again.
fn issue(conn: &Connection, request: &Request) -> Result<Value, String> {
    let capability = request.capability.clone().ok_or(INVALID)?;
    write_payload(
        conn,
        CAPABILITY_KEY,
        &Value::Object(capability),
        &request.now,
    )
    .map_err(|()| UNAVAILABLE.to_owned())?;
    for key in [QUEUE_RUNTIME_KEY, LOCAL_APPROVALS_KEY, PENDING_KEY] {
        delete_payload(conn, key).map_err(|()| UNAVAILABLE.to_owned())?;
    }
    Ok(Value::Null)
}

/// The replay rows a verdict about `subject` could match.
///
/// The capability verdict matches a row by identity digest, job id or
/// idempotency key. Every row records the id and key of the identity its
/// digest covers, so a row naming neither of the subject's values cannot
/// match by any of the three. Rows missing either field are kept for the
/// verdict to judge, and a subject that is not an object keeps them all so
/// the verdict refuses it.
fn replay_rows(conn: &Connection, subject: Option<&Value>) -> Result<Value, String> {
    let items = state_items(conn, REPLAY_KEY)?;
    let Some(subject) = subject.and_then(Value::as_object) else {
        return Ok(Value::Array(items.into_iter().map(Value::Object).collect()));
    };
    let names: Vec<&str> = ["id", "idempotencyKey"]
        .iter()
        .filter_map(|field| subject.get(*field).and_then(Value::as_str))
        .flat_map(|value| [value, value.trim()])
        .collect();
    let named = |item: &Map<String, Value>, field: &str| {
        item.get(field)
            .and_then(Value::as_str)
            .is_some_and(|value| names.contains(&value))
    };
    Ok(Value::Array(
        items
            .into_iter()
            .filter(|item| {
                !item.get("jobId").is_some_and(Value::is_string)
                    || !item.get("idempotencyKey").is_some_and(Value::is_string)
                    || named(item, "jobId")
                    || named(item, "idempotencyKey")
            })
            .map(Value::Object)
            .collect(),
    ))
}

/// `revoke_command_capability`: drops the capability and every row of the
/// ledger in one transaction, so no reader sees a revoked capability with
/// grants or pending jobs still beside it.
fn clear(conn: &Connection) -> Result<Value, String> {
    for key in CLEARED_KEYS {
        delete_payload(conn, key).map_err(|()| UNAVAILABLE.to_owned())?;
    }
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

#[path = "command_state_key.rs"]
mod key;

#[cfg(test)]
#[path = "command_state_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "command_state_key_tests.rs"]
mod key_tests;

#[cfg(test)]
#[path = "command_state_replay_tests.rs"]
mod replay_tests;

#[cfg(test)]
#[path = "command_queue_repair_tests.rs"]
mod queue_repair_tests;
