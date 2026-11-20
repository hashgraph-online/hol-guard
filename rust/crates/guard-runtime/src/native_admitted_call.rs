//! The witness that one exact tool call ran on the user's approval.
//!
//! When a `PreToolUse` hook lets a reviewed call through because the user
//! chose Allow once or Always allow, the policy floor that sent it to review
//! (for example `subprocess_action: review`) still applies to the call's
//! `PostToolUse`. Without a witness, that hook would join the same floor
//! again and withhold the output of the action the user just approved.
//!
//! The witness is one `guard_continuation_effects` row keyed by the harness's
//! own call id and the tool name. `PostToolUse` reads it back for the same
//! call id and tool. The input is not part of the key: a host may present the
//! executed input differently afterwards (Oh My Pi reports a read's relative
//! path as an absolute one), and the call id already names that one
//! execution. A harness that documents no call id shared by both events gets
//! no witness, so its output keeps the floor.

use std::path::Path;

use guard_contracts::{write_canonical_json, GuardStoreRequestV1, GUARD_STORE_REQUEST_SCHEMA};
use rusqlite::Connection;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::guard_store_args::Args;
use crate::guard_store_db::{exec, query_all, StoreResult};
use crate::local_store_read::STORE_FILE_NAME;

const DOMAIN: &[u8] = b"hol-guard.native-admitted-call.v1\0";
const EVENT_NAME: &str = "native-review.call-admitted";
pub(crate) const RECORD_METHOD: &str = "record_native_admitted_call";
pub(crate) const LOOKUP_METHOD: &str = "native_admitted_call";
/// The longest a reviewed call may run before its output loses the witness.
const WINDOW_MICROS: i64 = 60 * 60 * 1_000_000;
const MAX_CALL_ID_BYTES: usize = 512;
const BUSY_TIMEOUT_MS: u64 = 250;
const PRUNE_BATCH: i64 = 64;

/// The top-level call id each harness sends unchanged on both `PreToolUse`
/// and `PostToolUse`, as `edge_identity` reads it. Codex stamps
/// `tool_use_id`, like Claude Code; it sends no `tool_call_id`.
/// Cursor is absent: its post-execution events are not `PostToolUse`.
const CALL_ID_FIELDS: [(&str, &str); 6] = [
    ("claude-code", "tool_use_id"),
    ("codex", "tool_use_id"),
    ("grok", "toolUseId"),
    ("zcode", "tool_use_id"),
    ("pi", "tool_call_id"),
    ("omp", "tool_call_id"),
];

/// The witness key for `payload`, or `None` when the call carries no proven
/// call id or tool name.
pub(crate) fn call_key(harness: &str, payload: &Map<String, Value>) -> Option<String> {
    let harness = harness.trim().to_ascii_lowercase().replace('_', "-");
    let field = CALL_ID_FIELDS
        .iter()
        .find(|(known, _)| *known == harness)?
        .1;
    let call_id = payload
        .get(field)?
        .as_str()
        .filter(|value| !value.trim().is_empty() && value.len() <= MAX_CALL_ID_BYTES)?;
    let tool_name = payload
        .get("tool_name")?
        .as_str()
        .filter(|value| !value.is_empty())?;
    let mut canonical = Vec::new();
    write_canonical_json(
        &json!({
            "harness": harness,
            "call_id": call_id,
            "tool_name": tool_name,
        }),
        &mut canonical,
    )
    .ok()?;
    let mut digest = Sha256::new();
    digest.update(DOMAIN);
    digest.update(&canonical);
    Some(hex::encode(digest.finalize()))
}

fn args_key(args: &Args) -> StoreResult<Option<(String, String)>> {
    let harness = args.str("harness")?;
    let Some(payload) = args.0.get("payload").and_then(Value::as_object) else {
        return Ok(None);
    };
    let Some(key) = call_key(harness, payload) else {
        return Ok(None);
    };
    let Some((_, now)) = crate::guard_store_native_review_consume::instant(Some(args.str("now")?))
    else {
        return Ok(None);
    };
    Ok(Some((key, now)))
}

/// `record_native_admitted_call`: writes the witness for an approved call.
/// `false` when the call has no witness key or already had one.
pub(crate) fn record(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let Some((key, now)) = args_key(args)? else {
        return Ok(json!(false));
    };
    prune_expired(connection, &now)?;
    let inserted = exec(
        connection,
        "insert or ignore into guard_continuation_effects \
         (effect_key, request_id, evidence_id, event_name, created_at) \
         values (?, ?, ?, ?, ?)",
        &[
            Value::from(key.clone()),
            Value::from(args.str("harness")?),
            Value::from(key),
            Value::from(EVENT_NAME),
            Value::from(now),
        ],
    )?;
    Ok(json!(inserted == 1))
}

/// Deletes up to `PRUNE_BATCH` of the oldest witnesses that have left the
/// window, so every approved call keeps the table bounded.
fn prune_expired(connection: &Connection, now: &str) -> StoreResult<()> {
    let Some((current, _)) = crate::guard_store_native_review_consume::instant(Some(now)) else {
        return Ok(());
    };
    let rows = query_all(
        connection,
        "select effect_key, created_at from guard_continuation_effects \
         where event_name = ? order by created_at limit ?",
        &[Value::from(EVENT_NAME), Value::from(PRUNE_BATCH)],
    )?;
    for row in rows {
        let expired = crate::guard_store_native_review_consume::instant(
            row.get("created_at").and_then(Value::as_str),
        )
        .is_none_or(|(at, _)| current - at > WINDOW_MICROS);
        if let (true, Some(key)) = (expired, row.get("effect_key").and_then(Value::as_str)) {
            exec(
                connection,
                "delete from guard_continuation_effects where effect_key = ? and event_name = ?",
                &[Value::from(key), Value::from(EVENT_NAME)],
            )?;
        }
    }
    Ok(())
}

/// `native_admitted_call`: whether this exact call was admitted on an
/// approval within the last hour. Reads only.
pub(crate) fn lookup(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let Some((key, now)) = args_key(args)? else {
        return Ok(json!(false));
    };
    let rows = query_all(
        connection,
        "select created_at from guard_continuation_effects \
         where effect_key = ? and event_name = ?",
        &[Value::from(key), Value::from(EVENT_NAME)],
    )?;
    let Some((current, _)) = crate::guard_store_native_review_consume::instant(Some(&now)) else {
        return Ok(json!(false));
    };
    let admitted = rows.iter().any(|row| {
        crate::guard_store_native_review_consume::instant(
            row.get("created_at").and_then(Value::as_str),
        )
        .is_some_and(|(at, _)| (0..=WINDOW_MICROS).contains(&(current - at)))
    });
    Ok(json!(admitted))
}

fn store_request(
    guard_home: &str,
    method: &str,
    harness: &str,
    payload: &Map<String, Value>,
) -> Option<GuardStoreRequestV1> {
    let now = crate::hook_direct::lifecycle::utc_now_isoformat()?;
    let mut args = Map::new();
    args.insert("harness".to_owned(), json!(harness));
    args.insert("payload".to_owned(), Value::Object(payload.clone()));
    args.insert("now".to_owned(), json!(now));
    Some(GuardStoreRequestV1 {
        schema: GUARD_STORE_REQUEST_SCHEMA.to_owned(),
        request_id: format!("hook-{method}"),
        store_path: Path::new(guard_home)
            .join(STORE_FILE_NAME)
            .to_string_lossy()
            .into_owned(),
        guard_home: guard_home.to_owned(),
        method: method.to_owned(),
        source: "default".to_owned(),
        busy_timeout_ms: BUSY_TIMEOUT_MS,
        args,
    })
}

/// Records that the hook admitted `payload` on an approval. Best effort: a
/// call without a witness keeps the policy floor on its output.
pub(crate) fn record_for_hook(guard_home: &str, harness: &str, payload: &Map<String, Value>) {
    if call_key(harness, payload).is_none() {
        return;
    }
    let Ok(_gate) =
        crate::hook_direct::saved_decision::consume::storage_gate(Path::new(guard_home))
    else {
        return;
    };
    if let Some(request) = store_request(guard_home, RECORD_METHOD, harness, payload) {
        let _ = crate::guard_store_op::evaluate(&request);
    }
}

/// Whether a `PostToolUse` belongs to a call its `PreToolUse` admitted on an
/// approval. Any failure answers `false`.
pub(crate) fn admitted_for_post(
    guard_home: &str,
    harness: &str,
    payload: &Map<String, Value>,
) -> bool {
    if call_key(harness, payload).is_none() {
        return false;
    }
    let Ok(_gate) =
        crate::hook_direct::saved_decision::consume::storage_gate(Path::new(guard_home))
    else {
        return false;
    };
    store_request(guard_home, LOOKUP_METHOD, harness, payload)
        .and_then(|request| crate::guard_store_op::evaluate(&request).ok())
        .is_some_and(|(payload, _)| payload == Value::Bool(true))
}

#[cfg(test)]
#[path = "native_admitted_call_tests.rs"]
mod tests;
