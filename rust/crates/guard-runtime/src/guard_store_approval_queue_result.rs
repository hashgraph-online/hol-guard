//! Queue-aware single-request resolutions:
//! `GuardStore.resolve_request_with_queue_result` (the dashboard decision)
//! and `GuardStore.resolve_native_workspace_review_request` (a decision the
//! resident already claimed for a workspace review). Each resolves one
//! pending request and its resolvable duplicates in the caller's write
//! transaction, then reports what remains of the queue. The approval gate and
//! the receipt checks that need no store stay with the caller, which runs them
//! before the call.

use rusqlite::Connection;
use serde_json::{json, Map, Value};

use crate::guard_store_approval_page_reads::{
    get_next_pending_request, summary, ORDER, SUMMARY_COLUMNS,
};
use crate::guard_store_approval_read_scope::project;
use crate::guard_store_approval_reads::get_approval_request;
use crate::guard_store_approval_resolve::{resolve_duplicates, set_resolution};
use crate::guard_store_approval_sweep::{resolution, resolution_block_reason};
use crate::guard_store_args::Args;
use crate::guard_store_db::{exec, query_all, query_one, value_error, StoreError, StoreResult};
use crate::guard_store_json::dumps_sorted;
use crate::policy_store::PolicySnapshotStore;
use crate::MAX_NATIVE_RESPONSE_BYTES;

/// `exact_cloud_review.EXACT_CLOUD_REVIEW_REVOCATION_STATE_KEY`.
const REVOCATION_STATE_KEY: &str = "guard_exact_cloud_review_revocation";
const RECEIPT_STATE_PREFIX: &str = "native_workspace_review.receipt:";
const RECEIPT_BINDINGS: [&str; 12] = [
    "claim_id",
    "workspace_binding",
    "device_binding",
    "installation_binding",
    "scope_binding",
    "request_binding",
    "action_binding",
    "intent_binding",
    "revision_binding",
    "policy_binding",
    "retry_scope_binding",
    "request_snapshot_digest",
];
const WORKSPACE_REVIEW_REASON: &str = "Native workspace review decision";
/// `_REMAINING_SUMMARIES`.
const REMAINING_SUMMARIES: usize = 10;
/// The reply, leaving room for the response envelope.
const REPLY_LIMIT_BYTES: usize = MAX_NATIVE_RESPONSE_BYTES - 64 * 1024;

/// `resolve_request_with_queue_result`.
pub(crate) fn resolve_request_with_queue_result(
    connection: &Connection,
    guard_home: &str,
    args: &Args<'_>,
    owner: Option<&PolicySnapshotStore>,
) -> StoreResult<Value> {
    let request_id = args.str("request_id")?;
    let resolution = resolution(args)?;
    fits(queue_result(
        connection,
        guard_home,
        request_id,
        &resolution,
        args.opt_str("cwd")?,
        owner,
    )?)
}

/// `resolve_native_workspace_review_request` after the caller validated the
/// decision, encoded the expected request snapshot and the receipt.
pub(crate) fn resolve_native_workspace_review_request(
    connection: &Connection,
    guard_home: &str,
    args: &Args<'_>,
    owner: Option<&PolicySnapshotStore>,
) -> StoreResult<Value> {
    let request_id = args.str("request_id")?;
    let action = args.str("resolution_action")?;
    let expected_snapshot = args.str("expected_snapshot")?;
    let resolved_at = args.str("resolved_at")?;
    let replayed = args.flag("native_replayed")?;
    let receipt_json = args.opt_str("native_receipt_json")?;
    let cwd = args.opt_str("cwd")?;
    let receipt = match receipt_json {
        None => None,
        Some(text) => Some(
            serde_json::from_str::<Value>(text)
                .map_err(|_| StoreError::Invalid("native_guard_store_args_invalid"))?,
        ),
    };
    if query_one(
        connection,
        "select 1 from sync_state where state_key = ?",
        &[Value::from(REVOCATION_STATE_KEY)],
    )?
    .is_some()
    {
        return Ok(refused("native_workspace_review_cloud_review_disabled"));
    }
    let Value::Object(current) = request(connection, guard_home, request_id, cwd, owner)? else {
        return Ok(refused("native_workspace_review_request_missing"));
    };
    match current.get("status").and_then(Value::as_str) {
        Some("resolved") => {
            if let Some(receipt) = &receipt {
                let previous = stored_receipt(connection, request_id)?;
                if !replayed || !same_consumed_decision(previous.as_ref(), receipt) {
                    return Ok(refused("native_workspace_review_request_resolved"));
                }
            }
            if current.get("resolution_action").and_then(Value::as_str) == Some(action)
                && current.get("resolution_scope").and_then(Value::as_str) == Some("artifact")
            {
                return Ok(json!({
                    "resolved": true,
                    "replayed": true,
                    "resolved_request": current,
                    "resolved_duplicate_ids": [],
                }));
            }
            return Ok(refused("native_workspace_review_request_resolved"));
        }
        Some("pending") => {}
        _ => return Ok(refused("native_workspace_review_request_not_pending")),
    }
    let current = Value::Object(current);
    let Some(snapshot) = dumps_sorted(&current) else {
        return Ok(refused("native_workspace_review_request_invalid"));
    };
    if snapshot != expected_snapshot {
        return Ok(refused("native_workspace_review_request_stale"));
    }
    if block_reason(&current).is_some() {
        return Ok(refused("native_workspace_review_request_invalid"));
    }
    let resolution = [
        Value::from(action),
        Value::from("artifact"),
        Value::from(WORKSPACE_REVIEW_REASON),
        Value::from(resolved_at),
    ];
    let mut result = queue_result(connection, guard_home, request_id, &resolution, cwd, owner)?;
    if let (Value::Bool(true), Some(receipt_json)) = (&result["resolved"], receipt_json) {
        exec(
            connection,
            "insert into sync_state (state_key, payload_json, updated_at) values (?, ?, ?)",
            &[
                Value::from(format!("{RECEIPT_STATE_PREFIX}{request_id}")),
                Value::from(receipt_json),
                Value::from(resolved_at),
            ],
        )?;
    }
    result["native_replayed"] = Value::Bool(replayed);
    fits(result)
}

/// The reply goes out after the commit. One too large to send fails here, so
/// the caller's transaction rolls the resolution back instead of committing a
/// decision the dashboard never hears about.
pub(crate) fn fits(reply: Value) -> StoreResult<Value> {
    if serde_json::to_vec(&reply).map_or(usize::MAX, |bytes| bytes.len()) > REPLY_LIMIT_BYTES {
        return value_error("approval_queue_result_too_large");
    }
    Ok(reply)
}

/// The Python `resolve_request_with_queue_result` body: resolve the pending
/// request, then every resolvable pending duplicate of its queue group and
/// OAuth source, and report the queue that remains.
pub(crate) fn queue_result(
    connection: &Connection,
    guard_home: &str,
    request_id: &str,
    resolution: &[Value; 4],
    cwd: Option<&str>,
    owner: Option<&PolicySnapshotStore>,
) -> StoreResult<Value> {
    let Value::Object(item) = request(connection, guard_home, request_id, cwd, owner)? else {
        return unresolved(connection, guard_home, cwd, "not_found", Value::Null, owner);
    };
    let item = Value::Object(item);
    if item["status"] != "pending" {
        return unresolved(connection, guard_home, cwd, "already_resolved", item, owner);
    }
    if let Some(reason) = block_reason(&item) {
        return unresolved(connection, guard_home, cwd, reason, item, owner);
    }
    if set_resolution(connection, request_id, resolution.clone(), true)? != 1 {
        return unresolved(connection, guard_home, cwd, "already_resolved", item, owner);
    }
    let duplicate_ids = match item["queue_group_id"].as_str() {
        Some(queue_group_id) => resolve_duplicates(
            connection,
            guard_home,
            queue_group_id,
            Value::from(item["oauth_source"].as_str()),
            request_id,
            resolution,
        )?,
        None => Vec::new(),
    };
    let updated = request(connection, guard_home, request_id, cwd, owner)?;
    let mut excluded = vec![request_id];
    excluded.extend(duplicate_ids.iter().map(String::as_str));
    let next = next_pending(connection, guard_home, &excluded, cwd, owner)?;
    let (summaries, remaining) = pending_summaries(connection, guard_home)?;
    Ok(json!({
        "resolved": true,
        "item": updated,
        "resolved_request": updated,
        "remaining_pending_count": remaining,
        "next_selectable_request_id": next,
        "remaining_pending_summaries": summaries,
        "resolved_duplicate_ids": duplicate_ids,
        "resolution_summary": resolution_summary(remaining),
        "retry_hint": "Retry the action in your AI assistant if you approved it.",
    }))
}

/// `_unresolved_queue_result`.
pub(crate) fn unresolved(
    connection: &Connection,
    guard_home: &str,
    cwd: Option<&str>,
    error: &str,
    item: Value,
    owner: Option<&PolicySnapshotStore>,
) -> StoreResult<Value> {
    let (summaries, remaining) = pending_summaries(connection, guard_home)?;
    let next = next_pending(connection, guard_home, &[], cwd, owner)?;
    Ok(json!({
        "resolved": false,
        "error": error,
        "item": item,
        "remaining_pending_count": remaining,
        "next_selectable_request_id": next,
        "remaining_pending_summaries": summaries,
        "resolved_duplicate_ids": [],
        "resolution_summary": "Request was not resolved.",
        "retry_hint": "Refresh the approval queue and choose an active request.",
    }))
}

/// `get_approval_request(connection, request_id)`: the derived payload, or
/// null when no row has the id.
pub(crate) fn request(
    connection: &Connection,
    guard_home: &str,
    request_id: &str,
    cwd: Option<&str>,
    owner: Option<&PolicySnapshotStore>,
) -> StoreResult<Value> {
    let args = Map::from_iter([
        ("request_id".to_owned(), Value::from(request_id)),
        ("derive_scope".to_owned(), Value::Bool(true)),
        ("cwd".to_owned(), Value::from(cwd)),
    ]);
    get_approval_request(connection, guard_home, &Args(&args), owner)
}

/// The id of the newest pending payload among the first candidates that is
/// not excluded, as `get_next_pending_request` picks it.
fn next_pending(
    connection: &Connection,
    guard_home: &str,
    excluded: &[&str],
    cwd: Option<&str>,
    owner: Option<&PolicySnapshotStore>,
) -> StoreResult<Value> {
    let args = Map::from_iter([
        ("exclude_ids".to_owned(), Value::from(excluded.to_vec())),
        ("cwd".to_owned(), Value::from(cwd)),
    ]);
    let next = get_next_pending_request(connection, guard_home, &Args(&args), owner)?;
    Ok(next.get("request_id").cloned().unwrap_or(Value::Null))
}

/// `_pending_summaries`: the first pending summaries and the pending count.
/// Every fetched row is projected, then summarized, before the extra one is
/// dropped, as the Python read did.
fn pending_summaries(connection: &Connection, guard_home: &str) -> StoreResult<(Vec<Value>, i64)> {
    let rows = query_all(
        connection,
        &format!(
            "select {SUMMARY_COLUMNS} from approval_requests where status = 'pending' {ORDER} limit ?"
        ),
        &[Value::from(REMAINING_SUMMARIES + 1)],
    )?;
    let projections = rows
        .iter()
        .map(|row| project(row, guard_home))
        .collect::<StoreResult<Vec<_>>>()?;
    let mut summaries = rows
        .iter()
        .zip(&projections)
        .map(|(row, projection)| summary(row, projection).map(Value::Object))
        .collect::<StoreResult<Vec<_>>>()?;
    summaries.truncate(REMAINING_SUMMARIES);
    let total = query_one(
        connection,
        "select count(*) as total from approval_requests where status = 'pending'",
        &[],
    )?
    .and_then(|row| row.get("total").and_then(Value::as_i64))
    .unwrap_or(0);
    Ok((summaries, total))
}

/// `approval_resolution_block_reason` for a request payload.
pub(crate) fn block_reason(request: &Value) -> Option<&'static str> {
    resolution_block_reason(&json!({
        "contract_error": request.get("decision_contract_error").cloned().unwrap_or(Value::Null),
        "policy_action": request.get("policy_action").cloned().unwrap_or(Value::Null),
    }))
}

/// `_resolution_summary`.
fn resolution_summary(remaining: i64) -> String {
    match remaining {
        0 => "Decision saved. No blocked actions remain.".to_owned(),
        1 => "Decision saved. 1 blocked action remains.".to_owned(),
        count => format!("Decision saved. {count} blocked actions remain."),
    }
}

fn refused(error: &str) -> Value {
    json!({"resolved": false, "error": error})
}

/// The receipt stored when the request was first resolved; text that is not
/// JSON reads as no receipt.
fn stored_receipt(connection: &Connection, request_id: &str) -> StoreResult<Option<Value>> {
    let row = query_one(
        connection,
        "select payload_json from sync_state where state_key = ?",
        &[Value::from(format!("{RECEIPT_STATE_PREFIX}{request_id}"))],
    )?;
    Ok(row
        .and_then(|row| {
            row.get("payload_json")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .and_then(|text| serde_json::from_str(&text).ok()))
}

/// `_same_consumed_decision`: the stored receipt is an object with the same
/// decision and bindings.
fn same_consumed_decision(previous: Option<&Value>, current: &Value) -> bool {
    let Some(Value::Object(stored)) = previous else {
        return false;
    };
    let field =
        |map: &Map<String, Value>, name: &str| map.get(name).cloned().unwrap_or(Value::Null);
    let Value::Object(current) = current else {
        return false;
    };
    ["decision"]
        .into_iter()
        .chain(RECEIPT_BINDINGS)
        .all(|name| field(stored, name) == field(current, name))
}

#[cfg(all(test, unix))]
#[path = "guard_store_approval_queue_result_tests.rs"]
mod tests;
