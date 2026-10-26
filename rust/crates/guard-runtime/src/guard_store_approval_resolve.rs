//! Single-request and duplicate-group approval resolutions:
//! `GuardStore.resolve_approval_request`, `resolve_one_request_only`,
//! `resolve_harness_native_approval_request` and
//! `resolve_matching_duplicate_requests`. Each runs in the caller's write
//! transaction; the approval gate stays with the caller, which checks it
//! before the resolution.

use rusqlite::Connection;
use serde_json::Value;

use crate::guard_store_approval_page_reads::ORDER;
use crate::guard_store_approval_read_scope::project;
use crate::guard_store_approval_sweep::{
    resolution, resolution_block_reason, resolvable_ids, resolve_ids,
};
use crate::guard_store_approval_write::oauth_source;
use crate::guard_store_args::Args;
use crate::guard_store_db::{exec, query_all, query_one, text, value_error, Row, StoreResult};
use crate::guard_store_json::py_strip;
use crate::MAX_NATIVE_RESPONSE_BYTES;

/// The reported duplicate ids, leaving room for the response envelope.
const REPLY_LIMIT_BYTES: usize = MAX_NATIVE_RESPONSE_BYTES - 64 * 1024;
const REQUEST_COLUMNS: &str =
    "request_id, harness, artifact_id, artifact_hash, status, policy_action, \
     decision_v2_json, action_envelope_json";

/// The stored request and why it cannot accept a user resolution, if it
/// cannot. A request the resident cannot project fails the call.
fn load(
    connection: &Connection,
    guard_home: &str,
    request_id: &str,
) -> StoreResult<Option<(Row, Option<&'static str>)>> {
    let Some(row) = query_one(
        connection,
        &format!("select {REQUEST_COLUMNS} from approval_requests where request_id = ?"),
        &[Value::from(request_id)],
    )?
    else {
        return Ok(None);
    };
    let blocked = resolution_block_reason(&project(&row, guard_home)?);
    Ok(Some((row, blocked)))
}

pub(crate) fn set_resolution(
    connection: &Connection,
    request_id: &str,
    resolution: [Value; 4],
    pending_only: bool,
) -> StoreResult<i64> {
    let guard = if pending_only {
        " and status = 'pending'"
    } else {
        ""
    };
    let mut params = resolution.to_vec();
    params.push(Value::from(request_id));
    exec(
        connection,
        &format!(
            "update approval_requests set status = 'resolved', resolution_action = ?, \
             resolution_scope = ?, reason = ?, resolved_at = ? where request_id = ?{guard}"
        ),
        &params,
    )
}

/// `resolve_approval_request` (`pending_only` false: resolves the row in any
/// status and reports nothing) and `resolve_one_request_only` (true: reports
/// whether a pending row was resolved). A terminal or inconsistent row is
/// refused with its block reason.
pub(crate) fn resolve_approval_request(
    connection: &Connection,
    guard_home: &str,
    args: &Args<'_>,
    pending_only: bool,
) -> StoreResult<Value> {
    let request_id = args.str("request_id")?;
    let resolution = resolution(args)?;
    if let Some((_, Some(reason))) = load(connection, guard_home, request_id)? {
        return value_error(reason);
    }
    let changed = set_resolution(connection, request_id, resolution, pending_only)?;
    Ok(if pending_only {
        Value::Bool(changed == 1)
    } else {
        Value::Null
    })
}

/// `resolve_harness_native_approval_request`: an artifact-scoped allow after
/// a verified harness-native accept. Anything but a resolvable pending row of
/// the expected harness, artifact and hash reports false.
pub(crate) fn resolve_harness_native_approval_request(
    connection: &Connection,
    guard_home: &str,
    args: &Args<'_>,
) -> StoreResult<Value> {
    let request_id = args.str("request_id")?;
    if py_strip(request_id).is_empty() {
        return Ok(Value::Bool(false));
    }
    let Some((row, None)) = load(connection, guard_home, request_id)? else {
        return Ok(Value::Bool(false));
    };
    let expected = |column: &str, key: &str| -> StoreResult<bool> {
        Ok(args
            .opt_str(key)?
            .is_none_or(|expected| text(&row, column) == expected))
    };
    if text(&row, "status") != "pending"
        || text(&row, "harness") != args.str("expected_harness")?
        || !expected("artifact_id", "expected_artifact_id")?
        || !expected("artifact_hash", "expected_artifact_hash")?
    {
        return Ok(Value::Bool(false));
    }
    exec(
        connection,
        "update approval_requests set status = 'resolved', resolution_action = 'allow', \
         resolution_scope = 'artifact', reason = ?, resolved_at = ? where request_id = ?",
        &[
            Value::from(args.opt_str("reason")?),
            Value::from(args.str("resolved_at")?),
            Value::from(request_id),
        ],
    )?;
    Ok(Value::Bool(true))
}

/// `resolve_matching_duplicate_requests`: every other resolvable pending
/// request of the queue group from this store's source, all reported.
pub(crate) fn resolve_matching_duplicate_requests(
    connection: &Connection,
    source: &str,
    guard_home: &str,
    args: &Args<'_>,
) -> StoreResult<Value> {
    let resolution = resolution(args)?;
    let Some(queue_group_id) = args.opt_str("queue_group_id")? else {
        return Ok(Value::Array(Vec::new()));
    };
    let ids = resolve_duplicates(
        connection,
        guard_home,
        queue_group_id,
        Value::from(oauth_source(source)),
        args.str("request_id")?,
        &resolution,
    )?;
    Ok(Value::from(ids))
}

/// Resolves every other resolvable pending request of the queue group and
/// OAuth source (`None` matches a null source) and returns their ids.
pub(crate) fn resolve_duplicates(
    connection: &Connection,
    guard_home: &str,
    queue_group_id: &str,
    oauth_source: Value,
    request_id: &str,
    resolution: &[Value; 4],
) -> StoreResult<Vec<String>> {
    let rows = query_all(
        connection,
        &format!(
            "select request_id, policy_action, decision_v2_json, action_envelope_json \
             from approval_requests where queue_group_id = ? and oauth_source is ? \
             and request_id != ? and status = 'pending' {ORDER}"
        ),
        &[
            Value::from(queue_group_id),
            oauth_source,
            Value::from(request_id),
        ],
    )?;
    let ids = resolvable_ids(&rows, guard_home)?;
    // The reply goes out after the commit; a list too large to send fails
    // here, before anything is written.
    if serde_json::to_vec(&ids).map_or(usize::MAX, |bytes| bytes.len()) > REPLY_LIMIT_BYTES {
        return value_error("approval_duplicate_group_too_large");
    }
    resolve_ids(connection, &ids, resolution)?;
    Ok(ids)
}

#[cfg(all(test, unix))]
#[path = "guard_store_approval_resolve_tests.rs"]
mod tests;
