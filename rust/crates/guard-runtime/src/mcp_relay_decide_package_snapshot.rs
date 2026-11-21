//! The read-only snapshot rows the relayed package lane reads beside its
//! resolution: the approval request a saved row names, and the cached
//! advisory feed snapshot its approval context binds. Each reads the
//! snapshot the rest of the lane reads, with narrow read-only SQL, because
//! the resident's own store opens the file read-write and this lane must not.

use super::package_policy::RESOLVE_FAILED;
use super::store::Saved;
use crate::context_digest::python_strip;
use crate::local_store_read::table_exists;
use rusqlite::OptionalExtension;
use serde_json::{json, Map, Value};

/// The approval request row `decision.request_id` names, read as the six
/// columns the resolution's two approval checks read
/// (`is_fresh_artifact_approval`, `is_legacy_package_local_approval`). Each is
/// a plain pass-through column of `_row_to_payload`, so the narrow read
/// answers both checks exactly as the full row would.
///
/// `_approval_request` swallows a failed read and resolves without the row.
/// The relay defers instead: a row it could not read would decide the two
/// approval checks by its absence, and deferring is the answer the proxy
/// cannot give.
pub(super) fn approval_request(
    saved: &Saved<'_>,
    decision: &Value,
) -> Result<Option<Value>, &'static str> {
    let Some(request_id) = decision
        .get("request_id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
    else {
        return Ok(None);
    };
    const COLUMNS: [&str; 6] = [
        "artifact_id",
        "artifact_hash",
        "artifact_type",
        "status",
        "resolution_action",
        "resolution_scope",
    ];
    if !table_exists(saved.connection, "approval_requests").map_err(|_| RESOLVE_FAILED)? {
        return Ok(None);
    }
    let row = saved
        .connection
        .prepare_cached(&format!(
            "select {} from approval_requests where request_id = ?1 limit 1",
            COLUMNS.join(", ")
        ))
        .and_then(|mut statement| {
            statement
                .query_row([request_id], |row| {
                    let mut payload = Map::new();
                    for (index, column) in COLUMNS.iter().enumerate() {
                        let value: Option<String> = row.get(index)?;
                        payload.insert((*column).to_owned(), json!(value));
                    }
                    Ok(Value::Object(payload))
                })
                .optional()
        })
        .map_err(|_| RESOLVE_FAILED)?;
    Ok(row)
}
/// `_feed_snapshot_hash` (`native_package_approval_hash.py:83`): the cached
/// supply-chain bundle's feed snapshot, read with narrow read-only SQL on the
/// snapshot the rest of the lane reads. The resident's own store opens the
/// file read-write, which this lane must not do.
pub(super) fn feed_snapshot_hash(saved: &Saved<'_>) -> Result<Option<String>, &'static str> {
    let Some(workspace_id) = cloud_workspace_id(saved)? else {
        return Ok(None);
    };
    if !table_exists(saved.connection, "guard_supply_chain_bundle_cache")
        .map_err(|_| RESOLVE_FAILED)?
    {
        return Ok(None);
    }
    let cached: Option<String> = saved
        .connection
        .prepare_cached(
            "select response_json from guard_supply_chain_bundle_cache \
             where workspace_id = ?1 limit 1",
        )
        .and_then(|mut statement| {
            statement
                .query_row([&workspace_id], |row| row.get(0))
                .optional()
        })
        .map_err(|_| RESOLVE_FAILED)?;
    let Some(cached) = cached else {
        return Ok(None);
    };
    // `get_supply_chain_bundle` reads the row with `json.loads`, which raises
    // on a malformed payload rather than resolving without the feed snapshot.
    let payload = serde_json::from_str::<Value>(&cached).map_err(|_| RESOLVE_FAILED)?;
    Ok(payload
        .get("bundle")
        .filter(|bundle| bundle.is_object())
        .and_then(|bundle| bundle.get("feedSnapshotHash"))
        .and_then(Value::as_str)
        .filter(|hash| !hash.is_empty())
        .map(str::to_owned))
}

/// `_cloud_workspace_id_from_connection`: the workspace the cached bundle is
/// keyed by, from the local OAuth credential payload.
fn cloud_workspace_id(saved: &Saved<'_>) -> Result<Option<String>, &'static str> {
    if !table_exists(saved.connection, "sync_state").map_err(|_| RESOLVE_FAILED)? {
        return Ok(None);
    }
    let payload: Option<String> = saved
        .connection
        .prepare_cached(
            "select payload_json from sync_state \
             where state_key = 'oauth_local_credentials' limit 1",
        )
        .and_then(|mut statement| statement.query_row([], |row| row.get(0)).optional())
        .map_err(|_| RESOLVE_FAILED)?;
    let Some(payload) = payload else {
        return Ok(None);
    };
    // `_cloud_workspace_id_from_connection` also reads the credential payload
    // with `json.loads`, so a malformed row defers instead of reading as an
    // unpaired install.
    let payload = serde_json::from_str::<Value>(&payload).map_err(|_| RESOLVE_FAILED)?;
    Ok(payload
        .get("workspace_id")
        .and_then(Value::as_str)
        .filter(|value| !python_strip(value).is_empty())
        .map(str::to_owned))
}
