//! `cached_supply_chain_bundle`: the bundle `GET /v1/supply-chain/bundle`
//! answers with, read as `store.get_cloud_workspace_id()` and
//! `store.get_cached_supply_chain_bundle(workspace_id)` read it.

use rusqlite::{params, Connection, OptionalExtension};
use serde_json::Value;

use crate::claim_reuse_binding::sync_state_payload;
use crate::guard_store_db::{StoreError, StoreResult};

const UNREADABLE: StoreError = StoreError::Invalid("native_supply_chain_bundle_unreadable");

/// `_cloud_workspace_id_from_connection`: the OAuth credential row's
/// non-blank workspace id, unstripped.
fn cloud_workspace_id(connection: &Connection) -> StoreResult<Option<String>> {
    let Some(text) = sync_state_payload(connection, "oauth_local_credentials")? else {
        return Ok(None);
    };
    let payload: Value = serde_json::from_str(&text).map_err(|_| UNREADABLE)?;
    Ok(match payload.get("workspace_id") {
        Some(Value::String(id)) if !id.trim().is_empty() => Some(id.clone()),
        _ => None,
    })
}

/// The cached bundle's `bundle` value, or `null` when Guard Cloud has no
/// workspace or the cache holds no bundle for it.
pub(crate) fn cached_bundle(connection: &Connection) -> StoreResult<Value> {
    let Some(workspace_id) = cloud_workspace_id(connection)? else {
        return Ok(Value::Null);
    };
    let Some(text) = connection
        .query_row(
            "select response_json from guard_supply_chain_bundle_cache where workspace_id = ?1",
            params![workspace_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?
    else {
        return Ok(Value::Null);
    };
    let payload: Value = serde_json::from_str(&text).map_err(|_| UNREADABLE)?;
    Ok(match payload {
        Value::Object(mut wrapper) => wrapper.remove("bundle").unwrap_or(Value::Null),
        _ => Value::Null,
    })
}

#[cfg(test)]
#[path = "supply_chain_bundle_cache_op_tests.rs"]
mod tests;
