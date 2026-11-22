//! The cached supply-chain bundle: the answer `GET /v1/supply-chain/bundle`
//! gave for a workspace.
//!
//! - `cached_supply_chain_bundle` reads the bundle for the signed-in
//!   workspace, as `store.get_cloud_workspace_id()` and
//!   `store.get_cached_supply_chain_bundle(workspace_id)` read it.
//! - `get_cached_supply_chain_bundle` and `cache_supply_chain_bundle` are the
//!   `GuardStore` read and write for one named workspace, ported from
//!   `store_supply_chain.py`.

use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Map, Value};

use crate::claim_reuse_binding::sync_state_payload;
use crate::guard_store_args::Args;
use crate::guard_store_db::{value_error, StoreError, StoreResult};

/// The bundle fields copied into their own columns, in column order.
const BUNDLE_COLUMNS: [&str; 6] = [
    "bundleVersion",
    "keyId",
    "tier",
    "policyHash",
    "feedSnapshotHash",
    "scoringVersion",
];

/// Whether `method` is one of the bundle cache methods.
pub(crate) fn handles(method: &str) -> bool {
    matches!(
        method,
        "cached_supply_chain_bundle"
            | "get_cached_supply_chain_bundle"
            | "cache_supply_chain_bundle"
    )
}

pub(crate) fn dispatch(
    connection: &Connection,
    method: &str,
    args: &Args<'_>,
) -> StoreResult<Value> {
    match method {
        "cached_supply_chain_bundle" => cached_bundle(connection),
        "get_cached_supply_chain_bundle" => workspace_bundle(connection, args.str("workspace_id")?),
        "cache_supply_chain_bundle" => cache_bundle(
            connection,
            args.str("workspace_id")?,
            args.object("response")?,
            args.str("cached_at")?,
        ),
        _ => Err(StoreError::Invalid("native_guard_store_method_unknown")),
    }
}

/// `get_supply_chain_bundle`: the stored response text and when it was
/// cached, or `null` when the workspace has no row. The text is handed back
/// unchanged so the caller parses it with its own key order.
fn workspace_bundle(connection: &Connection, workspace_id: &str) -> StoreResult<Value> {
    let row: Option<(String, String)> = connection
        .query_row(
            "select response_json, cached_at from guard_supply_chain_bundle_cache \
             where workspace_id = ?1",
            params![workspace_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    Ok(row.map_or(Value::Null, |(response_json, cached_at)| {
        json!({"response_json": response_json, "cached_at": cached_at})
    }))
}

/// `upsert_supply_chain_bundle`: replace the workspace's cached response.
fn cache_bundle(
    connection: &Connection,
    workspace_id: &str,
    response: &Map<String, Value>,
    cached_at: &str,
) -> StoreResult<Value> {
    let Some(Value::Object(bundle)) = response.get("bundle") else {
        return value_error("response must include a bundle object");
    };
    let mut columns = Vec::with_capacity(BUNDLE_COLUMNS.len());
    for key in BUNDLE_COLUMNS {
        columns.push(column_text(bundle.get(key), key)?);
    }
    let payload_hash = column_text(response.get("payloadHash"), "payloadHash")?;
    let response_json = Value::Object(response.clone()).to_string();
    connection.execute(
        "insert or replace into guard_supply_chain_bundle_cache (workspace_id, \
         bundle_version, key_id, tier, policy_hash, feed_snapshot_hash, scoring_version, \
         payload_hash, response_json, cached_at) \
         values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            workspace_id,
            columns[0],
            columns[1],
            columns[2],
            columns[3],
            columns[4],
            columns[5],
            payload_hash,
            response_json,
            cached_at,
        ],
    )?;
    Ok(Value::Null)
}

/// A column value as Python's `str()` wrote it for the values a bundle
/// carries: text unchanged, a whole number in decimal, a boolean as
/// `True`/`False` and null as `None`. A missing field, a fraction or a
/// container is refused.
fn column_text(value: Option<&Value>, key: &str) -> StoreResult<String> {
    match value {
        Some(Value::String(text)) => Ok(text.clone()),
        Some(Value::Number(number)) if number.is_i64() || number.is_u64() => Ok(number.to_string()),
        Some(Value::Bool(true)) => Ok("True".to_owned()),
        Some(Value::Bool(false)) => Ok("False".to_owned()),
        Some(Value::Null) => Ok("None".to_owned()),
        Some(_) => value_error(&format!("supply-chain bundle field {key} is not text")),
        None => value_error(&format!("supply-chain bundle field {key} is missing")),
    }
}

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
fn cached_bundle(connection: &Connection) -> StoreResult<Value> {
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
