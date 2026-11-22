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
            | "newest_supply_chain_bundle_workspace"
    )
}

pub(crate) fn dispatch(
    connection: &Connection,
    method: &str,
    args: &Args<'_>,
) -> StoreResult<Value> {
    match method {
        "cached_supply_chain_bundle" => cached_bundle(connection),
        "get_cached_supply_chain_bundle" => {
            workspace_bundle_page(connection, args.str("workspace_id")?, args.int("offset")?)
        }
        "cache_supply_chain_bundle" => cache_bundle(
            connection,
            args.str("workspace_id")?,
            args.object("response")?,
            args.str("cached_at")?,
        ),
        "newest_supply_chain_bundle_workspace" => newest_workspace(connection),
        _ => Err(StoreError::Invalid("native_guard_store_method_unknown")),
    }
}

/// The workspace of the most recently cached response, as stored, or `null`
/// when the cache is empty or that row's workspace id is not text. The
/// sign-in record falls back to it when it names no workspace.
fn newest_workspace(connection: &Connection) -> StoreResult<Value> {
    let workspace = connection
        .query_row(
            "select case when typeof(workspace_id) = 'text' then workspace_id end \
             from guard_supply_chain_bundle_cache order by cached_at desc limit 1",
            [],
            |row| row.get::<_, Option<String>>(0),
        )
        .optional()?
        .flatten();
    Ok(workspace.map_or(Value::Null, Value::String))
}

/// Characters of stored response text returned per call. A reply is capped
/// at 2 MiB, and even four-byte characters escaped into JSON stay well under
/// that at this size, while cloud sync may store a much larger response.
pub(crate) const RESPONSE_PAGE_CHARS: i64 = 256 * 1024;

/// `get_supply_chain_bundle`, one page at a time: the stored response text
/// from character `offset`, its full length and when it was cached, or
/// `null` when the workspace has no row. The caller joins the pages and
/// parses the text with its own key order, and restarts when `cached_at` or
/// the length changes between pages.
fn workspace_bundle_page(
    connection: &Connection,
    workspace_id: &str,
    offset: i64,
) -> StoreResult<Value> {
    if offset < 0 {
        return value_error("offset must not be negative");
    }
    let row: Option<(String, i64, String)> = connection
        .query_row(
            "select substr(response_json, ?2 + 1, ?3), length(response_json), cached_at \
             from guard_supply_chain_bundle_cache where workspace_id = ?1",
            params![workspace_id, offset, RESPONSE_PAGE_CHARS],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    Ok(row.map_or(
        Value::Null,
        |(page, length, cached_at)| json!({"page": page, "length": length, "cached_at": cached_at}),
    ))
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
