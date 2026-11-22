//! Cheap presence reads a policy lookup takes before it gathers evidence, and
//! the head of the stored extension-control authority snapshot.
//!
//! `policy_row_presence` says which kinds of saved rows exist, so a store with
//! none skips the keyring and integrity work. `extension_control_authority_head`
//! names the snapshot a policy clear must replace.

use guard_policy_snapshot::policy_integrity::REMOTE_POLICY_SOURCES;
use rusqlite::Connection;
use serde_json::{json, Value};

use crate::guard_store_db::{query_one, text, StoreError, StoreResult};

pub(crate) fn handles(method: &str) -> bool {
    matches!(
        method,
        "policy_row_presence" | "extension_control_authority_head"
    )
}

pub(crate) fn dispatch(connection: &Connection, method: &str) -> StoreResult<Value> {
    match method {
        "policy_row_presence" => presence(connection),
        "extension_control_authority_head" => authority_head(connection),
        _ => Err(StoreError::Invalid("native_guard_store_method_unknown")),
    }
}

fn exists(connection: &Connection, sql: &str, params: &[Value]) -> StoreResult<bool> {
    Ok(query_one(connection, sql, params)?.is_some())
}

/// Which saved rows exist: local and remote policy decisions, local-once
/// approvals, and policy-bundle decisions.
fn presence(connection: &Connection) -> StoreResult<Value> {
    let placeholders = vec!["?"; REMOTE_POLICY_SOURCES.len()].join(",");
    let remote: Vec<Value> = REMOTE_POLICY_SOURCES
        .iter()
        .map(|source| Value::from(*source))
        .collect();
    let local_policy = exists(
        connection,
        &format!("select 1 from policy_decisions where source not in ({placeholders}) limit 1"),
        &remote,
    )?;
    let remote_policy = exists(
        connection,
        &format!("select 1 from policy_decisions where source in ({placeholders}) limit 1"),
        &remote,
    )?;
    let local_once = exists(
        connection,
        "select 1 from guard_local_once_approvals limit 1",
        &[],
    )?;
    let policy_bundle = exists(
        connection,
        "select 1 from policy_decisions where source = 'policy-bundle' limit 1",
        &[],
    )?;
    Ok(json!({
        "local_policy": local_policy,
        "remote_policy": remote_policy,
        "local_once": local_once,
        "policy_bundle": policy_bundle,
    }))
}

/// The stored snapshot's revision and digest, or null when none is stored.
fn authority_head(connection: &Connection) -> StoreResult<Value> {
    let row = query_one(
        connection,
        "select revision, snapshot_digest from extension_control_authority_snapshot \
         where singleton = 1",
        &[],
    )?;
    let Some(row) = row else {
        return Ok(Value::Null);
    };
    let Some(revision) = row.get("revision").and_then(Value::as_i64) else {
        return Err(StoreError::Runtime(
            "extension control authority revision is not an integer".to_owned(),
        ));
    };
    Ok(json!({
        "revision": revision,
        "snapshot_digest": text(&row, "snapshot_digest"),
    }))
}

#[cfg(test)]
#[path = "guard_store_policy_presence_tests.rs"]
mod tests;
