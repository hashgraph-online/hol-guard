//! The newest assessed run of every worktree, with its findings text, and
//! the digest of the cached advisory bundles a local evaluation reads.
//!
//! `list_latest_assessed_workspace_runs` pages like the other run lists, in
//! worktree-key order, so many worktrees with large finding lists never push
//! one reply past its size cap. `keys` limits it to the named worktrees.
//! `workspace_assessment_feed_digest` hashes the same bytes
//! `workspace_assessment_runner.feed_context_digest` hashed in Python, so a
//! digest stored before this change still matches.

use rusqlite::Connection;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::{cursor_parts, page, RUN_COLUMNS};
use crate::guard_store_args::Args;
use crate::guard_store_db::{query_each, value_error, StoreResult};
use crate::hook_env_stamp::json_string;

/// A summary names at most a few hundred worktrees; this bounds the filter
/// a caller can send.
const MAX_KEYS: usize = 4096;
const FEED_DIGEST_DOMAIN: &str = "guard.workspace-feed.v1\0";
const FEED_COLUMNS: [&str; 3] = ["workspace_id", "payload_hash", "policy_hash"];

pub(super) fn handles(method: &str) -> bool {
    matches!(
        method,
        "list_latest_assessed_workspace_runs" | "workspace_assessment_feed_digest"
    )
}

pub(super) fn dispatch(connection: &Connection, method: &str, args: &Args) -> StoreResult<Value> {
    match method {
        "workspace_assessment_feed_digest" => feed_digest(connection),
        _ => latest_assessed_runs(connection, args),
    }
}

/// `latest_assessed_runs(store, keys)`: per worktree, the newest completed or
/// partial run. Runs finished in the same millisecond keep the order they
/// were queued in. `after` is the `[codebase_key, worktree_key]` of the last
/// row read plus the highest run rowid the first page saw, so every page
/// reads the same set of runs: a run finished between pages cannot replace a
/// worktree's newest run on a later page or move a worktree already read.
fn latest_assessed_runs(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let mut source = String::from("workspace_assessment_runs r");
    let mut params = Vec::new();
    if let Some(keys) = args.raw("keys") {
        if !valid_keys(keys) {
            return value_error("keys must list [codebase_key, worktree_key] pairs");
        }
        // The named worktrees drive the join, so each one is a lookup on the
        // run table's worktree index instead of a scan of every run.
        source = String::from(
            "(select distinct json_extract(value, '$[0]') as codebase_key, \
               json_extract(value, '$[1]') as worktree_key from json_each(?)) k \
             join workspace_assessment_runs r \
               on r.codebase_key = k.codebase_key and r.worktree_key = k.worktree_key",
        );
        params.push(Value::from(keys.to_string()));
    }
    let (saw, after) = match args.raw("after") {
        None => {
            let saw = connection.query_row(
                "select coalesce(max(rowid), 0) from workspace_assessment_runs",
                [],
                |row| row.get::<_, i64>(0),
            )?;
            (saw, None)
        }
        Some(cursor) => {
            let [Some(codebase), Some(worktree), Some(saw)] = cursor_parts::<3>(cursor) else {
                return value_error("after must name the last worktree read");
            };
            if !codebase.is_string() || !worktree.is_string() {
                return value_error("after must name the last worktree read");
            }
            let Some(saw) = saw.as_i64() else {
                return value_error("after must name the last worktree read");
            };
            (saw, Some([codebase.clone(), worktree.clone()]))
        }
    };
    params.extend([Value::from(saw), Value::from(saw)]);
    let after = match after {
        None => "",
        Some(cursor) => {
            params.extend(cursor);
            " and (r.codebase_key, r.worktree_key) > (?, ?)"
        }
    };
    let sql = format!(
        "select {RUN_COLUMNS}, r.findings_json from {source} \
         where r.state in ('completed', 'partial') and r.rowid <= ? \
           and r.run_id = (select latest.run_id from workspace_assessment_runs latest \
             where latest.codebase_key = r.codebase_key \
               and latest.worktree_key = r.worktree_key \
               and latest.state in ('completed', 'partial') and latest.rowid <= ? \
             order by latest.finished_at_ms desc, latest.rowid desc limit 1){after} \
         order by r.codebase_key, r.worktree_key"
    );
    page(connection, &sql, &params, |row| {
        json!([row["codebase_key"], row["worktree_key"], saw])
    })
}

fn valid_keys(keys: &Value) -> bool {
    keys.as_array().is_some_and(|items| {
        items.len() <= MAX_KEYS
            && items.iter().all(|item| {
                item.as_array()
                    .is_some_and(|pair| pair.len() == 2 && pair.iter().all(Value::is_string))
            })
    })
}

/// SHA-256 over the domain and `json.dumps(rows, separators=(",", ":"))`,
/// where each row is the `str()` of a cached bundle's workspace id, payload
/// hash and policy hash, in workspace order.
fn feed_digest(connection: &Connection) -> StoreResult<Value> {
    let mut encoded = String::from("[");
    query_each(
        connection,
        "select workspace_id, payload_hash, policy_hash \
         from guard_supply_chain_bundle_cache order by workspace_id",
        &[],
        |row| {
            if encoded.len() > 1 {
                encoded.push(',');
            }
            encoded.push('[');
            for (index, name) in FEED_COLUMNS.iter().enumerate() {
                if index > 0 {
                    encoded.push(',');
                }
                let cell = python_str(row.get(*name).unwrap_or(&Value::Null));
                encoded.push_str(&json_string(&cell, true, false));
            }
            encoded.push(']');
            Ok(true)
        },
    )?;
    encoded.push(']');
    let digest = Sha256::digest(format!("{FEED_DIGEST_DOMAIN}{encoded}").as_bytes());
    Ok(Value::from(hex::encode(digest)))
}

/// Python's `str()` of a SQLite cell. The columns are `text not null`, so
/// only text arrives; the other arms keep a malformed row hashable.
fn python_str(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Null => "None".to_owned(),
        other => other.to_string(),
    }
}

#[cfg(test)]
#[path = "guard_store_workspace_assessment_latest_tests.rs"]
mod tests;
