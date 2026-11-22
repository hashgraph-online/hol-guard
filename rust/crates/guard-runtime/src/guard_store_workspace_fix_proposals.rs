//! The stored rows of workspace fix proposals and the worktree they edit.
//!
//! Port of the SQLite reads and writes in
//! `workspace_assessment_fix_proposals.py`. Python keeps the request handling
//! and the state machine; the native `workspace-fix` command plans and applies
//! the manifest edits. Stored JSON comes back as text, so its key order and
//! spacing survive, and a proposal's diff only leaves the store while it is
//! still waiting for review.

use base64::{engine::general_purpose::STANDARD, Engine};
use rusqlite::Connection;
use serde_json::{json, Map, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{
    exec, query_all, query_each, query_one, value_error, Row, StoreError, StoreResult,
};

/// `MAX_LISTED_PROPOSALS`.
const MAX_LISTED: i64 = 100;
/// A page stays well under the 2 MiB reply cap.
const PAGE_BYTES: usize = 1024 * 1024;
const PROPOSAL_COLUMNS: &str = "proposal_id, codebase_key, worktree_key, finding_id, ecosystem, \
     package_name, fix_version, advisory_ids_json, rule_ids_json, source_run_id, snapshot_digest, \
     manifest_path, base_sha256, new_sha256, edits_json, \
     case when state = 'prepared' then diff_text end as diff_text, state, created_at_ms, \
     updated_at_ms, applied_at_ms, verified_at_ms, verification_run_id";
const VERDICTS: [&str; 2] = ["still_present", "verified_fixed"];
/// The finding's identity every proposal of one prepare shares.
const IDENTITY: [&str; 5] = [
    "ecosystem",
    "package_name",
    "fix_version",
    "advisory_ids_json",
    "rule_ids_json",
];

pub(crate) fn handles(method: &str) -> bool {
    matches!(
        method,
        "workspace_assessment_worktree_root"
            | "list_workspace_fix_proposals"
            | "get_workspace_fix_proposal"
            | "list_workspace_fix_proposals_to_verify"
            | "settle_workspace_fix_proposals"
            | "store_prepared_workspace_fix_proposals"
            | "set_workspace_fix_proposal_state"
    )
}

pub(crate) fn dispatch(connection: &Connection, method: &str, args: &Args) -> StoreResult<Value> {
    match method {
        "workspace_assessment_worktree_root" => worktree_root(connection, args),
        "list_workspace_fix_proposals" => list(connection, args),
        "get_workspace_fix_proposal" => get(connection, args),
        "list_workspace_fix_proposals_to_verify" => to_verify(connection, args),
        "settle_workspace_fix_proposals" => settle(connection, args),
        "store_prepared_workspace_fix_proposals" => store_prepared(connection, args),
        "set_workspace_fix_proposal_state" => set_state(connection, args),
        _ => Err(StoreError::Invalid("native_guard_store_method_unknown")),
    }
}

fn keys(args: &Args) -> StoreResult<[Value; 2]> {
    Ok([
        Value::from(args.str("codebase_key")?),
        Value::from(args.str("worktree_key")?),
    ])
}

/// The admitted worktree's root and paused flag, or `null`.
fn worktree_root(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let row = query_one(
        connection,
        "select private_root as root, paused from workspace_assessment_state \
         where codebase_key = ? and worktree_key = ?",
        &keys(args)?,
    )?;
    Ok(row.map_or(Value::Null, Value::Object))
}

/// A worktree's newest proposals, at most `limit`, newest first. `before` is
/// the `[created_at_ms, proposal_id]` of the last proposal read.
fn list(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let limit = match args.raw("limit") {
        None => MAX_LISTED,
        Some(value) => match value.as_i64() {
            Some(limit) => limit.clamp(1, MAX_LISTED),
            None => return value_error("limit must be a whole number"),
        },
    };
    let mut params = keys(args)?.to_vec();
    let mut cursor = "";
    if let Some(before) = args.raw("before") {
        let Some([created, proposal]) = before.as_array().map(Vec::as_slice) else {
            return value_error("before must name the last proposal read");
        };
        if !created.is_i64() || !proposal.is_string() {
            return value_error("before must name the last proposal read");
        }
        params.extend([created.clone(), proposal.clone()]);
        cursor = "and (created_at_ms, proposal_id) < (?, ?)";
    }
    params.push(Value::from(limit));
    let sql = format!(
        "select {PROPOSAL_COLUMNS} from workspace_fix_proposals \
         where codebase_key = ? and worktree_key = ? {cursor} \
         order by created_at_ms desc, proposal_id desc limit ?"
    );
    page(connection, &sql, &params, |row| {
        json!([row["created_at_ms"], row["proposal_id"]])
    })
}

/// One proposal, or `null`.
fn get(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let row = query_one(
        connection,
        &format!("select {PROPOSAL_COLUMNS} from workspace_fix_proposals where proposal_id = ?"),
        &[Value::from(args.str("proposal_id")?)],
    )?;
    Ok(row.map_or(Value::Null, Value::Object))
}

/// The applied proposals a newer run may settle, by id. `after` is the id of
/// the last proposal read.
fn to_verify(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let mut params = keys(args)?.to_vec();
    let mut cursor = "";
    if let Some(after) = args.raw("after") {
        if !after.is_string() {
            return value_error("after must name the last proposal read");
        }
        params.push(after.clone());
        cursor = "and proposal_id > ?";
    }
    let sql = format!(
        "select proposal_id, ecosystem, package_name, fix_version, \
                advisory_ids_json as advisory_ids, rule_ids_json as rule_ids, snapshot_digest, \
                applied_at_ms, state, verification_run_id \
         from workspace_fix_proposals \
         where codebase_key = ? and worktree_key = ? \
           and state in ('applied', 'still_present') {cursor} \
         order by proposal_id"
    );
    page(connection, &sql, &params, |row| row["proposal_id"].clone())
}

/// Records each verdict of `run_id`, only while it is still the worktree's
/// newest assessed run; `false` when a newer run finished meanwhile. A
/// proposal takes its verdict only while its state and verification run are
/// still the ones it was judged from.
fn settle(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let run_id = args.str("run_id")?;
    let now = args.int("now_ms")?;
    let updates = objects(args, "updates")?;
    let mut checked = Vec::with_capacity(updates.len());
    for update in &updates {
        let update = Args(update);
        let state = update.str("state")?;
        if !VERDICTS.contains(&state) {
            return value_error("a verdict must be still_present or verified_fixed");
        }
        let prior_run = match update.raw("prior_verification_run_id") {
            None => Value::Null,
            Some(Value::String(run)) => Value::from(run.as_str()),
            Some(_) => return value_error("prior_verification_run_id must be text or null"),
        };
        checked.push([
            Value::from(state),
            Value::from(update.str("proposal_id")?),
            Value::from(update.str("prior_state")?),
            prior_run,
        ]);
    }
    let newest = query_one(
        connection,
        "select run_id from workspace_assessment_runs \
         where codebase_key = ? and worktree_key = ? and state in ('completed', 'partial') \
         order by finished_at_ms desc, rowid desc limit 1",
        &keys(args)?,
    )?;
    if newest.as_ref().and_then(|row| row["run_id"].as_str()) != Some(run_id) {
        return Ok(Value::Bool(false));
    }
    for [state, proposal, prior_state, prior_run] in checked {
        exec(
            connection,
            "update workspace_fix_proposals set \
               state = ?, verified_at_ms = ?, verification_run_id = ?, \
               updated_at_ms = max(created_at_ms, ?) \
             where proposal_id = ? and state = ? and verification_run_id is ?",
            &[
                state,
                Value::from(now),
                Value::from(run_id),
                Value::from(now),
                proposal,
                prior_state,
                prior_run,
            ],
        )?;
    }
    Ok(Value::Bool(true))
}

/// Stores each planned edit as a prepared proposal and returns their ids in
/// order. A prepared proposal for the same finding and manifest with the same
/// hashes and snapshot is kept; any other prepared one for them goes stale.
/// Each item carries the id a new proposal takes.
fn store_prepared(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let [codebase, worktree] = keys(args)?;
    let finding = Value::from(args.str("finding_id")?);
    let source_run = Value::from(args.str("source_run_id")?);
    let snapshot = args.str("snapshot_digest")?;
    let now = args.int("now_ms")?;
    let mut identity = Vec::with_capacity(IDENTITY.len());
    for key in IDENTITY {
        identity.push(Value::from(args.str(key)?));
    }
    let mut ids = Vec::new();
    for item in objects(args, "items")? {
        let item = Args(&item);
        let manifest = Value::from(item.str("manifest_path")?);
        let base = item.str("base_sha256")?;
        let new = item.str("new_sha256")?;
        let existing = query_all(
            connection,
            "select proposal_id, base_sha256, new_sha256, snapshot_digest \
             from workspace_fix_proposals \
             where codebase_key = ? and worktree_key = ? and finding_id = ? \
               and manifest_path = ? and state = 'prepared'",
            &[
                codebase.clone(),
                worktree.clone(),
                finding.clone(),
                manifest.clone(),
            ],
        )?;
        let same = existing
            .iter()
            .find(|row| {
                row["base_sha256"].as_str() == Some(base)
                    && row["new_sha256"].as_str() == Some(new)
                    && row["snapshot_digest"].as_str() == Some(snapshot)
            })
            .map(|row| row["proposal_id"].clone());
        for row in &existing {
            if Some(&row["proposal_id"]) != same.as_ref() {
                exec(
                    connection,
                    "update workspace_fix_proposals \
                     set state = 'stale', updated_at_ms = max(created_at_ms, ?) \
                     where proposal_id = ?",
                    &[Value::from(now), row["proposal_id"].clone()],
                )?;
            }
        }
        if let Some(same) = same {
            ids.push(same);
            continue;
        }
        let proposal = Value::from(item.str("proposal_id")?);
        let mut params = vec![
            proposal.clone(),
            codebase.clone(),
            worktree.clone(),
            finding.clone(),
        ];
        params.extend(identity.iter().cloned());
        params.extend([
            source_run.clone(),
            Value::from(snapshot),
            manifest,
            Value::from(base),
            Value::from(new),
            Value::from(decoded_text(&item, "edits_base64")?),
            Value::from(decoded_text(&item, "diff_base64")?),
            Value::from(now),
            Value::from(now),
        ]);
        exec(
            connection,
            "insert into workspace_fix_proposals ( \
               proposal_id, codebase_key, worktree_key, finding_id, ecosystem, package_name, \
               fix_version, advisory_ids_json, rule_ids_json, source_run_id, snapshot_digest, \
               manifest_path, base_sha256, new_sha256, edits_json, diff_text, state, \
               created_at_ms, updated_at_ms) \
             values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'prepared', ?, ?)",
            &params,
        )?;
        ids.push(proposal);
    }
    Ok(Value::Array(ids))
}

/// Proposal text arrives as base64 so escaped characters cannot outgrow the
/// request; it must decode to UTF-8.
fn decoded_text(item: &Args, key: &str) -> StoreResult<String> {
    let bytes = STANDARD
        .decode(item.str(key)?)
        .or_else(|_| value_error(&format!("{key} must be base64")))?;
    String::from_utf8(bytes).or_else(|_| value_error(&format!("{key} must be UTF-8")))
}

/// Moves a prepared proposal to `state`; `applied` also stamps its apply time.
/// A proposal no longer prepared is left as it is.
fn set_state(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let now = args.int("now_ms")?;
    exec(
        connection,
        "update workspace_fix_proposals set \
           state = ?, updated_at_ms = max(created_at_ms, ?), \
           applied_at_ms = case when ? then ? else applied_at_ms end \
         where proposal_id = ? and state = 'prepared'",
        &[
            Value::from(args.str("state")?),
            Value::from(now),
            Value::from(args.flag("applied")?),
            Value::from(now),
            Value::from(args.str("proposal_id")?),
        ],
    )?;
    Ok(Value::Null)
}

/// A required list of objects.
fn objects(args: &Args, key: &str) -> StoreResult<Vec<Map<String, Value>>> {
    let Some(Value::Array(items)) = args.raw(key) else {
        return value_error("expected a list of objects");
    };
    items
        .iter()
        .map(|item| match item {
            Value::Object(item) => Ok(item.clone()),
            _ => value_error("expected a list of objects"),
        })
        .collect()
}

/// Rows until the page passes `PAGE_BYTES`, with the cursor of the last row
/// kept when more rows follow.
fn page(
    connection: &Connection,
    sql: &str,
    params: &[Value],
    cursor_of: impl Fn(&Map<String, Value>) -> Value,
) -> StoreResult<Value> {
    let mut items: Vec<Value> = Vec::new();
    let mut bytes = 0usize;
    let mut next = Value::Null;
    query_each(connection, sql, params, |row: Row| {
        let encoded = serde_json::to_string(&row).map_or(usize::MAX, |text| text.len());
        if let Some(Value::Object(last)) = items.last() {
            if bytes.saturating_add(encoded) > PAGE_BYTES {
                next = cursor_of(last);
                return Ok(false);
            }
        }
        bytes = bytes.saturating_add(encoded);
        items.push(Value::Object(row));
        Ok(true)
    })?;
    Ok(json!({"items": items, "next": next}))
}

#[cfg(test)]
#[path = "guard_store_workspace_fix_proposals_tests.rs"]
mod tests;
