//! Read models over the workspace assessment tables, as
//! `workspace_assessment_reads` builds them: the admitted worktrees, run
//! history, the newest run of every worktree and one worktree's newest
//! assessed run.
//!
//! Stored JSON (`coverage_json`, `findings_json`) comes back as its stored
//! text, which Python parses, so its key order survives. Run lists carry a
//! finding count instead of the finding lists. The list reads come back in
//! pages that stop near `PAGE_BYTES`, so a long history or a store with many
//! worktrees never pushes a reply past its size cap. Each page names the
//! cursor the next page continues from.

use rusqlite::Connection;
use serde_json::{json, Map, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{query_each, query_one, value_error, Row, StoreResult};

/// One page stops once its rows pass this many encoded bytes. A single row
/// is bounded by the schema (a 4 KiB root, 16 KiB of coverage, or 256 KiB
/// of findings), so the first row always fits under the reply cap.
pub(crate) const PAGE_BYTES: usize = 1024 * 1024;
/// `recent_runs` reads at most this many runs, as Python clamped it;
/// `latest_runs` has no limit.
const MAX_RUNS: i64 = 200;

const RUN_COLUMNS: &str = "r.run_id, r.codebase_key, r.worktree_key, r.snapshot_digest, \
                           r.kind, r.trigger_kind, r.state, r.dirty_generation, \
                           r.coverage_json, r.error_code, r.created_at_ms, \
                           r.started_at_ms, r.finished_at_ms";

pub(crate) fn handles(method: &str) -> bool {
    matches!(
        method,
        "list_workspace_assessment_worktrees"
            | "list_workspace_assessment_runs"
            | "latest_workspace_assessment_run"
    )
}

pub(crate) fn dispatch(connection: &Connection, method: &str, args: &Args) -> StoreResult<Value> {
    match method {
        "list_workspace_assessment_worktrees" => worktrees(connection, args),
        "list_workspace_assessment_runs" => runs(connection, args),
        _ => latest_assessed(connection, args),
    }
}

/// `list_worktrees(include_paused=...)`, oldest admission first. `after`
/// is the `[admitted_at_ms, worktree_key, codebase_key]` of the last row read.
fn worktrees(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let include_paused = match args.raw("include_paused") {
        None => true,
        Some(Value::Bool(flag)) => *flag,
        Some(_) => return value_error("include_paused must be a boolean"),
    };
    let mut params = vec![Value::from(i64::from(include_paused))];
    let mut cursor = "";
    if let Some(after) = args.raw("after") {
        let [Some(admitted), Some(worktree), Some(codebase)] = cursor_parts::<3>(after) else {
            return value_error("after must name the last worktree read");
        };
        if !admitted.is_i64() || !worktree.is_string() || !codebase.is_string() {
            return value_error("after must name the last worktree read");
        }
        params.extend([admitted.clone(), worktree.clone(), codebase.clone()]);
        cursor = "and (s.admitted_at_ms, s.worktree_key, s.codebase_key) > (?, ?, ?)";
    }
    let sql = format!(
        "select s.codebase_key, s.worktree_key, s.private_root as root, s.dirty_generation, \
         s.last_completed_generation, s.last_scan_at_ms, s.paused, s.admitted_at_ms, \
         exists (select 1 from workspace_assessment_ended_admissions e \
                 where e.codebase_key = s.codebase_key and e.worktree_key = s.worktree_key) \
           as ended \
         from workspace_assessment_state s \
         where (? or s.paused = 0) {cursor} \
         order by s.admitted_at_ms, s.worktree_key, s.codebase_key"
    );
    page(connection, &sql, &params, |row| {
        json!([
            row["admitted_at_ms"],
            row["worktree_key"],
            row["codebase_key"]
        ])
    })
}

/// `recent_runs` (`mode: "recent"`, optionally for one worktree, at most
/// `limit` runs) and `latest_runs` (`mode: "latest"`, the newest run of every
/// worktree), newest first. `before` is the `[created_at_ms, run_id]` of the
/// last run read.
fn runs(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let mut clauses = Vec::new();
    let mut params = Vec::new();
    let mode = args.str("mode")?;
    match mode {
        "recent" => {
            if let Some(codebase) = args.opt_str("codebase_key")? {
                clauses.push("r.codebase_key = ? and r.worktree_key = ?");
                params.push(Value::from(codebase));
                params.push(Value::from(args.str("worktree_key")?));
            }
        }
        "latest" => clauses.push(
            "r.run_id = (select newest.run_id from workspace_assessment_runs newest \
             where newest.codebase_key = r.codebase_key \
               and newest.worktree_key = r.worktree_key \
             order by newest.created_at_ms desc, newest.run_id desc limit 1)",
        ),
        _ => return value_error("mode must be recent or latest"),
    }
    if let Some(before) = args.raw("before") {
        let [Some(created), Some(run_id)] = cursor_parts::<2>(before) else {
            return value_error("before must name the last run read");
        };
        if !created.is_i64() || !run_id.is_string() {
            return value_error("before must name the last run read");
        }
        clauses.push("(r.created_at_ms, r.run_id) < (?, ?)");
        params.extend([created.clone(), run_id.clone()]);
    }
    // The newest run of every worktree is never cut short; SQLite reads a
    // negative limit as no limit.
    let limit = match (mode, args.raw("limit")) {
        ("latest", None) => -1,
        ("latest", Some(_)) => return value_error("latest runs take no limit"),
        (_, None) => MAX_RUNS,
        (_, Some(value)) => match value.as_i64() {
            Some(limit) => limit.clamp(1, MAX_RUNS),
            None => return value_error("limit must be a whole number"),
        },
    };
    params.push(Value::from(limit));
    let filter = if clauses.is_empty() {
        String::new()
    } else {
        format!("where {}", clauses.join(" and "))
    };
    let sql = format!(
        "select {RUN_COLUMNS}, coalesce(json_array_length(r.findings_json), 0) as finding_count \
         from workspace_assessment_runs r {filter} \
         order by r.created_at_ms desc, r.run_id desc limit ?"
    );
    page(connection, &sql, &params, |row| {
        json!([row["created_at_ms"], row["run_id"]])
    })
}

/// `latest_assessed_run(keys)`: the newest completed or partial run of one
/// worktree, with its stored findings text, or `null`. Runs finished in the
/// same millisecond keep the order they were queued in.
fn latest_assessed(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let row = query_one(
        connection,
        &format!(
            "select {RUN_COLUMNS}, r.findings_json from workspace_assessment_runs r \
             where r.codebase_key = ? and r.worktree_key = ? \
               and r.state in ('completed', 'partial') \
             order by r.finished_at_ms desc, r.rowid desc limit 1"
        ),
        &[
            Value::from(args.str("codebase_key")?),
            Value::from(args.str("worktree_key")?),
        ],
    )?;
    Ok(row.map_or(Value::Null, Value::Object))
}

fn cursor_parts<const N: usize>(value: &Value) -> [Option<&Value>; N] {
    let items = value.as_array().filter(|items| items.len() == N);
    std::array::from_fn(|index| items.and_then(|items| items.get(index)))
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
#[path = "guard_store_workspace_assessment_reads_tests.rs"]
mod tests;
