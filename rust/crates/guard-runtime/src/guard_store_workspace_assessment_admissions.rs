//! Admitting worktrees for background assessment, pausing them, noting the
//! digests a poll observed and ending install admissions, as
//! `workspace_assessment_admissions` and `workspace_assessment_store` did.
//!
//! An admission, its first observation and its first run are written in one
//! transaction, so a failure part way leaves nothing behind for the next poll
//! to mistake for a finished admission. A worktree admitted automatically,
//! because a harness install registered it, is marked; it stops being watched
//! once no active install registers its root, unless someone admitted it
//! themselves.
//!
//! Ending an admission stops the worker from checking the worktree and nothing
//! else: its run history and fix proposals are kept, and its state row stays,
//! paused and marked ended, so a later admission of the same worktree resumes
//! it.

use std::collections::HashSet;

use rusqlite::Connection;
use serde_json::{json, Value};

use super::assessment_queue::{enqueue_locked, Keys, Request};
use crate::guard_store_args::Args;
use crate::guard_store_db::{
    exec, query_all, query_each, query_one, text, value_error, Row, StoreResult,
};

/// A page stays well under the 2 MiB reply cap.
const PAGE_BYTES: usize = 1024 * 1024;
/// Room for `{"items":[],"next":[codebase,worktree]}` around the roots.
const ENVELOPE_BYTES: usize = 512;
/// True for a state row whose automatic admission has ended.
const IS_ENDED: &str = "exists ( \
     select 1 from workspace_assessment_ended_admissions e \
     where e.codebase_key = workspace_assessment_state.codebase_key \
       and e.worktree_key = workspace_assessment_state.worktree_key \
   )";

pub(crate) fn handles(method: &str) -> bool {
    matches!(
        method,
        "admit_workspace_assessment"
            | "set_workspace_assessment_paused"
            | "record_workspace_assessment_observation"
            | "observe_workspace_assessment"
            | "workspace_assessment_watched_roots"
            | "is_manual_workspace_assessment_admission"
            | "end_unregistered_workspace_assessment_admissions"
    )
}

pub(crate) fn dispatch(connection: &Connection, method: &str, args: &Args) -> StoreResult<Value> {
    match method {
        "admit_workspace_assessment" => admit(connection, args),
        "set_workspace_assessment_paused" => set_paused(connection, args),
        "record_workspace_assessment_observation" => {
            let keys = Keys::from_args(args)?;
            Ok(json!(observe_digests(connection, &keys, args)?))
        }
        "observe_workspace_assessment" => observe(connection, args),
        "workspace_assessment_watched_roots" => watched_roots(connection, args),
        "is_manual_workspace_assessment_admission" => is_manual(connection, args),
        _ => end_unregistered(connection, args),
    }
}

/// Admit a worktree, record its first observation and queue its first run.
///
/// A manual admission also resumes a paused worktree and takes over one that
/// was admitted automatically. An automatic admission leaves a worktree that
/// is already admitted alone and returns null; when its root used to name
/// another worktree admitted the same way, that admission ends.
fn admit(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let keys = Keys::from_args(args)?;
    let root = args.str("root")?;
    let now_ms = args.int("now_ms")?;
    let automatic = match args.raw("automatic") {
        Some(Value::Bool(flag)) => *flag,
        _ => return value_error("automatic must be a boolean"),
    };
    let stat_digest = args.str("stat_digest")?;
    let feed_digest = args.opt_str("feed_digest")?;
    let request = Request {
        trigger_kind: "workspace_open",
        detector_set_digest: args.str("detector_set_digest")?,
        kind: "deterministic",
        now_ms,
    };
    let run_id = args.str("run_id")?;
    // A manual admission takes over any existing row. An automatic one leaves
    // it alone unless its admission had ended, which a new registration
    // revives.
    let takeover = "update set private_root = excluded.private_root, paused = 0";
    let conflict = if automatic {
        format!("{takeover} where {IS_ENDED}")
    } else {
        takeover.to_owned()
    };
    let [codebase, worktree] = keys.params();
    let inserted = exec(
        connection,
        &format!(
            "insert into workspace_assessment_state \
               (codebase_key, worktree_key, private_root, admitted_at_ms) \
             values (?, ?, ?, ?) \
             on conflict(codebase_key, worktree_key) do {conflict}"
        ),
        &[codebase, worktree, Value::from(root), Value::from(now_ms)],
    )?;
    if inserted != 1 {
        return Ok(Value::Null);
    }
    exec(
        connection,
        "delete from workspace_assessment_ended_admissions \
         where codebase_key = ? and worktree_key = ?",
        &keys.params(),
    )?;
    if automatic {
        let [codebase, worktree] = keys.params();
        let replaced = query_all(
            connection,
            "select s.codebase_key, s.worktree_key from workspace_assessment_state s \
             join workspace_assessment_install_admissions a using (codebase_key, worktree_key) \
             where s.private_root = ? and not (s.codebase_key = ? and s.worktree_key = ?)",
            &[Value::from(root), codebase, worktree],
        )?;
        end_admissions(connection, &replaced, now_ms)?;
        exec(
            connection,
            "insert or ignore into workspace_assessment_install_admissions values (?, ?)",
            &keys.params(),
        )?;
    } else {
        exec(
            connection,
            "delete from workspace_assessment_install_admissions \
             where codebase_key = ? and worktree_key = ?",
            &keys.params(),
        )?;
    }
    let [codebase, worktree] = keys.params();
    exec(
        connection,
        "update workspace_assessment_state set observed_stat_digest = ?, observed_feed_digest = ? \
         where codebase_key = ? and worktree_key = ?",
        &[
            Value::from(stat_digest),
            Value::from(feed_digest),
            codebase,
            worktree,
        ],
    )?;
    enqueue_locked(connection, &keys, &request, Some(run_id))
}

fn set_paused(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let keys = Keys::from_args(args)?;
    let paused = match args.raw("paused") {
        Some(Value::Bool(flag)) => *flag,
        _ => return value_error("paused must be a boolean"),
    };
    let [codebase, worktree] = keys.params();
    let changed = exec(
        connection,
        "update workspace_assessment_state set paused = ? \
         where codebase_key = ? and worktree_key = ?",
        &[Value::from(i64::from(paused)), codebase, worktree],
    )?;
    if changed == 1 && !paused {
        // Resuming is a person's choice to watch it, which supersedes an
        // ended admission.
        exec(
            connection,
            "delete from workspace_assessment_ended_admissions \
             where codebase_key = ? and worktree_key = ?",
            &keys.params(),
        )?;
    }
    Ok(Value::Bool(changed == 1))
}

/// Store observed digests and queue the runs they imply, in the one
/// transaction, returning how many runs are queued. Recording the digests
/// without queueing would lose the change: the next poll would compare against
/// the digests just stored and see nothing new.
fn observe(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let keys = Keys::from_args(args)?;
    let detector_set_digest = args.str("detector_set_digest")?;
    let now_ms = args.int("now_ms")?;
    let mut queued = 0_i64;
    for trigger_kind in observe_digests(connection, &keys, args)? {
        let request = Request {
            trigger_kind,
            detector_set_digest,
            kind: "deterministic",
            now_ms,
        };
        if !enqueue_locked(connection, &keys, &request, None)?.is_null() {
            queued += 1;
        }
    }
    Ok(Value::from(queued))
}

/// Store observed digests and return which triggers they imply.
fn observe_digests(
    connection: &Connection,
    keys: &Keys,
    args: &Args,
) -> StoreResult<Vec<&'static str>> {
    let stat_digest = args.opt_str("stat_digest")?;
    let feed_digest = args.opt_str("feed_digest")?;
    let Some(row) = query_one(
        connection,
        "select observed_stat_digest, observed_feed_digest from workspace_assessment_state \
         where codebase_key = ? and worktree_key = ? and paused = 0",
        &keys.params(),
    )?
    else {
        return Ok(Vec::new());
    };
    let mut triggers = Vec::new();
    if changed_from(&row, "observed_stat_digest", stat_digest) {
        triggers.push("file_change");
    }
    if changed_from(&row, "observed_feed_digest", feed_digest) {
        triggers.push("feed_change");
    }
    let [codebase, worktree] = keys.params();
    exec(
        connection,
        "update workspace_assessment_state set \
           observed_stat_digest = coalesce(?, observed_stat_digest), \
           observed_feed_digest = coalesce(?, observed_feed_digest) \
         where codebase_key = ? and worktree_key = ?",
        &[
            Value::from(stat_digest),
            Value::from(feed_digest),
            codebase,
            worktree,
        ],
    )?;
    Ok(triggers)
}

/// A digest counts as a change only against an earlier observation.
fn changed_from(row: &Row, column: &str, observed: Option<&str>) -> bool {
    match (row.get(column).and_then(Value::as_str), observed) {
        (Some(stored), Some(now)) => stored != now,
        _ => false,
    }
}

/// Roots of admitted worktrees, leaving out those last observed unavailable,
/// in pages keyed by the worktree. An unavailable root may now name another
/// worktree, so it is not proof that the worktree at that path is admitted.
fn watched_roots(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let unavailable = args.str("unavailable_digest")?;
    let after = match args.raw("after") {
        None => None,
        Some(Value::Array(cursor)) => match cursor.as_slice() {
            [Value::String(codebase), Value::String(worktree)] => {
                Some((codebase.as_str(), worktree.as_str()))
            }
            _ => return value_error("after must be a [codebase_key, worktree_key] pair"),
        },
        Some(_) => return value_error("after must be a [codebase_key, worktree_key] pair"),
    };
    let (scope, mut params) = match after {
        Some((codebase, worktree)) => (
            "and (codebase_key, worktree_key) > (?, ?)",
            vec![Value::from(codebase), Value::from(worktree)],
        ),
        None => ("", Vec::new()),
    };
    params.insert(0, Value::from(unavailable));
    let sql = format!(
        "select codebase_key, worktree_key, private_root from workspace_assessment_state \
         where (observed_stat_digest is null or observed_stat_digest != ?) \
           and not {IS_ENDED} {scope} \
         order by codebase_key, worktree_key"
    );
    let mut items: Vec<Value> = Vec::new();
    // The page envelope and its cursor of two keys count against the budget too.
    let mut bytes = ENVELOPE_BYTES;
    let mut last: Option<(String, String)> = None;
    let mut next = Value::Null;
    query_each(connection, &sql, &params, |row: Row| {
        let root = text(&row, "private_root").to_owned();
        // The bytes JSON sends for the root, quotes and escapes included,
        // plus its separator, so escaped paths cannot outgrow the reply.
        let size = serde_json::to_string(&root)
            .map_or(usize::MAX, |encoded| encoded.len())
            .saturating_add(1);
        if let Some((codebase, worktree)) = &last {
            if bytes.saturating_add(size) > PAGE_BYTES {
                next = json!([codebase, worktree]);
                return Ok(false);
            }
        }
        bytes = bytes.saturating_add(size);
        last = Some((
            text(&row, "codebase_key").to_owned(),
            text(&row, "worktree_key").to_owned(),
        ));
        items.push(Value::from(root));
        Ok(true)
    })?;
    Ok(json!({"items": items, "next": next}))
}

/// Whether someone admitted this worktree at `root` themselves and it is
/// still checked.
fn is_manual(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let keys = Keys::from_args(args)?;
    let [codebase, worktree] = keys.params();
    let row = query_one(
        connection,
        "select 1 as found from workspace_assessment_state s \
         where s.codebase_key = ? and s.worktree_key = ? and s.private_root = ? and s.paused = 0 \
           and not exists ( \
             select 1 from workspace_assessment_install_admissions a \
             where a.codebase_key = s.codebase_key and a.worktree_key = s.worktree_key \
           )",
        &[codebase, worktree, Value::from(args.str("root")?)],
    )?;
    Ok(Value::Bool(row.is_some()))
}

/// End automatic admissions whose root no active install registers. Only the
/// admission ends; the worktree's runs, findings and fix proposals stay.
fn end_unregistered(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let Some(registered) = args.strings("registered_roots")? else {
        return value_error("registered_roots must be a list of roots");
    };
    let registered: HashSet<&str> = registered.into_iter().collect();
    let now_ms = args.int("now_ms")?;
    let rows = query_all(
        connection,
        "select s.codebase_key, s.worktree_key, s.private_root from workspace_assessment_state s \
         join workspace_assessment_install_admissions a using (codebase_key, worktree_key)",
        &[],
    )?;
    let ended: Vec<Row> = rows
        .into_iter()
        .filter(|row| !registered.contains(text(row, "private_root")))
        .collect();
    end_admissions(connection, &ended, now_ms)?;
    Ok(Value::from(ended.len()))
}

/// Stop watching these worktrees, keeping every record that names them.
fn end_admissions(connection: &Connection, rows: &[Row], now_ms: i64) -> StoreResult<()> {
    for row in rows {
        let keys = [
            Value::from(text(row, "codebase_key")),
            Value::from(text(row, "worktree_key")),
        ];
        exec(
            connection,
            "delete from workspace_assessment_install_admissions \
             where codebase_key = ? and worktree_key = ?",
            &keys,
        )?;
        exec(
            connection,
            "update workspace_assessment_state set paused = 1 \
             where codebase_key = ? and worktree_key = ?",
            &keys,
        )?;
        let [codebase, worktree] = keys;
        exec(
            connection,
            "insert or ignore into workspace_assessment_ended_admissions \
               (codebase_key, worktree_key, ended_at_ms) values (?, ?, ?)",
            &[codebase, worktree, Value::from(now_ms)],
        )?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "guard_store_workspace_assessment_admissions_tests.rs"]
mod tests;
