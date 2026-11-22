//! The background workspace assessment queue, as `workspace_assessment_store`
//! drove it: queueing a worktree's run, leasing the next due run, renewing
//! and fencing that lease, and recording the outcome.
//!
//! Each admitted worktree has a dirty generation. A trigger bumps it and
//! leaves at most one queued run; a worker claims a run under a fenced lease,
//! and only the holder of the current lease generation can record its
//! outcome. A run whose snapshot changed while it ran is superseded and one
//! successor is queued, so results are never attached to content they did not
//! assess. Python supplies the instants, the outcome JSON text and the id of a
//! run it queues itself; every method runs in one write transaction.

use rusqlite::Connection;
use serde_json::{json, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{exec, int, query_all, query_one, text, value_error, StoreResult};

pub(crate) const DEBOUNCE_MS: i64 = 5_000;
/// Edits that never pause for the debounce still get assessed this often.
pub(crate) const MAX_DEBOUNCE_WAIT_MS: i64 = 60_000;
pub(crate) const MIN_INTERVAL_MS: i64 = 60_000;
pub(crate) const MAX_DEVICE_WORKERS: i64 = 2;
pub(crate) const LEASE_MS: i64 = 5 * 60_000;

const TRIGGERS: [&str; 5] = [
    "workspace_open",
    "file_change",
    "feed_change",
    "manual",
    "fix_verification",
];
/// User-requested runs skip the debounce and interval: someone is waiting.
const USER_TRIGGERS: [&str; 2] = ["manual", "fix_verification"];
const KINDS: [&str; 2] = ["deterministic", "verification"];
const FINISHED_STATES: [&str; 4] = ["completed", "partial", "failed", "superseded"];

pub(crate) fn handles(method: &str) -> bool {
    matches!(
        method,
        "enqueue_workspace_assessment"
            | "claim_workspace_assessment"
            | "finish_workspace_assessment"
            | "renew_workspace_assessment_lease"
            | "cancel_workspace_assessment"
    )
}

pub(crate) fn dispatch(connection: &Connection, method: &str, args: &Args) -> StoreResult<Value> {
    match method {
        "enqueue_workspace_assessment" => enqueue(connection, args),
        "claim_workspace_assessment" => claim(connection, args),
        "finish_workspace_assessment" => finish(connection, args),
        "renew_workspace_assessment_lease" => renew(connection, args),
        _ => cancel(connection, args),
    }
}

/// The worktree a call names.
pub(crate) struct Keys<'a> {
    pub(crate) codebase: &'a str,
    pub(crate) worktree: &'a str,
}

impl<'a> Keys<'a> {
    pub(crate) fn from_args(args: &Args<'a>) -> StoreResult<Self> {
        Ok(Self {
            codebase: args.str("codebase_key")?,
            worktree: args.str("worktree_key")?,
        })
    }

    pub(crate) fn params(&self) -> [Value; 2] {
        [Value::from(self.codebase), Value::from(self.worktree)]
    }
}

/// What a queued run is asked to do.
pub(crate) struct Request<'a> {
    pub(crate) trigger_kind: &'a str,
    pub(crate) detector_set_digest: &'a str,
    pub(crate) kind: &'a str,
    pub(crate) now_ms: i64,
}

fn enqueue(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let keys = Keys::from_args(args)?;
    let request = Request {
        trigger_kind: args.str("trigger_kind")?,
        detector_set_digest: args.str("detector_set_digest")?,
        kind: args.str("kind")?,
        now_ms: args.int("now_ms")?,
    };
    check_request(&request)?;
    enqueue_locked(connection, &keys, &request, Some(args.str("run_id")?))
}

/// A caller-supplied trigger and kind must be ones the queue knows.
pub(crate) fn check_request(request: &Request) -> StoreResult<()> {
    if !TRIGGERS.contains(&request.trigger_kind) {
        return value_error("unknown workspace assessment trigger");
    }
    if !KINDS.contains(&request.kind) {
        return value_error("unknown workspace assessment kind");
    }
    Ok(())
}

/// Mark the worktree dirty and return the one queued run that covers it, or
/// null when it is paused or not admitted. `run_id` names a run this call
/// inserts; without one a fresh id is drawn.
pub(crate) fn enqueue_locked(
    connection: &Connection,
    keys: &Keys,
    request: &Request,
    run_id: Option<&str>,
) -> StoreResult<Value> {
    let bumped = exec(
        connection,
        "update workspace_assessment_state set dirty_generation = dirty_generation + 1 \
         where codebase_key = ? and worktree_key = ? and paused = 0",
        &keys.params(),
    )?;
    if bumped != 1 {
        return Ok(Value::Null);
    }
    let state = query_one(
        connection,
        "select dirty_generation from workspace_assessment_state \
         where codebase_key = ? and worktree_key = ?",
        &keys.params(),
    )?;
    let generation = state.map_or(0, |row| int(&row, "dirty_generation"));
    let queued = query_one(
        connection,
        "select run_id, trigger_kind from workspace_assessment_runs \
         where codebase_key = ? and worktree_key = ? and state = 'queued'",
        &keys.params(),
    )?;
    if let Some(queued) = queued {
        // Coalesce: the queued run now covers the newer generation and the
        // debounce restarts from this trigger. A user request upgrades an
        // automatic one so it is not held by the debounce. The run records
        // the detector set of the daemon that now covers it, which is the set
        // that will execute it.
        let upgraded = if USER_TRIGGERS.contains(&request.trigger_kind) {
            request.trigger_kind
        } else {
            text(&queued, "trigger_kind")
        };
        let queued_id = text(&queued, "run_id");
        exec(
            connection,
            "update workspace_assessment_runs set \
               dirty_generation = ?, trigger_kind = ?, triggered_at_ms = max(triggered_at_ms, ?), \
               detector_set_digest = ? \
             where run_id = ?",
            &[
                Value::from(generation),
                Value::from(upgraded),
                Value::from(request.now_ms),
                Value::from(request.detector_set_digest),
                Value::from(queued_id),
            ],
        )?;
        return Ok(Value::from(queued_id));
    }
    let run_id = match run_id {
        Some(id) => id.to_owned(),
        None => fresh_run_id()?,
    };
    let [codebase, worktree] = keys.params();
    exec(
        connection,
        "insert into workspace_assessment_runs ( \
           run_id, codebase_key, worktree_key, detector_set_digest, kind, trigger_kind, \
           state, dirty_generation, created_at_ms, triggered_at_ms \
         ) values (?, ?, ?, ?, ?, ?, 'queued', ?, ?, ?)",
        &[
            Value::from(run_id.as_str()),
            codebase,
            worktree,
            Value::from(request.detector_set_digest),
            Value::from(request.kind),
            Value::from(request.trigger_kind),
            Value::from(generation),
            Value::from(request.now_ms),
            Value::from(request.now_ms),
        ],
    )?;
    Ok(Value::from(run_id))
}

/// 32 lowercase hex characters, the shape `uuid.uuid4().hex` gave.
fn fresh_run_id() -> StoreResult<String> {
    let mut bytes = [0_u8; 16];
    if getrandom::fill(&mut bytes).is_err() {
        return value_error("workspace assessment run id entropy unavailable");
    }
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// Lease the next due run. `detector_set_digest`, when given, is the set the
/// caller will execute: a run queued by an older daemon is relabelled with it,
/// so the stored digest names the detectors that produced the result.
/// `user_only` leaves automatic runs queued, for a host under pressure.
fn claim(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let owner = args.str("owner")?;
    let now_ms = args.int("now_ms")?;
    let caller_digest = args.opt_str("detector_set_digest")?;
    let user_only = args.flag("user_only")?;
    expire_leases(connection, now_ms)?;
    let running = query_one(
        connection,
        "select count(*) as running from workspace_assessment_runs where state = 'running'",
        &[],
    )?;
    if running.map_or(0, |row| int(&row, "running")) >= MAX_DEVICE_WORKERS {
        return Ok(Value::Null);
    }
    let Some(row) = query_one(
        connection,
        "select r.run_id, r.codebase_key, r.worktree_key, s.private_root, r.trigger_kind, r.kind, \
                r.dirty_generation, r.lease_generation, r.detector_set_digest \
         from workspace_assessment_runs r \
         join workspace_assessment_state s \
           on s.codebase_key = r.codebase_key and s.worktree_key = r.worktree_key \
         where r.state = 'queued' and s.paused = 0 \
           and not exists ( \
             select 1 from workspace_assessment_runs active \
             where active.codebase_key = r.codebase_key and active.worktree_key = r.worktree_key \
               and active.state = 'running' \
           ) \
           and ( \
             r.trigger_kind in (?, ?) \
             or (? = 0 \
                 and (r.triggered_at_ms <= ? or r.created_at_ms <= ?) \
                 and (s.last_scan_at_ms is null or s.last_scan_at_ms <= ?)) \
           ) \
         order by r.created_at_ms, r.run_id \
         limit 1",
        &[
            Value::from(USER_TRIGGERS[0]),
            Value::from(USER_TRIGGERS[1]),
            Value::from(i64::from(user_only)),
            Value::from(now_ms - DEBOUNCE_MS),
            Value::from(now_ms - MAX_DEBOUNCE_WAIT_MS),
            Value::from(now_ms - MIN_INTERVAL_MS),
        ],
    )?
    else {
        return Ok(Value::Null);
    };
    let lease_generation = int(&row, "lease_generation") + 1;
    let digest = caller_digest.unwrap_or_else(|| text(&row, "detector_set_digest"));
    exec(
        connection,
        "update workspace_assessment_runs set \
           state = 'running', lease_generation = ?, lease_owner = ?, lease_until_ms = ?, \
           started_at_ms = ?, detector_set_digest = ? \
         where run_id = ? and state = 'queued'",
        &[
            Value::from(lease_generation),
            Value::from(owner),
            Value::from(now_ms + LEASE_MS),
            Value::from(now_ms),
            Value::from(digest),
            Value::from(text(&row, "run_id")),
        ],
    )?;
    Ok(json!({
        "run_id": text(&row, "run_id"),
        "codebase_key": text(&row, "codebase_key"),
        "worktree_key": text(&row, "worktree_key"),
        "private_root": text(&row, "private_root"),
        "trigger_kind": text(&row, "trigger_kind"),
        "kind": text(&row, "kind"),
        "dirty_generation": int(&row, "dirty_generation"),
        "lease_generation": lease_generation,
        "detector_set_digest": digest,
    }))
}

fn expire_leases(connection: &Connection, now_ms: i64) -> StoreResult<()> {
    let expired = query_all(
        connection,
        "select run_id, codebase_key, worktree_key, trigger_kind, detector_set_digest, kind, \
                created_at_ms \
         from workspace_assessment_runs where state = 'running' and lease_until_ms < ?",
        &[Value::from(now_ms)],
    )?;
    for row in expired {
        let keys = Keys {
            codebase: text(&row, "codebase_key"),
            worktree: text(&row, "worktree_key"),
        };
        // The runner renews its lease between stages, so an expired lease
        // means the worker died or one stage hung. Retry once; a retry that
        // also expires would repeat forever, so the worktree stays stale
        // until its next change or request instead.
        let retry = is_lease_retry(connection, &keys, int(&row, "created_at_ms"))?;
        let error_code = if retry {
            "assessment_timed_out"
        } else {
            "lease_expired"
        };
        exec(
            connection,
            "update workspace_assessment_runs set \
               state = 'failed', error_code = ?, finished_at_ms = ?, \
               lease_generation = lease_generation + 1 \
             where run_id = ?",
            &[
                Value::from(error_code),
                Value::from(now_ms),
                Value::from(text(&row, "run_id")),
            ],
        )?;
        if retry {
            continue;
        }
        let request = Request {
            trigger_kind: text(&row, "trigger_kind"),
            detector_set_digest: text(&row, "detector_set_digest"),
            kind: text(&row, "kind"),
            now_ms,
        };
        enqueue_locked(connection, &keys, &request, None)?;
    }
    Ok(())
}

/// A retry is inserted in the same transaction that expires the run before
/// it, so it was created at that run's finish time. A run queued later (for
/// example after a paused worktree resumes) gets its own retry.
fn is_lease_retry(connection: &Connection, keys: &Keys, created_at_ms: i64) -> StoreResult<bool> {
    let [codebase, worktree] = keys.params();
    Ok(query_one(
        connection,
        "select 1 as found from workspace_assessment_runs \
         where codebase_key = ? and worktree_key = ? and error_code = 'lease_expired' \
           and finished_at_ms = ? \
         limit 1",
        &[codebase, worktree, Value::from(created_at_ms)],
    )?
    .is_some())
}

/// Record an outcome only if the run still holds the current lease.
fn finish(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let keys = Keys::from_args(args)?;
    let state = args.str("state")?;
    if !FINISHED_STATES.contains(&state) {
        return value_error("invalid workspace assessment outcome state");
    }
    let now_ms = args.int("now_ms")?;
    let feed_context_digest = args.opt_str("feed_context_digest")?;
    let changed = exec(
        connection,
        "update workspace_assessment_runs set \
           state = ?, snapshot_digest = ?, input_manifest_digest = ?, feed_context_digest = ?, \
           coverage_json = ?, findings_json = ?, error_code = ?, finished_at_ms = ?, \
           lease_owner = null, lease_until_ms = null \
         where run_id = ? and state = 'running' and lease_generation = ? and lease_until_ms >= ?",
        &[
            Value::from(state),
            Value::from(args.opt_str("snapshot_digest")?),
            Value::from(args.opt_str("input_manifest_digest")?),
            Value::from(feed_context_digest),
            Value::from(args.str("coverage_json")?),
            Value::from(args.str("findings_json")?),
            Value::from(args.opt_str("error_code")?),
            Value::from(now_ms),
            Value::from(args.str("run_id")?),
            Value::from(args.int("lease_generation")?),
            Value::from(now_ms),
        ],
    )?;
    if changed != 1 {
        return Ok(Value::Bool(false));
    }
    let [codebase, worktree] = keys.params();
    if state == "completed" || state == "partial" {
        exec(
            connection,
            "update workspace_assessment_state set \
               last_completed_generation = max(last_completed_generation, min(?, dirty_generation)), \
               last_scan_at_ms = ?, \
               observed_feed_digest = coalesce(?, observed_feed_digest) \
             where codebase_key = ? and worktree_key = ?",
            &[
                Value::from(args.int("dirty_generation")?),
                Value::from(now_ms),
                Value::from(feed_context_digest),
                codebase,
                worktree,
            ],
        )?;
    } else {
        exec(
            connection,
            "update workspace_assessment_state set last_scan_at_ms = ? \
             where codebase_key = ? and worktree_key = ?",
            &[Value::from(now_ms), codebase, worktree],
        )?;
    }
    if state == "superseded" {
        // The successor keeps a user request's trigger so it is not held
        // back by the debounce the user already bypassed.
        let trigger_kind = args.str("trigger_kind")?;
        let successor = if USER_TRIGGERS.contains(&trigger_kind) {
            trigger_kind
        } else {
            "file_change"
        };
        let request = Request {
            trigger_kind: successor,
            detector_set_digest: args.str("detector_set_digest")?,
            kind: args.str("kind")?,
            now_ms,
        };
        enqueue_locked(connection, &keys, &request, None)?;
    }
    Ok(Value::Bool(true))
}

/// Extend a run's lease between stages; false once it is canceled, expired
/// or fenced.
fn renew(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let now_ms = args.int("now_ms")?;
    let changed = exec(
        connection,
        "update workspace_assessment_runs set lease_until_ms = ? \
         where run_id = ? and state = 'running' and lease_generation = ? and lease_until_ms >= ?",
        &[
            Value::from(now_ms + LEASE_MS),
            Value::from(args.str("run_id")?),
            Value::from(args.int("lease_generation")?),
            Value::from(now_ms),
        ],
    )?;
    Ok(Value::Bool(changed == 1))
}

/// Cancel a queued or running run; a running worker's lease is fenced off.
fn cancel(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let changed = exec(
        connection,
        "update workspace_assessment_runs set \
           state = 'canceled', finished_at_ms = ?, lease_owner = null, lease_until_ms = null, \
           lease_generation = lease_generation + 1 \
         where run_id = ? and state in ('queued', 'running')",
        &[
            Value::from(args.int("now_ms")?),
            Value::from(args.str("run_id")?),
        ],
    )?;
    Ok(Value::Bool(changed == 1))
}

#[cfg(test)]
#[path = "guard_store_workspace_assessment_queue_tests.rs"]
pub(crate) mod tests;
