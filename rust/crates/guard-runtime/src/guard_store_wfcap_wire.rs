//! Plan/commit entry points of the workflow-capability authority.
//!
//! The control blob lives in the caller's credential store, so an operation
//! runs twice. `plan` executes it in a rolled-back transaction and reports
//! the outcome with every control write it needs persisted. After the caller
//! persists those writes, `commit` replays the operation in a real
//! transaction and refuses (`stale`) if it no longer produces exactly the
//! planned writes. Any control write that must follow the database commit is
//! returned for the caller to persist afterwards.

use rusqlite::Connection;
use serde_json::{json, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{StoreError, StoreResult};
use crate::guard_store_wfcap_ctx::Ctx;
use crate::guard_store_wfcap_error::{WfError, WfResult};
use crate::guard_store_wfcap_ops::{prelude, run};

const STALE: StoreError = StoreError::Invalid("native_guard_store_capability_plan_stale");

struct Outcome {
    result: WfResult<Value>,
    writes: Vec<String>,
    post_commit: Vec<String>,
}

fn execute(conn: &Connection, args: &Args<'_>) -> StoreResult<Outcome> {
    let op = args.str("op")?;
    let now = args.str("now")?;
    let prepared = prelude(op, args);
    let (result, writes, post_commit) = match prepared {
        Err(error) => (Err(error), Vec::new(), Vec::new()),
        Ok(()) => {
            match Ctx::new(
                conn,
                args.opt_str("key_b64")?,
                args.opt_str("key_id")?,
                now,
                args.opt_str("control_blob")?,
            ) {
                Err(error) => (Err(error), Vec::new(), Vec::new()),
                Ok(mut ctx) => {
                    let result = run(op, &mut ctx, args);
                    let (writes, post_commit) = ctx.into_writes();
                    (result, writes, post_commit)
                }
            }
        }
    };
    if let Err(WfError::Store(error)) = result {
        return Err(error);
    }
    Ok(Outcome {
        result,
        writes,
        post_commit,
    })
}

fn schema_version(conn: &Connection) -> StoreResult<i64> {
    Ok(conn.query_row("pragma schema_version", [], |row| row.get(0))?)
}

fn error_value(error: &WfError) -> Value {
    match error {
        WfError::Capability(code) => json!({"kind": "capability", "code": code}),
        WfError::Runtime(message) => json!({"kind": "runtime", "message": message}),
        _ => Value::Null,
    }
}

/// `workflow_capability_plan` (runs in a transaction the caller rolls back).
pub(crate) fn plan(conn: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    let changes = conn.total_changes();
    let schema = schema_version(conn)?;
    let outcome = execute(conn, args)?;
    let dirty = conn.total_changes() != changes || schema_version(conn)? != schema;
    Ok(match &outcome.result {
        Ok(result) => json!({
            "ok": true,
            "result": result,
            "writes": outcome.writes,
            "post_writes": outcome.post_commit,
            "commit": dirty || !outcome.post_commit.is_empty(),
        }),
        Err(error) => json!({
            "ok": false,
            "error": error_value(error),
            "writes": outcome.writes,
        }),
    })
}

/// `workflow_capability_commit` (runs in the write transaction).
pub(crate) fn commit(conn: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    let outcome = execute(conn, args)?;
    let planned = args.strings("plan_writes")?.unwrap_or_default();
    let planned_post = args.strings("plan_post_writes")?.unwrap_or_default();
    let matches = outcome
        .writes
        .iter()
        .map(String::as_str)
        .eq(planned.iter().copied())
        && outcome
            .post_commit
            .iter()
            .map(String::as_str)
            .eq(planned_post.iter().copied());
    match outcome.result {
        Ok(result) if matches => Ok(json!({
            "result": result,
            "post_writes": outcome.post_commit,
        })),
        _ => Err(STALE),
    }
}
