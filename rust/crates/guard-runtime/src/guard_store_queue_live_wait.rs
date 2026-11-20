//! A Codex hook's live wait, linked and seeded in its review's queue write.
//!
//! The native Codex bridge holds the tool call open while the user decides.
//! An approval only releases that hook when the request has an operation
//! naming the waiting process and a resume record seeded from it. The hook
//! used to write the operation, the request and the resume record in three
//! store calls. `add_approval_request` now takes the wait as
//! `codex_live_wait` and writes all three in the queue write's transaction:
//! the operation first, so the request is never approvable without it.

use rusqlite::Connection;
use serde_json::{Map, Value};

use crate::codex_live_wait_build::NOT_LIVE_KEY;
use crate::codex_request_resume_op::{seed, Call};
use crate::guard_store_args::Args;
use crate::guard_store_db::{StoreError, StoreResult};
use crate::guard_store_sessions::link_codex_live_wait;

const INVALID: StoreError = StoreError::Invalid("native_guard_store_args_invalid");
const UNSEEDED: StoreError = StoreError::Invalid("native_guard_store_live_wait_unseeded");

/// Runs `write` for the request in `args`, linking and seeding the Codex live
/// wait in `codex_live_wait` around it.
///
/// A link that fails is rolled back and the request is queued without its
/// `continuation_snapshot`, so it stays retry-only. A failure after the write
/// only leaves that wait unresumable; the reply names it in `live_wait` and
/// the queued review stays. Without `codex_live_wait` this is `write` alone,
/// and a wait the resident would not build is reported as `not_live`.
pub(crate) fn queue_with_live_wait(
    connection: &Connection,
    args: &Args<'_>,
    write: impl FnOnce(&Args<'_>) -> StoreResult<Value>,
) -> StoreResult<Value> {
    let Some(wait) = args.opt_object("codex_live_wait")? else {
        let written = write(args)?;
        if !args.flag(NOT_LIVE_KEY)? {
            return Ok(written);
        }
        // The hook sent its wait, but its bridge is no live process with a
        // wait budget: the request is a manual retry and the reply says so.
        return Ok(match written {
            Value::String(stored_id) => {
                serde_json::json!({"request_id": stored_id, "live_wait": "not_live"})
            }
            Value::Object(mut reply) => {
                reply.insert("live_wait".to_owned(), Value::from("not_live"));
                Value::Object(reply)
            }
            other => other,
        });
    };
    let request = args.object("request")?;
    let request_id = request
        .get("request_id")
        .and_then(Value::as_str)
        .ok_or(INVALID)?;
    let now = args.str("now")?;
    // An error rolls the whole store call back; a request the write declines
    // to store rolls back its link here.
    connection.execute_batch("savepoint live_wait_queue")?;
    // Only a Codex approval can be resumed; any other request is queued as
    // it came and its wait is not linked.
    let codex = request.get("harness").and_then(Value::as_str) == Some("codex");
    let linked = if codex {
        savepoint(connection, || link(connection, wait, request_id, now))
    } else {
        Err(INVALID)
    };
    let written = if linked.is_ok() || !codex {
        write(args)?
    } else {
        let mut request = request.clone();
        request.remove("continuation_snapshot");
        let mut retry_only = args.0.clone();
        retry_only.insert("request".to_owned(), Value::Object(request));
        write(&Args(&retry_only))?
    };
    let mut reply = match written {
        Value::String(stored_id) => {
            Map::from_iter([("request_id".to_owned(), Value::String(stored_id))])
        }
        Value::Object(reply) => reply,
        other => {
            connection.execute_batch("rollback to live_wait_queue; release live_wait_queue")?;
            return Ok(other);
        }
    };
    connection.execute_batch("release live_wait_queue")?;
    let stored_id = reply
        .get("request_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let outcome = linked.and_then(|()| {
        // A retry of a still-pending action folds into the existing row. The
        // link made for the unused id is dropped, and the bridge now waiting
        // is the retry's, so that row's operation is pointed at it before the
        // record is seeded.
        if stored_id != request_id {
            savepoint(connection, || discard(connection, request_id))?;
        }
        savepoint(connection, || {
            if stored_id != request_id {
                link(connection, wait, &stored_id, now)?;
            }
            let seeded = seed(
                connection,
                &Call {
                    request_id: &stored_id,
                    now,
                },
            )?;
            seeded.map(|_| ()).ok_or(UNSEEDED)
        })
    });
    let status = match outcome {
        Ok(()) => Value::from("seeded"),
        Err(error) => Value::from(error.code()),
    };
    reply.insert("live_wait".to_owned(), status);
    Ok(Value::Object(reply))
}

fn link(
    connection: &Connection,
    wait: &Map<String, Value>,
    request_id: &str,
    now: &str,
) -> StoreResult<()> {
    let mut link_args = wait.clone();
    link_args.insert("request_id".to_owned(), Value::from(request_id));
    link_args.insert("now".to_owned(), Value::from(now));
    link_codex_live_wait(connection, &Args(&link_args)).map(|_| ())
}

fn discard(connection: &Connection, request_id: &str) -> StoreResult<()> {
    let id = format!("codex-hook-{request_id}");
    connection.execute(
        "delete from guard_operations where operation_id = ?1",
        [&id],
    )?;
    connection.execute("delete from guard_sessions where session_id = ?1", [&id])?;
    Ok(())
}

fn savepoint(connection: &Connection, work: impl FnOnce() -> StoreResult<()>) -> StoreResult<()> {
    connection.execute_batch("savepoint live_wait")?;
    let result = work();
    connection.execute_batch(if result.is_ok() {
        "release live_wait"
    } else {
        "rollback to live_wait; release live_wait"
    })?;
    result
}

#[cfg(test)]
#[path = "guard_store_queue_live_wait_tests.rs"]
mod tests;
