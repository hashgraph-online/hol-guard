//! `transition_native_workspace_review_replay_marker`: move one request's
//! replay marker through a named step.
//!
//! - `probed`: the replay loop built (or failed to build) the request's
//!   native context. No valid authority backs the marker off; an authority the
//!   server already accepted is probed again later; any other authority comes
//!   back as the seed the caller requeues the request's events with.
//! - `requeued`: the requeue finished; record how many events it requeued.
//! - `accepted`: the server accepted a replayed event's authority-bound claim.

use rusqlite::Connection;
use serde_json::{json, Map, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{value_error, StoreResult};

use super::{
    after, authority_is_accepted, authority_is_replayed, authority_marker, failure_marker,
    replay_seed, request, same_binding, stored, write, Request, PROBE_INTERVAL_SECONDS,
};

fn probed(
    connection: &Connection,
    args: &Args<'_>,
    request: &Request<'_>,
    changed_at: &str,
) -> StoreResult<Value> {
    let previous = stored(connection, &request.key)?;
    let Some(authority) = authority_marker(args.opt_object("authority")?, request) else {
        let marker = failure_marker(previous.as_ref(), request)?;
        let marker = write(connection, request, marker, changed_at)?;
        return Ok(json!({"action": "failed", "marker": marker}));
    };
    let current = previous
        .as_ref()
        .filter(|marker| same_binding(marker, request.binding));
    if let Some(marker) = current.filter(|marker| authority_is_accepted(Some(*marker), &authority))
    {
        let mut probe = marker.clone();
        probe.extend(authority);
        probe.insert(
            "next_probe_at".to_owned(),
            json!(after(request, PROBE_INTERVAL_SECONDS)?),
        );
        let marker = write(connection, request, probe, changed_at)?;
        return Ok(json!({"action": "accepted", "marker": marker}));
    }
    let seed = replay_seed(previous.as_ref(), &authority, request)?;
    Ok(json!({"action": "requeue", "seed": seed}))
}

fn requeued(
    connection: &Connection,
    args: &Args<'_>,
    request: &Request<'_>,
    changed_at: &str,
) -> StoreResult<Value> {
    let seed = args.object("seed")?;
    let count = args.int("count")?;
    let attempts = seed.get("attempts").and_then(Value::as_i64);
    let owned = seed.get("request_id").and_then(Value::as_str) == Some(request.request_id)
        && same_binding(seed, request.binding);
    let Some(attempts) = attempts.filter(|_| owned) else {
        return value_error("invalid_seed");
    };
    let mut marker = seed.clone();
    marker.insert("requeued".to_owned(), json!(count));
    marker.insert(
        "attempts".to_owned(),
        json!(if count > 0 { 0 } else { attempts }),
    );
    let marker = write(connection, request, marker, changed_at)?;
    Ok(json!({"marker": marker}))
}

/// `fallback` is the marker the caller rebuilt from the delivery's commit
/// state; the stored marker wins while its binding is the current one.
fn accepted(
    connection: &Connection,
    args: &Args<'_>,
    request: &Request<'_>,
    changed_at: &str,
) -> StoreResult<Value> {
    let current = stored(connection, &request.key)?;
    let fallback: Option<&Map<String, Value>> = args.opt_object("fallback")?;
    let previous = current
        .as_ref()
        .filter(|marker| same_binding(marker, request.binding))
        .or_else(|| fallback.filter(|marker| same_binding(marker, request.binding)));
    let authority = authority_marker(args.opt_object("authority")?, request);
    let Some(authority) = authority.filter(|authority| authority_is_replayed(previous, authority))
    else {
        return Ok(json!({"result": "unmatched"}));
    };
    if authority_is_accepted(previous, &authority) {
        return Ok(json!({"result": "already"}));
    }
    let Some(previous) = previous else {
        return Ok(json!({"result": "unmatched"}));
    };
    let mut marker = previous.clone();
    marker.extend(authority);
    marker.insert("accepted".to_owned(), json!(true));
    marker.insert("accepted_at".to_owned(), json!(request.now));
    marker.insert("attempts".to_owned(), json!(0));
    marker.insert(
        "next_probe_at".to_owned(),
        json!(after(request, PROBE_INTERVAL_SECONDS)?),
    );
    let marker = write(connection, request, marker, changed_at)?;
    Ok(json!({"result": "accepted", "marker": marker}))
}

pub(crate) fn method(connection: &Connection, args: &Args<'_>) -> StoreResult<Value> {
    let request = request(args)?;
    let changed_at = args.opt_str("changed_at")?.unwrap_or(request.now);
    match args.str("step")? {
        "probed" => probed(connection, args, &request, changed_at),
        "requeued" => requeued(connection, args, &request, changed_at),
        "accepted" => accepted(connection, args, &request, changed_at),
        _ => value_error("invalid_step"),
    }
}

#[cfg(test)]
#[path = "guard_store_review_replay_step_tests.rs"]
mod tests;
