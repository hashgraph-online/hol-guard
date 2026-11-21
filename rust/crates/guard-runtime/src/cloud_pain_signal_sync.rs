//! Upload the cloud pain signals (`runner.sync_pain_signals`): the install
//! stops, warnings and changed artifacts recorded in the local event log since
//! the last upload.

use guard_command::local_supply_chain::utc_now_iso;
use rusqlite::{params_from_iter, OpenFlags};
use serde_json::{json, Value};

use crate::cloud_bundle_fetch::{resolve_auth, unreachable_message, SyncError};
use crate::cloud_event_sync::{
    answer_text, post, route_url, screen_supplied, trusted_base, EventStore, Refusal,
    EVENTS_BODY_LIMIT, PAIN_SIGNAL_TIMEOUTS,
};

pub(crate) const PAIN_SIGNAL_CURSOR_KEY: &str = "pain_signal_cursor";
const PAIN_SIGNAL_BATCH: usize = 500;
/// `sorted(_PAIN_SIGNAL_EVENTS)`.
const PAIN_SIGNAL_EVENTS: [&str; 8] = [
    "approval_gate/remote_policy_sync_blocked",
    "changed_artifact_caught",
    "install_time_block",
    "install_time_require-reapproval",
    "install_time_review",
    "install_time_sandbox-required",
    "install_time_warn",
    "supply_chain_bundle_refresh_requested",
];

/// `store.list_events_after(event_id, limit=500, event_names=...)`.
fn pain_signal_candidates(store: &EventStore<'_>, after: i64) -> Result<Vec<Value>, SyncError> {
    let failed =
        |error: rusqlite::Error| SyncError::Failed(format!("Guard store read failed: {error}"));
    // Hold the storage gate for the read only, never across the upload.
    let _gate = store.hold_gate()?;
    let connection = rusqlite::Connection::open_with_flags(
        store.store_path(),
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(failed)?;
    let placeholders = vec!["?"; PAIN_SIGNAL_EVENTS.len()].join(", ");
    let mut statement = connection
        .prepare(&format!(
            "select event_id, event_name, payload_json, occurred_at from guard_events \
             where event_id > ? and event_name in ({placeholders}) order by event_id asc limit ?"
        ))
        .map_err(failed)?;
    let mut bound: Vec<rusqlite::types::Value> = vec![after.into()];
    bound.extend(
        PAIN_SIGNAL_EVENTS
            .iter()
            .map(|name| rusqlite::types::Value::from((*name).to_owned())),
    );
    bound.push((PAIN_SIGNAL_BATCH as i64).into());
    let rows = statement
        .query_map(params_from_iter(bound), |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(failed)?;
    let mut items = Vec::new();
    for row in rows {
        let (event_id, event_name, payload_json, occurred_at) = row.map_err(failed)?;
        let payload = match serde_json::from_str::<Value>(&payload_json) {
            Ok(Value::Object(payload)) => Value::Object(payload),
            Ok(_) => json!({}),
            Err(_) => {
                return Err(SyncError::Failed(
                    "Guard event payload is not JSON.".to_owned(),
                ))
            }
        };
        items.push(json!({
            "event_id": event_id,
            "event_name": event_name,
            "occurred_at": occurred_at,
            "payload": payload,
        }));
    }
    Ok(items)
}

/// `sync_pain_signals`: the number of signals uploaded.
pub(crate) fn sync_pain_signals(store: &EventStore<'_>) -> Result<Value, SyncError> {
    let supplied = store.bundle.auth.as_ref().filter(|auth| !auth.is_empty());
    screen_supplied(supplied)?;
    let auth = match resolve_auth(&store.bundle.resident, false, supplied) {
        Err(SyncError::NotConfigured(_)) => return Ok(json!(0)),
        other => other?,
    };
    let url = route_url(
        "pain_signal",
        &route_url("receipts", &trusted_base(&auth)?)?,
    )?;
    let mut current = store
        .payload(PAIN_SIGNAL_CURSOR_KEY)?
        .and_then(|cursor| cursor.get("event_id").and_then(Value::as_i64))
        .filter(|id| *id > 0)
        .unwrap_or(0);
    // Batches an earlier broker round uploaded moved the cursor past them,
    // and the warning counts as of that cursor carry over with it.
    let (mut uploaded, mut warn_counts) = {
        let progress = store.progress.borrow();
        (
            progress.pain_signals,
            progress
                .pain_warn_counts
                .clone()
                .unwrap_or_else(|| json!([])),
        )
    };
    loop {
        let held = store.progress.borrow_mut().held_pain_signals.take();
        let candidates = match held {
            Some((cursor, held)) if cursor == current => held,
            _ => pain_signal_candidates(store, current)?,
        };
        if candidates.is_empty() {
            break;
        }
        let (covered, items, next_counts) = batch_within_body_limit(&candidates, &warn_counts)?;
        if !items.is_empty() {
            match post(
                &auth,
                &url,
                &json!({"items": items}),
                false,
                PAIN_SIGNAL_TIMEOUTS,
            ) {
                Ok(_) => uploaded += items.len(),
                Err(Err(SyncError::Pending)) => {
                    // The next round sends this batch again to read its answer.
                    store.progress.borrow_mut().held_pain_signals = Some((current, candidates));
                    return Err(SyncError::Pending);
                }
                Err(Err(error)) => return Err(error),
                Err(Ok(Refusal::Http {
                    status: 404 | 429, ..
                })) => return Ok(json!(uploaded)),
                Err(Ok(Refusal::Http { status, answer, .. })) => {
                    return Err(SyncError::Failed(answer_text(
                        answer.as_ref(),
                        "sync_message",
                        status,
                    )));
                }
                Err(Ok(Refusal::Transport(reason))) => {
                    return Err(SyncError::Failed(unreachable_message(&reason)));
                }
            }
        }
        warn_counts = next_counts;
        current = candidates[covered - 1]
            .get("event_id")
            .and_then(Value::as_i64)
            .filter(|id| *id != 0)
            .unwrap_or(current);
        store.save(
            PAIN_SIGNAL_CURSOR_KEY,
            &json!({"event_id": current}),
            &utc_now_iso(),
        )?;
        {
            let mut progress = store.progress.borrow_mut();
            progress.pain_signals = uploaded;
            progress.pain_warn_counts = Some(warn_counts.clone());
        }
        if covered == candidates.len() && candidates.len() < PAIN_SIGNAL_BATCH {
            break;
        }
    }
    Ok(json!(uploaded))
}

/// The leading candidates whose upload body fits the egress broker's request
/// limit, the items built from them and the warning counts after them. The
/// broker refuses a larger body before any request, so the candidate count is
/// halved until the body fits. A lone candidate that still does not fit is
/// passed over with no items, so it cannot hold back the signals after it.
fn batch_within_body_limit(
    candidates: &[Value],
    warn_counts: &Value,
) -> Result<(usize, Vec<Value>, Value), SyncError> {
    let mut covered = candidates.len();
    loop {
        let batch = crate::runner_sync_signals::pain_signal_batch(&json!({
            "events": &candidates[..covered],
            "warn_counts": warn_counts,
        }))
        .map_err(|reason| SyncError::Failed(format!("Guard pain signals failed: {reason}")))?;
        let next_counts = batch
            .get("warn_counts")
            .cloned()
            .unwrap_or_else(|| json!([]));
        let items = batch
            .get("items")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let size =
            serde_json::to_vec(&json!({"items": &items})).map_or(usize::MAX, |body| body.len());
        if size <= EVENTS_BODY_LIMIT {
            return Ok((covered, items, next_counts));
        }
        if covered == 1 {
            return Ok((1, Vec::new(), next_counts));
        }
        covered /= 2;
    }
}

#[cfg(test)]
#[path = "cloud_pain_signal_sync_tests.rs"]
mod tests;
