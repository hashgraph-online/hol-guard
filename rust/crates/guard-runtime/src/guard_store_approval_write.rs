//! The approval queue write (`GuardStore.add_approval_request`, once a
//! Python writer plus its outbox bind).
//!
//! The canonical surfaces and the queue identity are derived in process, so
//! the whole write runs under the store op's one immediate transaction.
//! `add_approval_request` backfills legacy rows first, as the Python writer
//! did. `add_native_review_approval_request`, for a review the resident
//! queues itself, answers `null` while legacy rows wait, and the daemon
//! queues the review through `add_approval_request`.

use std::collections::HashSet;

use guard_contracts::ApprovalQueueIdentityItemV1;
use rusqlite::Connection;
use serde_json::Value;

use crate::approval_queue_identity_op::identify;
use crate::guard_store_approval_backfill;
use crate::guard_store_approval_created::record_created_events;
use crate::guard_store_approval_request::ApprovalRequest;
use crate::guard_store_approval_row::{insert, update, Derived};
use crate::guard_store_args::Args;
use crate::guard_store_db::{
    exec, placeholders, query_all, query_one, text, StoreError, StoreResult,
};
use crate::guard_store_json::py_strip;
use crate::guard_store_outbox_binding::bind_events_for_request;
use crate::signal_projection_receipt::surfaces;

/// `_REQUEST_ID_CHUNK`: one lookup stays under SQLite's host-parameter cap.
const REQUEST_ID_CHUNK: usize = 500;
/// `_PROJECTION_BATCH_BYTES`. A stored row the daemon could not project in
/// one resident request is left to the daemon.
const PROJECTION_ROW_BYTES: usize = 3 * 1024 * 1024;
const FRESH_REVIEW_REQUIRED: &str = "fresh_review_request_id_required";
const SUPERSEDED: &str = "superseded_by_fresh_review:";
const IDENTITY_INVALID: &str = "native_approval_queue_identity_invalid";
/// `ApprovalQueueIdentityUnavailableError`'s message.
const IDENTITY_UNAVAILABLE: &str = "native_approval_queue_identity_unavailable";
const INVALID_ARGS: &str = "native_guard_store_args_invalid";

pub(crate) fn add_native_review_approval_request(
    connection: &Connection,
    source: &str,
    args: &Args,
) -> StoreResult<Value> {
    let request = ApprovalRequest::decode(args.raw("request"))?;
    let now = args.str("now")?;
    let derived = derive(&request)?;
    if legacy_rows_pending(connection)? {
        return Ok(Value::Null);
    }
    persist(connection, source, &request, &derived, now).map(Value::String)
}

/// `GuardStore.add_approval_request`: the queue write of every caller. Legacy
/// rows are backfilled in the same transaction first, and a request the
/// resident cannot identify answers Python's
/// `ApprovalQueueIdentityUnavailableError` message.
pub(crate) fn add_approval_request(
    connection: &Connection,
    source: &str,
    args: &Args,
) -> StoreResult<Value> {
    // `queue_blocked_approvals` records the creation events; other writers
    // leave `prompt_shown` out.
    let prompt_shown = match args.raw("prompt_shown") {
        None | Some(Value::Null) => None,
        Some(value) => Some(value.as_bool().ok_or(StoreError::Invalid(INVALID_ARGS))?),
    };
    add_request(
        connection,
        source,
        args.raw("request"),
        args.str("now")?,
        prompt_shown,
    )
    .map(Value::String)
}

/// The queue write of one `GuardApprovalRequest.to_dict()`: its persisted
/// request id.
pub(crate) fn add_request(
    connection: &Connection,
    source: &str,
    request: Option<&Value>,
    now: &str,
    prompt_shown: Option<bool>,
) -> StoreResult<String> {
    let request = ApprovalRequest::decode(request)?;
    let derived = derive(&request).map_err(|error| match error {
        StoreError::Invalid(IDENTITY_INVALID) => StoreError::Value(IDENTITY_UNAVAILABLE.to_owned()),
        other => other,
    })?;
    let backfill = guard_store_approval_backfill::pending(connection);
    if backfill {
        guard_store_approval_backfill::backfill(connection)?;
    }
    let request_id = persist(connection, source, &request, &derived, now)?;
    if let Some(prompt_shown) = prompt_shown.filter(|_| request_id == request.request_id) {
        record_created_events(connection, &request, prompt_shown, now)?;
    }
    if backfill {
        guard_store_approval_backfill::mark_complete(connection);
    }
    Ok(request_id)
}

/// The write and outbox bind under the caller's OAuth source.
/// `_normalize_source_name` for a source the caller already validated: the
/// `oauth_source` a request from it carries.
pub(crate) fn oauth_source(source: &str) -> String {
    match py_strip(source).to_lowercase() {
        normalized if normalized.is_empty() => "default".to_owned(),
        normalized => normalized,
    }
}

fn persist(
    connection: &Connection,
    source: &str,
    request: &ApprovalRequest,
    derived: &Derived,
    now: &str,
) -> StoreResult<String> {
    let oauth_source = oauth_source(source);
    let request_id = write(connection, request, derived, &oauth_source, now)?;
    bind_events_for_request(connection, &request_id, &oauth_source)?;
    Ok(request_id)
}

fn derive(request: &ApprovalRequest) -> StoreResult<Derived> {
    let canonical = surfaces(
        &request.policy_action,
        &request.decision(),
        &request.envelope(),
        true,
    )
    .map_err(StoreError::Value)?;
    let item = ApprovalQueueIdentityItemV1 {
        launch_target: request.launch_target.clone(),
        harness: request.harness.clone(),
        workspace: request.workspace.clone(),
        artifact_id: request.artifact_id.clone(),
        envelope: request.action_envelope_json.clone().map(Value::Object),
        browser_intent: request.browser_intent.clone().map(Value::Object),
        action_identity: request.action_identity.clone(),
        queue_group_id: request.queue_group_id.clone(),
    };
    let identity = identify(&item).ok_or(StoreError::Invalid(IDENTITY_INVALID))?;
    let field = |name: &str| identity[name].as_str().unwrap_or_default().to_owned();
    Ok(Derived {
        policy_action: canonical["policy_action"].clone(),
        decision: canonical["decision_v2_json"].clone(),
        envelope: canonical["action_envelope_json"].clone(),
        identity_key: field("identity_key"),
        action_identity: field("action_identity"),
        queue_group_id: field("queue_group_id"),
    })
}

/// `_legacy_queue_rows`: rows the write-time backfill has yet to
/// identify, or rejected and left as they are.
fn legacy_rows_pending(connection: &Connection) -> StoreResult<bool> {
    Ok(query_one(
        connection,
        "select 1 as present from approval_requests where action_identity is null \
         or queue_group_id is null or last_seen_at is null or dedupe_count is null \
         or dedupe_count < 1 limit 1",
        &[],
    )?
    .is_some())
}

/// `_add_approval_request_in_transaction`.
fn write(
    connection: &Connection,
    request: &ApprovalRequest,
    derived: &Derived,
    oauth_source: &str,
    now: &str,
) -> StoreResult<String> {
    expire_inconsistent_group(connection, request, derived, oauth_source, now)?;
    let mut existing = existing_request_id(connection, request, derived, oauth_source)?;
    if let Some(found) = existing.clone() {
        if consistent(connection, std::slice::from_ref(&found))?.is_empty() {
            if found == request.request_id {
                return Err(StoreError::Value(FRESH_REVIEW_REQUIRED.to_owned()));
            }
            // Only a new, canonically validated host attempt replaces this
            // row; its authority is never repaired under the old id.
            expire(connection, &found, &request.request_id, now)?;
            existing = None;
        }
    }
    match existing {
        Some(found) => {
            update(connection, request, derived, &found, oauth_source, now)?;
            Ok(found)
        }
        None => {
            insert(connection, request, derived, oauth_source, now)?;
            Ok(request.request_id.clone())
        }
    }
}

fn expire(
    connection: &Connection,
    request_id: &str,
    replacement: &str,
    now: &str,
) -> StoreResult<()> {
    exec(
        connection,
        "update approval_requests set status = 'expired', resolved_at = ?, \
         resolution_action = null, resolution_scope = null, reason = ? \
         where request_id = ? and status = 'pending'",
        &[
            Value::from(now),
            Value::from(format!("{SUPERSEDED}{replacement}")),
            Value::from(request_id),
        ],
    )?;
    Ok(())
}

/// `_expire_inconsistent_group_requests`: retire invalid older cards even
/// when a newer valid card wins deduplication.
fn expire_inconsistent_group(
    connection: &Connection,
    request: &ApprovalRequest,
    derived: &Derived,
    oauth_source: &str,
    now: &str,
) -> StoreResult<()> {
    let group: Vec<String> = query_all(
        connection,
        "select request_id from approval_requests \
         where queue_group_id = ? and harness = ? and oauth_source = ? and status = 'pending' \
         order by last_seen_at desc, request_id desc",
        &[
            Value::from(derived.queue_group_id.as_str()),
            Value::from(request.harness.as_str()),
            Value::from(oauth_source),
        ],
    )?
    .iter()
    .map(|row| request_id_text(row.get("request_id")))
    .collect();
    let valid = consistent(connection, &group)?;
    let (kept, invalid): (Vec<&String>, Vec<&String>) =
        group.iter().partition(|id| valid.contains(*id));
    if invalid.iter().any(|id| **id == request.request_id) {
        return Err(StoreError::Value(FRESH_REVIEW_REQUIRED.to_owned()));
    }
    let replacement = kept
        .first()
        .map_or(request.request_id.as_str(), |id| id.as_str());
    for id in invalid {
        expire(connection, id, replacement, now)?;
    }
    Ok(())
}

/// `str(row["request_id"])` for the text ids the queue stores.
fn request_id_text(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(text)) => text.clone(),
        Some(other) => other.to_string(),
        None => String::new(),
    }
}

/// `_consistent_pending_requests`: the ids whose stored decision projects
/// without a contract error. A projection failure leaves none consistent.
fn consistent(connection: &Connection, request_ids: &[String]) -> StoreResult<HashSet<String>> {
    let mut rows = Vec::new();
    for chunk in request_ids.chunks(REQUEST_ID_CHUNK) {
        let sql = format!(
            "select request_id, policy_action, decision_v2_json, action_envelope_json \
             from approval_requests where request_id in ({})",
            placeholders(chunk.len())
        );
        let params: Vec<Value> = chunk.iter().map(|id| Value::from(id.as_str())).collect();
        rows.extend(query_all(connection, &sql, &params)?);
    }
    let mut out = HashSet::new();
    let mut projected = Vec::new();
    for row in &rows {
        let size = ["policy_action", "decision_v2_json", "action_envelope_json"]
            .iter()
            .map(|name| text(row, name).len())
            .sum::<usize>();
        if size > PROJECTION_ROW_BYTES {
            return Err(StoreError::Invalid(
                "native_guard_store_approval_row_too_large",
            ));
        }
        let (Some(decision), Some(envelope)) = (
            stored_json(row.get("decision_v2_json")),
            stored_json(row.get("action_envelope_json")),
        ) else {
            continue;
        };
        let action = row.get("policy_action").cloned().unwrap_or(Value::Null);
        match surfaces(&action, &decision, &envelope, false) {
            Ok(projection) => projected.push((request_id_text(row.get("request_id")), projection)),
            Err(_) => return Ok(HashSet::new()),
        }
    }
    for (request_id, projection) in projected {
        if projection["contract_error"].is_null() {
            out.insert(request_id);
        }
    }
    Ok(out)
}

/// `json.loads(text) if text is not None else None`; `None` is a row the
/// daemon skips.
fn stored_json(value: Option<&Value>) -> Option<Value> {
    match value {
        None | Some(Value::Null) => Some(Value::Null),
        Some(Value::String(text)) => serde_json::from_str(text).ok(),
        Some(_) => None,
    }
}

/// `_existing_request_id`: the pending row of the same queue group, else a
/// legacy row of the same identity key or launch target.
fn existing_request_id(
    connection: &Connection,
    request: &ApprovalRequest,
    derived: &Derived,
    oauth_source: &str,
) -> StoreResult<Option<String>> {
    let harness = Value::from(request.harness.as_str());
    let source = Value::from(oauth_source);
    let artifact = Value::from(request.artifact_id.as_str());
    let workspace = request
        .workspace
        .as_deref()
        .map_or(Value::Null, Value::from);
    let launch_target = request
        .launch_target
        .as_deref()
        .map_or(Value::Null, Value::from);
    let queries: [(&str, Vec<Value>); 3] = [
        (
            "select request_id from approval_requests \
             where queue_group_id = ? and harness = ? and oauth_source = ? and status = 'pending' \
             order by last_seen_at desc, request_id desc limit 1",
            vec![
                Value::from(derived.queue_group_id.as_str()),
                harness.clone(),
                source.clone(),
            ],
        ),
        (
            "select request_id from approval_requests \
             where harness = ? and oauth_source = ? and artifact_id = ? and workspace IS ? \
             and normalized_identity_key = ? and queue_group_id IS NULL and status = 'pending' \
             order by created_at desc limit 1",
            vec![
                harness.clone(),
                source.clone(),
                artifact.clone(),
                workspace.clone(),
                Value::from(derived.identity_key.as_str()),
            ],
        ),
        (
            "select request_id from approval_requests \
             where harness = ? and oauth_source = ? and artifact_id = ? and workspace IS ? \
             and launch_target IS ? and normalized_identity_key IS NULL and queue_group_id IS NULL \
             and status = 'pending' order by created_at desc limit 1",
            vec![harness, source, artifact, workspace, launch_target],
        ),
    ];
    for (sql, params) in queries {
        if let Some(row) = query_one(connection, sql, &params)? {
            return Ok(Some(request_id_text(row.get("request_id"))));
        }
    }
    Ok(None)
}

#[cfg(test)]
#[path = "guard_store_approval_write_tests.rs"]
mod tests;
