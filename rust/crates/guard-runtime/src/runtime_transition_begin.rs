//! `RuntimeTransition.begin`: the checks before a transition journal is
//! first written, and the journal it starts with.
//!
//! `begin_check` refuses a refused operation, another home, a plan that
//! touches the journal or its authority, a pending transition and a deadline
//! outside the next minute, and answers the monotonic deadline. The caller
//! then checks its approval grant and compares the planned files and
//! installs, and `begin_commit` repeats the checks and writes the journal.

use std::path::Path;

use serde_json::{json, Map, Value};

use super::shape::{record_files, record_number, Refusal};
use super::{canonical_uuid, exists, journal, managed, no, write_record, Request, RECORD_SCHEMA};

const MAX_WINDOW_SECONDS: f64 = 60.0;

fn plan(request: &Request) -> Result<&Map<String, Value>, Refusal> {
    request.payload.as_ref().ok_or_else(|| no("invalid"))
}

fn finite(value: Option<f64>) -> Result<f64, Refusal> {
    value
        .filter(|value| value.is_finite())
        .ok_or_else(|| no("invalid"))
}

/// A canonical operation refused before it began cannot begin later.
fn refused_before(request: &Request, payload: &Map<String, Value>) -> Result<(), Refusal> {
    let operation = payload
        .get("operation_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !canonical_uuid(operation) {
        return Ok(());
    }
    let receipt = managed(request)?
        .join("runtime-refusals")
        .join(format!("{operation}.json"));
    if exists(&receipt) {
        return Err(no("operation_previously_refused"));
    }
    Ok(())
}

/// The journal, its retired copy and the install lock never enter a plan;
/// the hook manifest key enters only as a digest dependency.
fn authority_untouched(request: &Request, payload: &Map<String, Value>) -> Result<(), Refusal> {
    let current = journal(request)?;
    let codex = managed(request)?.join("codex");
    let reserved = [
        current.clone(),
        current.with_file_name("runtime-transition.previous.json"),
        codex.join("installation.lock"),
    ];
    let key = codex.join("hook-manifest.key");
    for change in record_files(payload)? {
        let target = Path::new(
            change
                .get("path")
                .and_then(Value::as_str)
                .unwrap_or_default(),
        );
        let replaces_key = target == key
            && (!change.contains_key("expected_digest")
                || change.contains_key("artifact_identity"));
        if reserved.iter().any(|path| path == target) || replaces_key {
            return Err(no("authority_target_forbidden"));
        }
    }
    Ok(())
}

/// The checks both halves make; the answer is the monotonic deadline.
fn checks(request: &Request) -> Result<f64, Refusal> {
    let payload = plan(request)?;
    refused_before(request, payload)?;
    if payload.get("guard_home").and_then(Value::as_str) != Some(request.guard_home.as_str()) {
        return Err(no("plan_context_mismatch"));
    }
    authority_untouched(request, payload)?;
    if exists(&journal(request)?) {
        return Err(no("pending_transition"));
    }
    let now = finite(request.now)?;
    let epoch = finite(request.now_epoch)?;
    let deadline_epoch = record_number(payload, "deadline_epoch")?;
    if !(epoch < deadline_epoch && deadline_epoch <= epoch + MAX_WINDOW_SECONDS) {
        return Err(no("deadline_invalid"));
    }
    let mut deadline = now + (deadline_epoch - epoch).max(0.0);
    if let Some(caller) = request.deadline_monotonic {
        if !caller.is_finite() || caller <= now {
            return Err(no("deadline_exceeded"));
        }
        deadline = deadline.min(caller);
    }
    Ok(deadline)
}

pub(super) fn check(request: &Request) -> Result<Value, Refusal> {
    Ok(json!({"deadline": checks(request)?}))
}

/// Write the first journal: authorized for this exact transition, owned by
/// the caller, until the earlier of the plan deadline and the grant expiry.
pub(super) fn commit(request: &Request) -> Result<Value, Refusal> {
    let deadline = checks(request)?;
    if request.owner.as_ref().is_none_or(Value::is_null) {
        return Err(no("owner_identity_unavailable"));
    }
    let now = finite(request.now)?;
    let epoch = finite(request.now_epoch)?;
    let mut payload = plan(request)?.clone();
    let deadline_epoch = record_number(&payload, "deadline_epoch")?;
    let forward_epoch = match request.grant_expires_epoch {
        Some(expires) if expires.is_finite() => deadline_epoch.min(expires),
        Some(_) => return Err(no("invalid")),
        None => deadline_epoch,
    };
    let forward = deadline.min(now + (forward_epoch - epoch).max(0.0));
    let fields = [
        ("schema", json!(RECORD_SCHEMA)),
        ("phase", json!("AuthorizedForExactTransition")),
        ("owner", request.owner.clone().unwrap_or(Value::Null)),
        (
            "installer_operation_id",
            json!(request.installer_operation_id),
        ),
        ("authorized_subject", json!(request.subject)),
        (
            "approval_required",
            json!(request.approval_required == Some(true)),
        ),
        ("forward_expires_epoch", json!(forward_epoch)),
        ("deadline_monotonic", json!(deadline)),
        ("forward_expires_monotonic", json!(forward)),
        ("first_cause", Value::Null),
        ("recovery_causes", json!([])),
    ];
    for (key, value) in fields {
        payload.insert(key.to_owned(), value);
    }
    write_record(request, &payload)?;
    Ok(json!({"ok": true}))
}
