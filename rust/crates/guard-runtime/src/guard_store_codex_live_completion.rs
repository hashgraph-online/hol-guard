//! The original Codex hook's browser decision, completed in one store call.
//!
//! `complete_codex_live_decision` checks that the request still holds a
//! terminal reviewed decision, replays a terminal resume already recorded for
//! it, asks for a fresh allow's authority evidence when the caller has not
//! sent it, reads that allow's exact one-shot authority, and records the hook's
//! continuation: the offer it was waiting under, the resume, the operation,
//! the continuation events and the spent authority, all in one write.
//! `record_codex_live_completion` records the continuation alone, without
//! authority, as `record_live_hook_completion` did.
//!
//! Both take the write lock themselves, so the authority's lookup, which
//! opens its own connection, never waits on a transaction held around it.

use std::path::Path;

use rusqlite::Connection;
use serde_json::{json, Map, Value};

use crate::codex_live_operation::{self, Operation};
use crate::codex_request_resume_store::resume;
use crate::continuation_authority_op as authority;
use crate::guard_store_args::Args;
use crate::guard_store_db::{StoreError, StoreResult};
use crate::guard_store_json::{add_micros_aware_isoformat, add_seconds_utc_isoformat, py_strip};
use crate::guard_store_outbox_identity::{correlation_id, correlation_shaped};
use crate::policy_store::PolicySnapshotStore;

const SUSPENDED: &str = "suspended-response";

/// `complete_codex_live_decision`.
pub(crate) fn complete(
    connection: &Connection,
    guard_home: &str,
    args: &Args<'_>,
    owner: Option<&PolicySnapshotStore>,
) -> StoreResult<Value> {
    let request_id = args.str("request_id")?;
    let Some(request) = read_request(connection, guard_home, args, owner)? else {
        return Ok(failure("request_not_found"));
    };
    if request["harness"] != "codex" || request["status"] != "resolved" {
        return Ok(failure("request_not_resolved"));
    }
    let action = match request["resolution_action"].as_str() {
        Some(action @ ("allow" | "block")) => action,
        _ => return Ok(failure("decision_not_terminal")),
    };
    if !matches!(
        request["policy_action"].as_str(),
        Some("review" | "require-reapproval")
    ) {
        return Ok(failure("policy_no_longer_reviewable"));
    }
    let previous = resume(connection, request_id)?;
    let replayed = previous
        .filter(|previous| terminal_matches(previous, action))
        .map(|previous| json!({"action": action, "completed": true, "continuation": previous, "replayed": true}));
    let decision = if action == "allow" {
        if !args.flag("fresh_allow_authorized")? {
            return Ok(failure("fresh_policy_revalidation_failed"));
        }
        if let Some(replayed) = replayed {
            return Ok(replayed);
        }
        if !args.flag("authority_gathered")? {
            // Nothing is written yet: the caller reads the policy store and
            // the keyring only once no recorded resume answers, then asks
            // again with the authority's evidence.
            return Ok(failure("codex_live_evidence_required"));
        }
        let decision =
            crate::guard_store_codex_live_authority::resolve(connection, guard_home, args)?;
        if decision.is_null() {
            return Ok(failure("exact_approval_authority_missing"));
        }
        decision
    } else if let Some(replayed) = replayed {
        return Ok(replayed);
    } else {
        Value::Null
    };
    let completion = record_with(connection, guard_home, args, &request, action, &decision)?;
    let expected = if action == "allow" {
        "resumed"
    } else {
        "blocked_not_resumed"
    };
    if completion["continuationStatus"] != expected {
        return Ok(failure("continuation_not_recorded"));
    }
    Ok(json!({"action": action, "completed": true, "continuation": completion, "replayed": false}))
}

/// `record_live_hook_completion` without authority: the continuation payload,
/// or `Null` when the request has no live hook waiting on it.
pub(crate) fn record(
    connection: &Connection,
    guard_home: &str,
    args: &Args<'_>,
    owner: Option<&PolicySnapshotStore>,
) -> StoreResult<Value> {
    let Some(request) = read_request(connection, guard_home, args, owner)? else {
        return Ok(Value::Null);
    };
    record_with(
        connection,
        guard_home,
        args,
        &request,
        args.str("action")?,
        &Value::Null,
    )
}

fn record_with(
    connection: &Connection,
    guard_home: &str,
    args: &Args<'_>,
    request: &Value,
    action: &str,
    decision: &Value,
) -> StoreResult<Value> {
    let request_id = args.str("request_id")?;
    let action = match action {
        "allow" | "allow_once" => "allow_once",
        "block" => "block",
        _ => return Err(StoreError::Value("continuation_action_invalid".to_owned())),
    };
    let now = args.str("now")?;
    let invalid = || StoreError::Value("continuation_time_invalid".to_owned());
    // The result keeps the caller's offset, as `datetime.fromisoformat(now)`
    // did; the offer reads the same instant in UTC.
    let completed_at = add_micros_aware_isoformat(now, 0).ok_or_else(invalid)?;
    let observed = add_seconds_utc_isoformat(now, 0).ok_or_else(invalid)?;
    let harness = request["harness"].as_str().map(py_strip).unwrap_or("");
    if harness.to_lowercase() != "codex" {
        return Ok(Value::Null);
    }
    let cwd = args.opt_str("cwd")?;
    let Some(operation) = codex_live_operation::read(connection, request_id, cwd)? else {
        return Ok(Value::Null);
    };
    let Some(deadline) = codex_live_operation::wait_deadline(guard_home, &operation) else {
        return Ok(Value::Null);
    };
    let offer = authority::offer(&json!({
        "harness": "codex", "wait_deadline": deadline, "original_hook_attached": true,
        "now": observed, "correlation_id": correlation(request, &operation.metadata, request_id)?,
        "headless": false, "session_target_verified": false, "opaque_target_id": null,
    }))
    .map_err(StoreError::Invalid)?["offer"]
        .take();
    if offer["capability"] != SUSPENDED {
        return Ok(Value::Null);
    }
    let prior = resume(connection, request_id)?.unwrap_or(Value::Null);
    if let Some(previous) = replayed(&offer, &prior, action)? {
        if previous["status"] != "waiting" {
            return payload(&offer, &previous, true);
        }
    }
    let (status, reason) = if action == "allow_once" {
        ("resumed", "live_hook_completed")
    } else {
        ("blocked_not_resumed", "blocked_not_resumed")
    };
    let result = json!({
        "correlation_id": offer["correlation_id"], "capability": offer["capability"],
        "status": status, "reason": reason, "completed_at": completed_at, "evidence_id": evidence_id()?,
    });
    let finalizing = Finalizing {
        request_id,
        action,
        now,
        cwd,
        offer: &offer,
        result: &result,
        decision,
    };
    if !persist(connection, guard_home, &finalizing, operation)? {
        return Ok(Value::Null);
    }
    let prior = resume(connection, request_id)?.unwrap_or(Value::Null);
    match replayed(&offer, &prior, action)? {
        Some(authoritative) => payload(&offer, &authoritative, true),
        None => payload(&offer, &result, false),
    }
}

struct Finalizing<'a> {
    request_id: &'a str,
    action: &'a str,
    now: &'a str,
    cwd: Option<&'a str>,
    offer: &'a Value,
    result: &'a Value,
    decision: &'a Value,
}

/// `store_finalize_projected` on this connection: spend the authority and
/// record the continuation in one write, or record nothing.
fn persist(
    connection: &Connection,
    guard_home: &str,
    finalizing: &Finalizing<'_>,
    read: Operation,
) -> StoreResult<bool> {
    let material = if finalizing.decision.is_null() {
        None
    } else {
        let home = Path::new(guard_home);
        let resolved = std::fs::canonicalize(home).unwrap_or_else(|_| home.to_path_buf());
        let mut secrets = crate::encrypted_secret_store::EncryptedFileSecretStore::new(&resolved);
        let Some(material) =
            crate::policy_integrity_resolver::resolve_integrity_state(&mut secrets, &resolved).0
        else {
            return Ok(false);
        };
        Some(material)
    };
    connection.execute_batch("BEGIN IMMEDIATE")?;
    let outcome = finalize(connection, finalizing, read, material.as_ref());
    if matches!(outcome, Ok(true)) {
        connection.execute_batch("COMMIT")?;
    } else {
        let _ = connection.execute_batch("ROLLBACK");
    }
    outcome
}

fn finalize(
    connection: &Connection,
    finalizing: &Finalizing<'_>,
    read: Operation,
    material: Option<&crate::policy_integrity_resolver::PolicyIntegrityMaterial>,
) -> StoreResult<bool> {
    let request_id = finalizing.request_id;
    // The operation as it stands under the write lock.
    let row = codex_live_operation::raw(connection, request_id)?;
    let operation = if row == read.row {
        Some(read)
    } else {
        codex_live_operation::decode(row, finalizing.cwd)?
    };
    let (operation, nonfinite) = operation.map_or((Value::Null, Vec::new()), |operation| {
        (operation.carried, operation.nonfinite)
    });
    let prior = resume(connection, request_id)?.unwrap_or(Value::Null);
    let mut request = authority::finalize(&json!({
        "offer": finalizing.offer, "result": finalizing.result, "prior": prior,
        "operation": operation, "request_id": request_id, "action": finalizing.action,
        "now": finalizing.now, "claim_id": null, "approval_decision": finalizing.decision,
    }))
    .map_err(StoreError::Invalid)?["finalization"]
        .take();
    request["metadata_nonfinite"] = Value::Array(nonfinite);
    if let Some(material) = material {
        if !crate::continuation_grants::consume(
            connection,
            request_id,
            finalizing.decision,
            finalizing.now,
            material.raw_key.as_slice(),
            &material.key_id,
        )? {
            return Ok(false);
        }
    }
    Ok(crate::continuation_store::finalize(connection, &request)?["finalized"] == true)
}

/// `get_approval_request(request_id)` with its derived scope.
fn read_request(
    connection: &Connection,
    guard_home: &str,
    args: &Args<'_>,
    owner: Option<&PolicySnapshotStore>,
) -> StoreResult<Option<Value>> {
    let mut read = Map::from_iter([
        ("request_id".to_owned(), json!(args.str("request_id")?)),
        ("derive_scope".to_owned(), Value::Bool(true)),
    ]);
    if let Some(cwd) = args.raw("cwd") {
        read.insert("cwd".to_owned(), cwd.clone());
    }
    let row = crate::guard_store_approval_reads::get_approval_request(
        connection,
        guard_home,
        &Args(&read),
        owner,
    )?;
    Ok(Some(row).filter(Value::is_object))
}

/// `canonical_continuation_correlation_id`: the first canonical correlation
/// the request, its snapshot or its operation carries, else the request's own.
fn correlation(request: &Value, metadata: &Value, request_id: &str) -> StoreResult<String> {
    let sources = [
        &request["continuation_snapshot"],
        &request["continuation_snapshot_json"],
        metadata,
        &request["decision_v2_json"],
        &request["action_envelope_json"],
        request,
    ];
    let carried = sources
        .into_iter()
        .filter(|source| source.is_object())
        .flat_map(|source| ["correlationId", "correlation_id"].map(|key| &source[key]))
        .filter_map(Value::as_str)
        .map(py_strip)
        .find(|text| correlation_shaped(text));
    match carried {
        Some(carried) => Ok(carried.to_owned()),
        None => correlation_id(request_id)
            .ok_or_else(|| StoreError::Value("local_request_id is required".to_owned())),
    }
}

/// `previous_result`: the result `prior` already recorded for this offer.
fn replayed(offer: &Value, prior: &Value, action: &str) -> StoreResult<Option<Value>> {
    let replay = authority::replay(&json!({"prior": prior, "offer": offer, "action": action}))
        .map_err(StoreError::Invalid)?;
    Ok(Some(replay["result"].clone()).filter(|result| !result.is_null()))
}

/// `continuation_payload`.
fn payload(offer: &Value, result: &Value, replayed: bool) -> StoreResult<Value> {
    let mut projection = authority::project(&json!({
        "offer": offer, "result": result, "operation": null,
        "request_id": "", "action": "allow_once", "now": "",
    }))
    .map_err(StoreError::Invalid)?;
    Ok(projection[if replayed {
        "replayed_payload"
    } else {
        "payload"
    }]
    .take())
}

/// `_terminal_resume_matches`.
fn terminal_matches(resume: &Value, action: &str) -> bool {
    resume["resolution_action"] == action
        && match (action, resume["status"].as_str()) {
            ("allow", Some(status)) => matches!(status, "resumed" | "sent"),
            (_, Some(status)) => matches!(status, "blocked" | "skipped"),
            (_, None) => false,
        }
}

/// `f"evidence-{uuid4().hex}"`.
fn evidence_id() -> StoreResult<String> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| StoreError::Invalid("continuation_random_failed"))?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(format!("evidence-{}", hex::encode(bytes)))
}

fn failure(code: &str) -> Value {
    json!({"completed": false, "error": code})
}

#[cfg(test)]
#[path = "guard_store_codex_live_completion_tests.rs"]
mod tests;
