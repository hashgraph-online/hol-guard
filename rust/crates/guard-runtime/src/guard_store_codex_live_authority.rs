//! `codex_live_allow_authority`: the exact unconsumed one-shot allow a
//! resolved Codex request may still release its waiting hook with, read in one
//! store call.
//!
//! 1. The exact Cloud Review allow issued for the request, read without
//!    claiming it, in one snapshot.
//! 2. Otherwise the non-consuming policy lookup the caller built for the
//!    request, composed with the workspace's portable project memory exactly
//!    as `resolve_policy_decision_lookup` composes it. A workspace whose
//!    portable identity is not settled grants no allow there (only the
//!    restrictive half of its lookup counts), so it answers no authority.
//!
//! Either answer counts only when it is the valid `approval-gate-once` allow
//! of this request. Anything else, including a lookup that fails, is `Null`.
//! The lookup may record integrity audit events, so a caller must never
//! repeat a call whose reply it lost.
//!
//! A caller that asks for `native_evidence` sends neither key nor lookup: the
//! resident reads both from the integrity state and key the daemon published,
//! as the MCP relay does. When it cannot (no current binding, a state that is
//! not the protected one the store holds, or rows it cannot verify), it
//! refuses with `native_guard_store_codex_live_evidence_required` before
//! reading anything, and the caller gathers the evidence and asks again. Its
//! answer comes as `{"native_evidence": decision}`, so the caller can tell
//! it from a resident that predates the flag and answered without a lookup.

use std::path::Path;

use guard_contracts::PolicyDecisionLookupRequestV1;
use rusqlite::Connection;
use serde_json::{json, Value};

use crate::guard_store_args::Args;
use crate::guard_store_db::{StoreError, StoreResult};
use crate::local_store_read::STORE_FILE_NAME;
use crate::mcp_relay_decide::store::{self as saved_store, Probe};
use crate::policy_store::PolicySnapshotStore;
use crate::project_identity::{portable_workspace, resolve_relative, PortableIdentity};

/// The resident cannot read this call's evidence itself.
pub(crate) const EVIDENCE_REQUIRED: &str = "codex_live_evidence_required";

/// `EVIDENCE_REQUIRED` as the store transport reports it to the caller.
pub(crate) const NATIVE_EVIDENCE_REQUIRED: &str = "native_guard_store_codex_live_evidence_required";

/// `codex_live_allow_authority`.
pub(crate) fn op(
    connection: &Connection,
    guard_home: &str,
    args: &Args<'_>,
    owner: Option<&PolicySnapshotStore>,
) -> StoreResult<Value> {
    if !args.flag("native_evidence")? {
        return resolve(connection, guard_home, args, owner);
    }
    match resolve_native(connection, guard_home, args, owner) {
        Ok(decision) => Ok(json!({ "native_evidence": decision })),
        Err(StoreError::Invalid(reason)) if reason == EVIDENCE_REQUIRED => {
            Err(StoreError::Invalid(NATIVE_EVIDENCE_REQUIRED))
        }
        Err(error) => Err(error),
    }
}

pub(crate) fn resolve(
    connection: &Connection,
    guard_home: &str,
    args: &Args<'_>,
    owner: Option<&PolicySnapshotStore>,
) -> StoreResult<Value> {
    if args.flag("native_evidence")? {
        return resolve_native(connection, guard_home, args, owner);
    }
    let request_id = args.str("request_id")?;
    // One consistent view of the request and the allow issued for it.
    connection.execute_batch("BEGIN")?;
    let exact = crate::guard_store_exact_cloud_peek::peek(connection, args);
    connection.execute_batch("ROLLBACK")?;
    let exact = exact?;
    if answers(&exact, request_id) {
        return Ok(exact);
    }
    let Some(lookup) = args.opt_object("lookup")? else {
        return Ok(Value::Null);
    };
    let mut request: PolicyDecisionLookupRequestV1 =
        serde_json::from_value(Value::Object(lookup.clone()))
            .map_err(|_| StoreError::Invalid("codex_live_authority_lookup_invalid"))?;
    if request.consume_one_shot
        || request.local_once_only
        || request.probe_groups.is_some()
        || request.portable_workspace.is_some()
        || request.evidence_binding.is_some()
        || request.integrity_key_b64.is_some()
        || request.local_once_integrity_key_b64.is_some()
    {
        return Err(StoreError::Invalid("codex_live_authority_lookup_invalid"));
    }
    // The key bytes travel only at the top level, which the request digest
    // never covers. A key the lookup names but the call does not carry stays
    // unset, so its rows verify as an unknown key.
    let key = args.opt_str("integrity_key_b64")?;
    let key_id = args.opt_str("integrity_key_id")?;
    request.integrity_key_b64 = carried(key, key_id, request.integrity_key_id.as_deref());
    request.local_once_integrity_key_b64 =
        carried(key, key_id, request.local_once_integrity_key_id.as_deref());
    // The lookup reads the store this call was opened on, never one it names.
    request.store_path = Path::new(guard_home)
        .join(STORE_FILE_NAME)
        .to_string_lossy()
        .into_owned();
    request.guard_home = guard_home.to_owned();
    evaluate(request, request_id, args.opt_str("cwd")?)
}

/// The lookup composed with the workspace's portable project memory, when it
/// answers this request.
fn evaluate(
    mut request: PolicyDecisionLookupRequestV1,
    request_id: &str,
    cwd: Option<&str>,
) -> StoreResult<Value> {
    match identity(request.workspace.as_deref(), cwd) {
        PortableIdentity::Absent => {}
        PortableIdentity::Identity(identity) => request.portable_workspace = Some(identity),
        PortableIdentity::Unknown => return Ok(Value::Null),
    }
    let Ok(lookup) = crate::policy_decision_lookup_op::evaluate(&request) else {
        return Ok(Value::Null);
    };
    let decision = lookup.get("decision").cloned().unwrap_or(Value::Null);
    Ok(if answers(&decision, request_id) {
        decision
    } else {
        Value::Null
    })
}

/// `resolve` on the evidence the daemon published: the key it signs with
/// reads the exact Cloud allow, and the saved rows are read as the MCP relay
/// reads them (`mcp_relay_decide_store.rs`).
fn resolve_native(
    connection: &Connection,
    guard_home: &str,
    args: &Args<'_>,
    owner: Option<&PolicySnapshotStore>,
) -> StoreResult<Value> {
    let required = || StoreError::Invalid(EVIDENCE_REQUIRED);
    if args.raw("lookup").is_some() || args.raw("integrity_key_b64").is_some() {
        return Err(StoreError::Invalid("codex_live_authority_lookup_invalid"));
    }
    let request_id = args.str("request_id")?;
    let now = guard_contracts::canonical_utc_timestamp(args.str("now")?)
        .ok_or(StoreError::Invalid("exact_cloud_peek_time_invalid"))?;
    let binding = owner
        .ok_or_else(required)?
        .admit_direct_binding()
        .map_err(|_| required())?;
    let (_, key) = saved_store::published_integrity(&binding).map_err(|_| required())?;
    connection.execute_batch("BEGIN")?;
    let read = native_read(connection, guard_home, request_id, &now, &binding, key);
    connection.execute_batch("ROLLBACK")?;
    let lookup = match read? {
        Native::Answered(decision) => return Ok(decision),
        Native::Lookup(lookup) => lookup,
        Native::NoLookup => return Ok(Value::Null),
    };
    evaluate(*lookup, request_id, args.opt_str("cwd")?)
}

enum Native {
    /// The exact Cloud allow issued for the request.
    Answered(Value),
    /// The lookup the saved rows need.
    Lookup(Box<PolicyDecisionLookupRequestV1>),
    /// No saved row can answer.
    NoLookup,
}

/// The exact Cloud allow and the saved-row lookup, on one snapshot.
fn native_read(
    connection: &Connection,
    guard_home: &str,
    request_id: &str,
    now: &str,
    binding: &crate::policy_store::policy_store_direct_lane::DirectLaneBinding,
    key: &crate::policy_store::policy_store_direct_lane::DirectLaneIntegrityKey,
) -> StoreResult<Native> {
    let exact = crate::guard_store_exact_cloud_peek::verified_decision(
        connection,
        request_id,
        now,
        &key.key,
        &key.key_id,
    )?;
    if answers(&exact, request_id) {
        return Ok(Native::Answered(exact));
    }
    let request = crate::guard_store_db::query_one(
        connection,
        "select harness, artifact_id, artifact_hash, workspace, publisher \
         from approval_requests where request_id = ?",
        &[Value::from(request_id)],
    )?
    .unwrap_or_default();
    let text = |field: &str| {
        request
            .get(field)
            .and_then(Value::as_str)
            .filter(|text| !text.is_empty())
    };
    let (Some(harness), Some(artifact_id)) = (text("harness"), text("artifact_id")) else {
        // `policy_decision_lookup_request` would send no artifact: the caller
        // builds that lookup.
        return Err(StoreError::Invalid(EVIDENCE_REQUIRED));
    };
    let Some(saved) =
        saved_store::saved_at(connection, binding, guard_home, harness, now.to_owned())
            .map_err(|_| StoreError::Invalid(EVIDENCE_REQUIRED))?
    else {
        return Ok(Native::NoLookup);
    };
    Ok(Native::Lookup(Box::new(saved.lookup_request(&Probe {
        harness,
        artifact_id,
        artifact_hash: text("artifact_hash"),
        workspace: text("workspace"),
        publisher: text("publisher"),
        exact_match_context: None,
        exception_workspace: None,
    }))))
}

/// `_portable_project_workspace(workspace)`, with a relative workspace read
/// under the caller's working directory as `resolve_portable_project_identity`
/// sends it.
pub(crate) fn identity(workspace: Option<&str>, cwd: Option<&str>) -> PortableIdentity {
    let Some(workspace) = workspace.filter(|workspace| !workspace.trim().is_empty()) else {
        return PortableIdentity::Absent;
    };
    match cwd.filter(|cwd| !cwd.is_empty()) {
        Some(cwd) => resolve_relative(workspace, cwd),
        None => portable_workspace(workspace),
    }
}

/// The call's key, for a lookup that names that same key.
fn carried(key: Option<&str>, key_id: Option<&str>, named: Option<&str>) -> Option<String> {
    key.filter(|_| named.is_some() && named == key_id)
        .map(str::to_owned)
}

/// The valid `approval-gate-once` allow issued for `request_id`.
fn answers(decision: &Value, request_id: &str) -> bool {
    let text = |field: &str| decision.get(field).and_then(Value::as_str);
    text("action") == Some("allow")
        && text("source") == Some("approval-gate-once")
        && text("request_id") == Some(request_id)
        && text("integrity_status") == Some("valid")
        && text("approval_id").is_some()
}

#[cfg(test)]
#[path = "guard_store_codex_live_authority_tests.rs"]
mod tests;
