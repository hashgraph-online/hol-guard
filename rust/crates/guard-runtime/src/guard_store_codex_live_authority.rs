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

use std::path::Path;

use guard_contracts::PolicyDecisionLookupRequestV1;
use rusqlite::Connection;
use serde_json::Value;

use crate::guard_store_args::Args;
use crate::guard_store_db::{StoreError, StoreResult};
use crate::local_store_read::STORE_FILE_NAME;
use crate::project_identity::{portable_workspace, resolve_relative, PortableIdentity};

pub(crate) fn resolve(
    connection: &Connection,
    guard_home: &str,
    args: &Args<'_>,
) -> StoreResult<Value> {
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
    match identity(request.workspace.as_deref(), args.opt_str("cwd")?) {
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

/// `_portable_project_workspace(workspace)`, with a relative workspace read
/// under the caller's working directory as `resolve_portable_project_identity`
/// sends it.
fn identity(workspace: Option<&str>, cwd: Option<&str>) -> PortableIdentity {
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
