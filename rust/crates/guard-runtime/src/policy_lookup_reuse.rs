//! Approval-reuse verdict composed onto a grouped saved-decision read.
//!
//! The generic hook peeks its saved decision, checks a saved allow's context
//! token against the current one, explains a miss through the approval-reuse
//! diagnostic, and composes the reuse verdict. All four steps run here on the
//! lookup's store connection, so the hook makes one resident call.

use guard_command::approval_reuse::evaluate_approval_reuse;
use guard_contracts::{
    ApprovalReuseDiagnosticEvidenceV1, ApprovalReuseDiagnosticRequestV1,
    PolicyDecisionLookupRequestV1, APPROVAL_REUSE_DIAGNOSTIC_REQUEST_SCHEMA,
};
use rusqlite::{Connection, OptionalExtension};
use serde_json::{json, Value};

use crate::approval_reuse_diagnostic_op::diagnose;
use crate::context_digest::validate_context_tokens;

/// The fail-closed reason when saved rows exist but no diagnosis is possible.
const DIAGNOSTIC_UNAVAILABLE_REASON: &str = "approval_reuse_integrity_failure";
const RUNTIME_EXACT_PREFIX: &str = "runtime-exact:";

/// Why a saved allow did not authorize, with the matched row's stored hash.
pub(crate) type MissDiagnosis = (Option<String>, Option<String>);

fn field<'a>(value: &'a Value, key: &str) -> &'a Value {
    value.get(key).unwrap_or(&Value::Null)
}

/// Compose `{decision, ignored_local_integrity}` with the reuse verdict.
///
/// `diagnose_miss` runs only when no saved decision or integrity evidence
/// was found.
pub(crate) fn compose_reuse<F>(
    saved: Value,
    current_action: &Value,
    current_token: &str,
    diagnose_miss: F,
) -> Value
where
    F: FnOnce() -> MissDiagnosis,
{
    let decision = field(&saved, "decision").clone();
    let ignored = field(&saved, "ignored_local_integrity").clone();
    let mut saved_action = field(&decision, "action").clone();
    let mut present = !decision.is_null() || !ignored.is_null();
    let mut reason: Option<String> = None;
    if !ignored.is_null() {
        if decision.is_null() {
            saved_action = json!("require-reapproval");
        }
        reason = Some(DIAGNOSTIC_UNAVAILABLE_REASON.to_owned());
    } else if saved_action == json!("allow") {
        let saved_hash = field(&decision, "artifact_hash");
        let runtime_exact = saved_hash
            .as_str()
            .is_some_and(|hash| hash.starts_with(RUNTIME_EXACT_PREFIX));
        if !runtime_exact {
            reason = validate_context_tokens(saved_hash, &json!(current_token));
        }
    }
    let mut saved_hash = field(&decision, "artifact_hash").clone();
    if !present {
        let (diagnosed, stored_hash) = diagnose_miss();
        saved_hash = stored_hash.map_or(Value::Null, Value::String);
        if diagnosed.is_some() {
            saved_action = json!("allow");
            present = true;
            reason = diagnosed;
        }
    }
    let flag = |key: &str| field(&decision, key) == &json!(true);
    let verdict = evaluate_approval_reuse(
        current_action,
        (!saved_action.is_null()).then_some(&saved_action),
        Some(present),
        reason.as_deref(),
        flag("fresh_local_approval"),
        flag("durable_exact_approval"),
    );
    json!({
        "decision": decision,
        "ignored_local_integrity": ignored,
        "reuse": serde_json::to_value(verdict).unwrap_or(Value::Null),
        "saved_present": present,
        "saved_artifact_hash": saved_hash,
    })
}

/// Explain a miss for the lookup's action on its own connection.
///
/// A store with no saved rows has nothing to diagnose. When rows exist and no
/// authoritative answer comes back, the miss fails closed as an integrity
/// failure without a stored hash.
pub(crate) fn diagnose_miss(
    request: &PolicyDecisionLookupRequestV1,
    connection: &Connection,
) -> MissDiagnosis {
    let Some(artifact_id) = request.artifact_id.clone() else {
        return (None, None);
    };
    match has_saved_rows(connection) {
        Ok(false) => return (None, None),
        Ok(true) => {}
        Err(()) => return (Some(DIAGNOSTIC_UNAVAILABLE_REASON.to_owned()), None),
    }
    let mut probe = ApprovalReuseDiagnosticRequestV1 {
        schema: APPROVAL_REUSE_DIAGNOSTIC_REQUEST_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        store_path: request.store_path.clone(),
        guard_home: request.guard_home.clone(),
        harness: request.harness.clone(),
        artifact_id,
        artifact_hash: request.artifact_hash.clone(),
        workspace: request.workspace.clone(),
        publisher: request.publisher.clone(),
        now: request.now.clone(),
        evidence: None,
    };
    let mut answer = diagnose(connection, &probe, request.now.clone());
    if let Ok(need) = &answer {
        if need.get("need").is_some() {
            probe.evidence = Some(diagnostic_evidence(request, need));
            answer = diagnose(connection, &probe, request.now.clone());
        }
    }
    match answer {
        Ok(payload) if payload.get("need").is_none() => {
            let text = |key: &str| payload.get(key).and_then(Value::as_str).map(str::to_owned);
            (text("reason"), text("stored_hash"))
        }
        _ => (Some(DIAGNOSTIC_UNAVAILABLE_REASON.to_owned()), None),
    }
}

/// The diagnostic evidence the lookup already carries: the policy key and
/// integrity state when policy rows need verification, and the local-once
/// key when local-once rows do.
fn diagnostic_evidence(
    request: &PolicyDecisionLookupRequestV1,
    need: &Value,
) -> ApprovalReuseDiagnosticEvidenceV1 {
    let policy = need.get("policy") == Some(&json!(true));
    let local_once = need.get("local_once") == Some(&json!(true));
    let mut evidence = ApprovalReuseDiagnosticEvidenceV1::default();
    if policy {
        evidence.integrity_state =
            Some(request.integrity_state.clone().unwrap_or_else(|| json!({})));
        evidence.integrity_key_b64 = request.integrity_key_b64.clone();
        evidence.integrity_key_id = request.integrity_key_id.clone();
    }
    if local_once {
        evidence.local_once_integrity_key_b64 = request.local_once_integrity_key_b64.clone();
        evidence.local_once_integrity_key_id = request.local_once_integrity_key_id.clone();
    }
    evidence
}

fn has_saved_rows(connection: &Connection) -> Result<bool, ()> {
    connection
        .query_row(
            "select 1 where exists (select 1 from policy_decisions) \
             or exists (select 1 from guard_local_once_approvals)",
            [],
            |_| Ok(()),
        )
        .optional()
        .map(|row| row.is_some())
        .map_err(|_| ())
}

#[cfg(test)]
#[path = "policy_lookup_reuse_tests.rs"]
mod tests;
