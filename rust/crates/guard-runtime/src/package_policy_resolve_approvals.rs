//! Which saved package approvals may satisfy a `require-reapproval` request.

use serde_json::{Map, Value};

use super::{field_or_null, has_token, is_int, non_empty_text, text_is, LOCAL_HARNESS};

/// A saved row speaks for this request's artifact when its context token is
/// valid and, if it names an artifact, that artifact is the requested one. The
/// reuse validation refuses a token whose content differs, so a changed
/// artifact still earns a fresh approval whatever scope saved the row.
fn binds_request_artifact(decision: &Map<String, Value>, artifact_id: &str) -> bool {
    has_token(decision)
        && non_empty_text(decision, "artifact_id").is_none_or(|saved| saved == artifact_id)
}

pub(super) fn is_fresh_artifact_approval(
    decision: &Map<String, Value>,
    request: Option<&Value>,
) -> bool {
    if !(is_int(decision.get("decision_id"))
        && text_is(decision, "source", "approval-gate")
        && text_is(decision, "scope", "artifact")
        && decision.get("expires_at").is_some_and(Value::is_string))
    {
        return false;
    }
    if non_empty_text(decision, "request_id").is_some() {
        return request
            .and_then(Value::as_object)
            .is_some_and(|row| text_is(row, "resolution_scope", "artifact"));
    }
    decision.get("harness").and_then(Value::as_str) == Some(LOCAL_HARNESS)
        && decision
            .get("artifact_id")
            .and_then(Value::as_str)
            .is_some_and(|id| id.starts_with(&format!("{LOCAL_HARNESS}:project:package-request:")))
        && has_token(decision)
}

/// A retained allow bound to the request's artifact, whatever scope saved it.
/// Only a row with no expiry qualifies: an expiring grant is the short-lived
/// one handled above, and the claim transaction deletes expiring rows, so a
/// durable rule is never selected through this path with an expiry.
pub(super) fn is_durable_exact_artifact_approval(
    decision: &Map<String, Value>,
    artifact_id: &str,
) -> bool {
    is_int(decision.get("decision_id"))
        && text_is(decision, "action", "allow")
        && text_is(decision, "source", "approval-gate")
        && field_or_null(decision, "expires_at").is_null()
        && binds_request_artifact(decision, artifact_id)
}

pub(super) fn is_legacy_package_local_approval(
    decision: &Map<String, Value>,
    request: Option<&Value>,
) -> bool {
    if non_empty_text(decision, "approval_id").is_none()
        || non_empty_text(decision, "request_id").is_none()
        || !field_or_null(decision, "workspace").is_null()
    {
        return false;
    }
    request.and_then(Value::as_object).is_some_and(|row| {
        text_is(row, "artifact_type", "package_request")
            && text_is(row, "status", "resolved")
            && text_is(row, "resolution_action", "allow")
            && text_is(row, "resolution_scope", "artifact")
            && field_or_null(row, "artifact_id") == field_or_null(decision, "artifact_id")
            && field_or_null(row, "artifact_hash") == field_or_null(decision, "artifact_hash")
    })
}
