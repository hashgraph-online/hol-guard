//! The portable Git-identity composition of a consuming saved lookup.
//!
//! `resolve_policy_decision_lookup` (`store_portable_project_memory.py`) wraps
//! the resident's own lookup: it previews the portable selector without
//! consuming it, discards any one-shot or permission-lowering decision it
//! carries (`_portable_lookup_without_permission_elevation`), composes that
//! with the local preview most restrictive, and only then claims the effective
//! allow. Portable Git metadata is classification, not authentication — it
//! lives inside the workspace and can be forged by it — so local-path
//! authority is the only source allowed to lower enforcement below review.
//!
//! Python keeps deriving the portable identity (`_portable_project_workspace`)
//! and ships it as `portable_workspace`: the resident's own
//! `project_identity::portable_workspace` can answer
//! `PortableIdentity::Unknown`, and every caller of that answer defers, which
//! a store lookup has no way to do.
//!
//! The claim reuses the request's `now`, as the Python wrapper passes the
//! caller's `now` straight through to `claim_approval_reuse_decision`. It also
//! reuses the lookup's integrity evidence: the previews only read, so the
//! refreshed state the Python claim would procure is the state the lookup
//! already shipped, and `evidence_binding` makes the resident refuse under the
//! write lock if anything it was derived against has moved.

use guard_contracts::{canonical_utc_timestamp, PolicyDecisionLookupRequestV1};
use rusqlite::Connection;
use serde_json::Value;

use crate::mcp_tool_policy_lookup::{severity, REVIEW_FLOOR};
use crate::policy_decision_lookup_op::{evaluate_non_consuming, open_lookup_connection};

const ERR_INVALID: &str = "native_policy_decision_lookup_invalid";
const ERR_STORE: &str = "native_policy_decision_lookup_write_failed";

/// Remove the preview-only authority revision from an enforcement result
/// (`_without_authority_revision`).
pub(crate) fn without_authority_revision(lookup: Value) -> Value {
    let Some(decision) = lookup.get("decision").and_then(Value::as_object) else {
        return lookup;
    };
    if !decision.contains_key("_approval_authority_revision") {
        return lookup;
    }
    let mut decision = decision.clone();
    decision.remove("_approval_authority_revision");
    let mut sanitized = lookup.as_object().cloned().unwrap_or_default();
    sanitized.insert("decision".to_owned(), Value::Object(decision));
    Value::Object(sanitized)
}

/// Fail closed after a saved allow cannot be atomically claimed
/// (`_restrictive_only_lookup`): only restrictive policy survives, and the
/// permission can be presented again on the caller's next approval cycle.
fn restrictive_only(lookup: Value) -> Value {
    let restrictive = match lookup.get("decision") {
        Some(Value::Object(decision)) => severity(decision.get("action")) >= REVIEW_FLOOR,
        _ => true,
    };
    let sanitized = without_authority_revision(lookup);
    if restrictive {
        return sanitized;
    }
    let mut cleared = sanitized.as_object().cloned().unwrap_or_default();
    cleared.insert("decision".to_owned(), Value::Null);
    Value::Object(cleared)
}

fn decode_key(encoded: Option<&str>) -> Option<Vec<u8>> {
    use base64ct::{Base64UrlUnpadded, Encoding};
    Base64UrlUnpadded::decode_vec(encoded?).ok()
}

/// The composed preview of one request, with nothing consumed.
fn compose(
    request: &PolicyDecisionLookupRequestV1,
    portable: &str,
    connection: &Connection,
) -> Result<Value, String> {
    let mut probe = |workspace: Option<&str>| -> Result<Value, String> {
        let probe = PolicyDecisionLookupRequestV1 {
            workspace: workspace.map(str::to_owned),
            consume_one_shot: false,
            portable_workspace: None,
            evidence_binding: None,
            ..request.clone()
        };
        evaluate_non_consuming(&probe, connection)
    };
    crate::policy_lookup_groups::compose_portable(
        Some(portable),
        request.workspace.as_deref(),
        &mut probe,
    )
}

/// Claim the exact preview the composition selected. The embedded authority
/// revision keeps a stale allow from surviving a concurrent policy or approval
/// change, and a failed member rolls the whole claim back.
fn claim(
    request: &PolicyDecisionLookupRequestV1,
    connection: &Connection,
    decision: &Value,
    now: &str,
) -> Result<bool, String> {
    let integrity_key = decode_key(request.integrity_key_b64.as_deref());
    let local_once_key = decode_key(request.local_once_integrity_key_b64.as_deref());
    let evidence = crate::claim_reuse::ClaimEvidence {
        integrity_state: request.integrity_state.as_ref(),
        integrity_key: integrity_key.as_deref(),
        integrity_key_id: request.integrity_key_id.as_deref(),
        local_once_key: local_once_key.as_deref(),
        local_once_key_id: request.local_once_integrity_key_id.as_deref(),
        policy_bundle_identities: request.policy_bundle_decision_identities.as_deref(),
    };
    let decisions = [decision.clone()];
    crate::claim_reuse::claim_approval_reuse_decisions(
        connection,
        &decisions,
        now,
        &evidence,
        &|connection, members| {
            crate::claim_reuse_binding::evidence_is_bound(
                connection,
                members,
                &evidence,
                request.evidence_binding.as_ref(),
            )
        },
    )
    .map_err(|_| ERR_STORE.to_owned())
}

pub(crate) fn evaluate(
    request: &PolicyDecisionLookupRequestV1,
    portable: &str,
) -> Result<Value, String> {
    // The exact local-once peek never reads portable authority, so Python
    // derives no identity for it (`local_once_only` short-circuits first).
    if request.local_once_only || portable.is_empty() {
        return Err(ERR_INVALID.to_owned());
    }
    let now = canonical_utc_timestamp(&request.now)
        .ok_or_else(|| "native_policy_decision_lookup_invalid_now".to_owned())?;
    let connection = open_lookup_connection(&request.store_path)?;
    let composed = compose(request, portable, &connection)?;
    if !request.consume_one_shot {
        return Ok(composed);
    }
    // Portable permission-lowering decisions were removed during composition,
    // so any effective allow came from local authority.
    let allow = composed
        .get("decision")
        .and_then(Value::as_object)
        .and_then(|decision| decision.get("action"))
        .and_then(Value::as_str)
        == Some("allow");
    if !allow {
        return Ok(without_authority_revision(composed));
    }
    let decision = composed
        .get("decision")
        .cloned()
        .ok_or_else(|| ERR_INVALID.to_owned())?;
    if claim(request, &connection, &decision, &now)? {
        return Ok(without_authority_revision(composed));
    }
    // Authority changed between preview and claim: recompute consuming
    // nothing and retain only restrictive policy.
    Ok(restrictive_only(compose(request, portable, &connection)?))
}

#[cfg(all(test, unix))]
#[path = "policy_lookup_portable_tests.rs"]
mod tests;
