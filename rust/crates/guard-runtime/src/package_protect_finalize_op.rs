//! `PackageProtectFinalize` — resident op owning the decision tail of
//! `local_supply_chain._final_package_protect_authority` that Python used to
//! drive through separate approval-reuse, context-token, verdict-rewrite and
//! stored-policy round trips.
//!
//! The caller still refreshes config and additional authority, runs the
//! initial saved-approval claim and rebuilds the package authority. It sends
//! the outcome of those steps plus the read-only stored-policy facts for the
//! rebuilt artifact; the runtime decides whether the claimed approval still
//! holds, whether an unclaimed one must be rejected, and which verdict
//! rewrite results, and returns a patch over the caller's evaluation.

use guard_command::approval_reuse::{
    evaluate_approval_reuse, ApprovalReuseDecision, APPROVAL_REUSE_CLAIM_FAILED,
    APPROVAL_REUSE_CONTEXT_CHANGED_AFTER_CLAIM,
};
use guard_command::effect_decision::GuardAction;
use guard_command::package_policy_override as policy;
use guard_contracts::{
    PackagePolicyResolveRequestV1, PackageProtectFinalizeRequestV1, SupplyChainEvalResultV1,
    PACKAGE_AUTHORITY_REQUEST_SCHEMA, PACKAGE_AUTHORITY_RESULT_SCHEMA,
};
use serde_json::{json, Map, Value};

use crate::context_digest::validate_context_tokens;
use crate::package_authority_op::{request_digest, ResidentPackageEval};
use crate::package_evaluation_compose_op::{parse_action, parse_evaluation, patch};
use crate::package_policy_resolve_op::{resolve_unclaimed, rewrite};

const IDENTITY_CHANGED: &str = "approval_reuse_identity_changed";
/// Fields the stored-policy facts must not carry: the runtime fills them.
const RESERVED_POLICY_KEYS: [&str; 7] = [
    "schema",
    "request_id",
    "guard_home",
    "evaluation",
    "current_action",
    "claim_saved_approval",
    "claim_succeeded",
];

fn invalid() -> String {
    "native_package_protect_finalize_invalid".to_owned()
}

/// Saved-approval reuse for a decision the caller already holds.
fn reuse(
    current_action: &str,
    saved_action: &str,
    validation_reason: Option<&str>,
    fresh_local_approval: bool,
) -> ApprovalReuseDecision {
    evaluate_approval_reuse(
        &json!(current_action),
        Some(&json!(saved_action)),
        Some(true),
        validation_reason,
        fresh_local_approval,
        false,
    )
}

fn rejected(
    evaluation: &Map<String, Value>,
    reuse: &ApprovalReuseDecision,
) -> Result<Map<String, Value>, String> {
    rewrite(evaluation, "rejected_reuse", Some(reuse), None, None, None)
}

fn reasons(evaluation: &Map<String, Value>) -> impl Iterator<Item = &Map<String, Value>> {
    evaluation
        .get("reasons")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
}

/// Python `_evaluation_uses_saved_package_approval`.
fn uses_saved_approval(evaluation: &Map<String, Value>) -> bool {
    reasons(evaluation)
        .any(|reason| reason.get("code").and_then(Value::as_str) == Some("saved_package_approval"))
}

/// Python `_package_approval_reuse_evidence` is non-empty.
fn has_reuse_evidence(evaluation: &Map<String, Value>) -> bool {
    reasons(evaluation).any(|reason| reason.get("approval_reuse").is_some_and(Value::is_object))
}

/// Python `_package_evaluation_with_current_policy_action`: current package
/// policy applies before any remembered user state is consulted.
fn with_current_policy_action(
    evaluation: &Map<String, Value>,
    current_action: GuardAction,
) -> Map<String, Value> {
    if evaluation.get("policy_action").and_then(Value::as_str) == Some(current_action.as_str()) {
        return evaluation.clone();
    }
    let mut merged = evaluation.clone();
    merged.extend(policy::package_evaluation_with_current_policy_action(
        &ResidentPackageEval,
        evaluation,
        current_action,
    ));
    merged
}

/// The stored package policy override for the rebuilt artifact, read-only
/// (`claim_saved_approval: false`), applied over `evaluation`.
fn stored_policy(
    request: &PackageProtectFinalizeRequestV1,
    evaluation: &Map<String, Value>,
    current_action: &str,
) -> Result<Map<String, Value>, String> {
    let mut facts = request
        .stored_policy
        .as_ref()
        .and_then(Value::as_object)
        .cloned()
        .ok_or_else(invalid)?;
    if RESERVED_POLICY_KEYS
        .iter()
        .any(|key| facts.contains_key(*key))
    {
        return Err(invalid());
    }
    let subset: Map<String, Value> = ["policy_action", "reasons", "packages"]
        .iter()
        .filter_map(|key| {
            evaluation
                .get(*key)
                .map(|value| ((*key).to_owned(), value.clone()))
        })
        .collect();
    facts.insert("schema".to_owned(), json!(request.schema));
    facts.insert("request_id".to_owned(), json!(request.request_id));
    facts.insert("guard_home".to_owned(), json!(request.guard_home));
    facts.insert("evaluation".to_owned(), Value::Object(subset));
    facts.insert("current_action".to_owned(), json!(current_action));
    facts.insert("claim_saved_approval".to_owned(), Value::Bool(false));
    let resolve_request: PackagePolicyResolveRequestV1 =
        serde_json::from_value(Value::Object(facts)).map_err(|_| invalid())?;
    let mut merged = evaluation.clone();
    merged.extend(resolve_unclaimed(&resolve_request)?);
    Ok(merged)
}

fn finalize(request: &PackageProtectFinalizeRequestV1) -> Result<Map<String, Value>, String> {
    let base = parse_evaluation(&request.evaluation)?;
    let Some(current_text) = request.current_action.as_deref() else {
        // The rebuild found no package intent: the saved approval cannot be
        // bound to anything that will run.
        if request.current_artifact_id.is_some() || request.current_artifact_hash.is_some() {
            return Err(invalid());
        }
        return rejected(
            &base,
            &reuse("review", "allow", Some(IDENTITY_CHANGED), false),
        );
    };
    let current_action = parse_action(current_text)?;
    let (Some(current_id), Some(current_hash)) = (
        request.current_artifact_id.as_deref(),
        request.current_artifact_hash.as_deref(),
    ) else {
        return Err(invalid());
    };
    let validation_reason = if current_id != request.initial_artifact_id {
        Some(IDENTITY_CHANGED.to_owned())
    } else {
        validate_context_tokens(&json!(request.initial_artifact_hash), &json!(current_hash))
    };
    let current = with_current_policy_action(&base, current_action);
    if request.claim_failed || request.observe_mode {
        return Ok(current);
    }
    if request.saved_approval_claimed {
        if let Some(reason) = validation_reason.as_deref() {
            return rejected(&current, &reuse(current_text, "allow", Some(reason), false));
        }
        let refreshed = stored_policy(request, &current, current_text)?;
        if uses_saved_approval(&refreshed) || has_reuse_evidence(&refreshed) {
            return Ok(refreshed);
        }
        if request.claim_disposition.as_deref() != Some("consumed") {
            let after_claim = reuse(
                current_text,
                "allow",
                Some(APPROVAL_REUSE_CONTEXT_CHANGED_AFTER_CLAIM),
                false,
            );
            return rejected(&current, &after_claim);
        }
        let revalidated = reuse(current_text, "allow", None, true);
        if revalidated.accepted() && revalidated.saved_action == Some(GuardAction::Allow) {
            return rewrite(
                &current,
                "saved_allow",
                Some(&revalidated),
                Some("claimed_revalidated"),
                None,
                None,
            );
        }
        return rejected(&current, &revalidated);
    }
    if let Some(reason) = validation_reason.as_deref() {
        let changed = reuse(current_text, "require-reapproval", Some(reason), false);
        return rejected(&current, &changed);
    }
    let resolved = stored_policy(request, &current, current_text)?;
    if uses_saved_approval(&resolved) {
        // Only the claim at the start of the launch may use a saved approval.
        let unclaimed = reuse(
            current_text,
            "allow",
            Some(APPROVAL_REUSE_CLAIM_FAILED),
            false,
        );
        return rejected(&current, &unclaimed);
    }
    Ok(resolved)
}

pub(crate) fn evaluate_package_protect_finalize(
    request: &PackageProtectFinalizeRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest(request)?;
    if request.schema != PACKAGE_AUTHORITY_REQUEST_SCHEMA {
        return Err("native_package_protect_finalize_schema_mismatch".to_owned());
    }
    let disposition_valid = match request.claim_disposition.as_deref() {
        None => true,
        Some("consumed" | "retained") => request.saved_approval_claimed,
        Some(_) => false,
    };
    if request.request_id.is_empty()
        || request.guard_home.is_empty()
        || (request.claim_failed && request.saved_approval_claimed)
        || !disposition_valid
    {
        return Err(invalid());
    }
    let output = finalize(request)?;
    let mut payload = Map::new();
    payload.insert("patch".to_owned(), patch(&request.evaluation, output));
    crate::encode_response(&SupplyChainEvalResultV1 {
        schema: PACKAGE_AUTHORITY_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: "ok".to_owned(),
        code: "ok".to_owned(),
        payload: Some(Value::Object(payload)),
    })
}

#[cfg(test)]
#[path = "package_protect_finalize_op_tests.rs"]
mod tests;
