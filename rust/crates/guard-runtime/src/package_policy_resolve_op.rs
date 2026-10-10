//! `PackagePolicyResolve` — resident op owning the stored package policy
//! override that `local_supply_chain.py` used to decide in Python: whether a
//! saved approval is reused, a saved block is kept, or the saved state is
//! rejected, and which verdict rewrite results.
//!
//! The caller hydrates the facts only it can read (the store lookup, the
//! daemon fallback, the approval request row, the matching bundle rules and the
//! claim disposition) and performs the claim itself. The runtime decides every
//! outcome and returns a patch over the caller's evaluation plus the claim the
//! caller must run. Claim success is assumed on the first call; a failed claim
//! is reported by repeating the request with `claim_succeeded: false`.

use guard_command::action_lattice::most_restrictive_guard_action;
use guard_command::approval_reuse::{
    evaluate_approval_reuse, ApprovalReuseDecision, APPROVAL_REUSE_CLAIM_FAILED,
};
use guard_command::effect_decision::GuardAction;
use guard_command::package_intent_common::GuardArtifact;
use guard_command::package_policy_override as policy;
use guard_contracts::{
    PackageEvaluationComposeRequestV1, PackagePolicyResolveRequestV1, SupplyChainEvalResultV1,
    PACKAGE_AUTHORITY_REQUEST_SCHEMA, PACKAGE_AUTHORITY_RESULT_SCHEMA,
};
use serde_json::{json, Map, Value};

use crate::approval_proof_op::claim_disposition;
use crate::context_digest::{parse_context_token, python_strip, validate_context_tokens};
use crate::package_authority_op::{request_digest, ResidentPackageEval};
use crate::package_evaluation_compose_op::{compose, parse_action, parse_evaluation, patch};

const LOCAL_HARNESS: &str = "guard-cli";
const EVALUATION_KEYS: [&str; 3] = ["policy_action", "reasons", "packages"];

fn invalid() -> String {
    "native_package_policy_resolve_invalid".to_owned()
}

/// Python `_string_value`: the string itself when it is not blank.
fn string_value(value: Option<&Value>) -> Option<&str> {
    value
        .and_then(Value::as_str)
        .filter(|text| !python_strip(text).is_empty())
}

fn text_is(map: &Map<String, Value>, key: &str, expected: &str) -> bool {
    map.get(key).and_then(Value::as_str) == Some(expected)
}

fn is_int(value: Option<&Value>) -> bool {
    value.is_some_and(|number| number.is_i64() || number.is_u64())
}

fn has_token(map: &Map<String, Value>) -> bool {
    map.get("artifact_hash")
        .is_some_and(|hash| parse_context_token(hash).is_some())
}

fn non_empty_text<'a>(map: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    map.get(key)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
}

fn field_or_null<'a>(map: &'a Map<String, Value>, key: &str) -> &'a Value {
    map.get(key).unwrap_or(&Value::Null)
}

fn is_fresh_artifact_approval(decision: &Map<String, Value>, request: Option<&Value>) -> bool {
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

fn is_durable_exact_artifact_approval(decision: &Map<String, Value>) -> bool {
    is_int(decision.get("decision_id"))
        && text_is(decision, "action", "allow")
        && text_is(decision, "source", "approval-gate")
        && text_is(decision, "scope", "artifact")
        && field_or_null(decision, "expires_at").is_null()
        && has_token(decision)
}

fn is_legacy_package_local_approval(
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

/// A policy-bundle family row is stale only when the validated bundle proves
/// no rule with the row's owner still saves package-request decisions.
fn is_stale_policy_bundle_family(
    decision: &Map<String, Value>,
    bundle_rules: Option<&[Value]>,
) -> bool {
    let family_row = string_value(decision.get("source")) == Some("policy-bundle")
        && string_value(decision.get("artifact_id")) == Some("family:package-request")
        && field_or_null(decision, "artifact_hash").is_null()
        && matches!(
            string_value(decision.get("scope")),
            Some("harness" | "global")
        );
    if !family_row || string_value(decision.get("owner")).is_none() {
        return false;
    }
    let Some(rules) = bundle_rules else {
        return false;
    };
    let owner = string_value(decision.get("owner"));
    let mut matching = rules
        .iter()
        .filter_map(Value::as_object)
        .filter(|rule| string_value(rule.get("ruleId")) == owner)
        .peekable();
    if matching.peek().is_none() {
        return true;
    }
    !matching.any(|rule| {
        crate::policy_bundle_families::saved_families(rule)
            .iter()
            .any(|family| family == "package-request")
    })
}

/// `ApprovalReuseDecision.to_evidence()`: every key present, nulls included.
fn reuse_evidence(reuse: &ApprovalReuseDecision) -> Value {
    let mut evidence = json!({
        "action": reuse.action.as_str(),
        "status": reuse.status,
        "reason_code": reuse.reason_code,
        "current_action": reuse.current_action.as_str(),
        "saved_action": reuse.saved_action.map(|action| action.as_str()),
        "should_claim": reuse.should_claim,
        "current_normalization_reason_code": reuse.current_normalization_reason_code,
        "saved_normalization_reason_code": reuse.saved_normalization_reason_code,
        "original_current_action": reuse.original_current_action,
        "original_saved_action": reuse.original_saved_action,
        "original_current_type": reuse.original_current_type,
        "original_saved_type": reuse.original_saved_type,
    });
    if let (Some(flag), Some(map)) = (
        reuse.saved_artifact_hash_is_context_token,
        evidence.as_object_mut(),
    ) {
        map.insert(
            "saved_artifact_hash_is_context_token".to_owned(),
            Value::Bool(flag),
        );
    }
    evidence
}

/// Record whether the saved approval was bound to the context-token contract.
fn with_provenance(
    mut reuse: ApprovalReuseDecision,
    stored_hash: Option<&Value>,
) -> ApprovalReuseDecision {
    if let Some(hash @ Value::String(text)) = stored_hash {
        if !text.is_empty() {
            reuse.saved_artifact_hash_is_context_token = Some(parse_context_token(hash).is_some());
        }
    }
    reuse
}

struct Resolution {
    output: Map<String, Value>,
    claim_disposition: Option<String>,
    claim: Option<&'static str>,
    reused: bool,
}

fn subset(map: &Map<String, Value>) -> Value {
    Value::Object(
        EVALUATION_KEYS
            .iter()
            .filter_map(|key| {
                map.get(*key)
                    .map(|value| ((*key).to_owned(), value.clone()))
            })
            .collect(),
    )
}

/// Run one compose rewrite over `current` and overlay its fields, the way the
/// caller used to apply each patch to the evaluation in turn.
fn rewrite(
    current: &Map<String, Value>,
    kind: &str,
    reuse: Option<&ApprovalReuseDecision>,
    variant: Option<&str>,
    claim_disposition: Option<&str>,
    clear_command: Option<String>,
) -> Result<Map<String, Value>, String> {
    let request = PackageEvaluationComposeRequestV1 {
        schema: PACKAGE_AUTHORITY_REQUEST_SCHEMA.to_owned(),
        request_id: String::new(),
        guard_home: String::new(),
        kind: kind.to_owned(),
        evaluation: subset(current),
        current_action: None,
        approval_reuse: reuse.map(reuse_evidence),
        variant: variant.map(str::to_owned),
        claim_disposition: claim_disposition.map(str::to_owned),
        clear_command,
    };
    let mut merged = current.clone();
    merged.extend(compose(&request)?);
    Ok(merged)
}

fn resolve(request: &PackagePolicyResolveRequestV1) -> Result<Resolution, String> {
    let original = parse_evaluation(&request.evaluation)?;
    let policy_action = original
        .get("policy_action")
        .and_then(Value::as_str)
        .ok_or_else(invalid)?;
    let effective = match request.current_action.as_ref() {
        None => parse_action(policy_action)?,
        Some(current) => most_restrictive_guard_action(
            &[json!(policy_action), current.clone()],
            GuardAction::Block,
        ),
    };
    let current = if effective.as_str() == policy_action {
        original.clone()
    } else {
        let mut merged = original.clone();
        merged.extend(policy::package_evaluation_with_current_policy_action(
            &ResidentPackageEval,
            &original,
            effective,
        ));
        merged
    };
    let unchanged = |output: Map<String, Value>| Resolution {
        output,
        claim_disposition: None,
        claim: None,
        reused: false,
    };
    let decision = request.decision.as_ref().and_then(Value::as_object);
    if decision.is_none() && !request.ignored_integrity && request.diagnosed_reason.is_none() {
        return Ok(unchanged(current));
    }
    if decision
        .is_some_and(|row| is_stale_policy_bundle_family(row, request.bundle_rules.as_deref()))
    {
        return Ok(unchanged(current));
    }
    let action = match decision {
        Some(row) => field_or_null(row, "action").clone(),
        None if request.ignored_integrity => json!("require-reapproval"),
        None => json!("allow"),
    };
    let artifact_hash = Value::String(request.artifact_hash.clone());
    let validation_reason: Option<String> = if request.ignored_integrity {
        Some("approval_reuse_integrity_failure".to_owned())
    } else if let Some(row) = decision {
        if text_is(row, "action", "allow") {
            validate_context_tokens(field_or_null(row, "artifact_hash"), &artifact_hash)
        } else {
            None
        }
    } else {
        request.diagnosed_reason.clone()
    };
    let approval_request = request.approval_request.as_ref();
    let legacy_local_approval =
        decision.is_some_and(|row| is_legacy_package_local_approval(row, approval_request));
    let fresh_local_approval = decision
        .is_some_and(|row| is_fresh_artifact_approval(row, approval_request))
        || legacy_local_approval;
    let durable_exact_approval = decision.is_some_and(is_durable_exact_artifact_approval);
    let current_value = json!(effective.as_str());
    let stored_hash: Option<Value> = match decision {
        Some(row) => row.get("artifact_hash").cloned(),
        None => request.diagnosed_stored_hash.clone().map(Value::String),
    };
    let mut reuse = with_provenance(
        evaluate_approval_reuse(
            &current_value,
            Some(&action),
            Some(true),
            validation_reason.as_deref(),
            fresh_local_approval,
            durable_exact_approval,
        ),
        stored_hash.as_ref(),
    );
    let claim_disposition = if fresh_local_approval {
        Some("consumed".to_owned())
    } else {
        decision
            .and_then(claim_disposition)
            .map(|disposition| disposition.as_str().to_owned())
    };
    let claim_needed = request.claim_saved_approval && reuse.should_claim;
    let claim = match (claim_needed, decision) {
        (true, Some(_)) if request.daemon_authority => Some("daemon"),
        (true, Some(_)) if legacy_local_approval => Some("legacy_local"),
        (true, Some(_)) => Some("store"),
        _ => None,
    };
    if claim.is_some() && request.claim_succeeded == Some(false) {
        reuse = with_provenance(
            evaluate_approval_reuse(
                &current_value,
                Some(&action),
                Some(true),
                Some(APPROVAL_REUSE_CLAIM_FAILED),
                false,
                false,
            ),
            stored_hash.as_ref(),
        );
    }
    let resolution = |output, disposition, reused| Resolution {
        output,
        claim_disposition: disposition,
        claim,
        reused,
    };
    if reuse.accepted() && reuse.saved_action == Some(GuardAction::Allow) {
        if !decision.is_some_and(|row| text_is(row, "action", "allow")) {
            let failed = with_provenance(
                evaluate_approval_reuse(
                    &json!(most_restrictive_guard_action(
                        &[current_value.clone(), json!("require-reapproval")],
                        GuardAction::Block
                    )
                    .as_str()),
                    Some(&json!("allow")),
                    Some(true),
                    Some(APPROVAL_REUSE_CLAIM_FAILED),
                    false,
                    false,
                ),
                stored_hash.as_ref(),
            );
            let output = rewrite(&current, "rejected_reuse", Some(&failed), None, None, None)?;
            return Ok(resolution(output, None, false));
        }
        let output = rewrite(
            &current,
            "saved_allow",
            Some(&reuse),
            Some("reused"),
            claim_disposition.as_deref(),
            None,
        )?;
        return Ok(resolution(output, claim_disposition, true));
    }
    if reuse.saved_action == Some(GuardAction::Block) {
        let row = decision.ok_or_else(invalid)?;
        let artifact = GuardArtifact {
            artifact_id: request.artifact_id.clone(),
            name: String::new(),
            harness: request.harness.clone(),
            artifact_type: String::new(),
            source_scope: String::new(),
            config_path: String::new(),
            command: None,
            args: Vec::new(),
            url: None,
            transport: None,
            publisher: None,
            metadata: Value::Null,
            runtime_private_metadata: Value::Null,
        };
        let clear = policy::saved_package_policy_clear_command(
            &artifact,
            &request.artifact_hash,
            row,
            &request.workspace_dir,
        );
        let output = rewrite(
            &current,
            "saved_block",
            Some(&reuse),
            None,
            None,
            Some(clear),
        )?;
        return Ok(resolution(output, None, false));
    }
    let output = rewrite(&current, "rejected_reuse", Some(&reuse), None, None, None)?;
    Ok(resolution(output, None, false))
}

pub(crate) fn evaluate_package_policy_resolve(
    request: &PackagePolicyResolveRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest(request)?;
    if request.schema != PACKAGE_AUTHORITY_REQUEST_SCHEMA {
        return Err("native_package_policy_resolve_schema_mismatch".to_owned());
    }
    if request.request_id.is_empty()
        || request.guard_home.is_empty()
        || request.harness.is_empty()
        || request.artifact_id.is_empty()
        || request
            .decision
            .as_ref()
            .is_some_and(|row| !row.is_object())
    {
        return Err(invalid());
    }
    let resolution = resolve(request)?;
    let mut payload = Map::new();
    payload.insert(
        "patch".to_owned(),
        patch(&request.evaluation, resolution.output),
    );
    payload.insert("claim".to_owned(), json!(resolution.claim));
    payload.insert(
        "claim_disposition".to_owned(),
        json!(resolution.claim_disposition),
    );
    payload.insert("reused".to_owned(), json!(resolution.reused));
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
#[path = "package_policy_resolve_op_tests.rs"]
mod tests;
