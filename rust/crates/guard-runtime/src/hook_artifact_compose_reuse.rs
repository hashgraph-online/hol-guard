//! Saved/claimed approval reuse, trusted-request override, and decision copy
//! queries of `HookArtifactCompose`. Pure: callers pass gathered evidence and
//! perform any store claim between queries.

use guard_command::approval_reuse::{
    evaluate_approval_reuse, ApprovalReuseDecision, APPROVAL_REUSE_CONTEXT_CHANGED_AFTER_CLAIM,
};
use guard_contracts::{
    ClaimedReuseQueryV1, DecisionBuildCopyQueryV1, DecisionCopyQueryV1, GuardAction,
    PackageReuseSettleQueryV1, RememberedRuleReasonQueryV1, SavedReuseQueryV1,
    TrustedOverrideQueryV1,
};
use serde_json::{json, Map, Value};

use crate::hook_artifact_compose_op::{act, coerce, name, stricter};

const INTEGRITY_FAILURE: &str = "approval_reuse_integrity_failure";
const REVIEW_ACTIONS: [&str; 2] = ["review", "require-reapproval"];
const CLOUD_REASON_CODES: [&str; 4] = [
    "cloud_auth_error",
    "cloud_validation_error",
    "cloud_http_error",
    "cloud_timeout",
];

/// Record whether the saved approval was bound to the context-token contract.
fn with_provenance(mut decision: ApprovalReuseDecision, stored_hash: &Value) -> Value {
    if stored_hash.as_str().is_some_and(|hash| !hash.is_empty()) {
        decision.saved_artifact_hash_is_context_token =
            Some(crate::context_digest::parse_context_token(stored_hash).is_some());
    }
    serde_json::to_value(decision).unwrap_or(Value::Null)
}

pub(crate) fn input_evidence(input_source: &str, reuse: &Value) -> Value {
    let mut evidence = Map::new();
    evidence.insert("source".into(), json!("approval_reuse"));
    evidence.insert("input_source".into(), json!(input_source));
    if let Value::Object(fields) = reuse {
        evidence.extend(fields.clone());
    }
    Value::Object(evidence)
}

fn reuse_action(reuse: &Value) -> Value {
    reuse.get("action").cloned().unwrap_or(Value::Null)
}

pub(crate) fn saved_reuse(query: &SavedReuseQueryV1) -> Value {
    let mut saved_action = query.stored_action.clone();
    let mut saved_present = query.stored_present;
    let mut validation: Option<String> = None;
    let mut source: Option<&str> = None;
    let mut diagnosed_hash = Value::Null;
    if query.integrity_failure {
        // A matching integrity-invalid local rule is security-relevant even
        // when a different, valid saved allow also matched.
        validation = Some(INTEGRITY_FAILURE.to_owned());
    } else if query.stored_present {
        validation = query.stored_validation_reason.clone();
    }
    if !saved_present && query.cursor_native_present {
        saved_action = json!("allow");
        saved_present = true;
        source = Some("cursor_native_approval");
        if query.cursor_validation_reason.is_some() {
            validation = query.cursor_validation_reason.clone();
        }
    } else if !saved_present && validation.is_none() {
        diagnosed_hash = query.diagnostic_stored_hash.clone();
        if query.diagnostic_reason.is_some() {
            validation = query.diagnostic_reason.clone();
            saved_action = json!("allow");
        }
    }
    if saved_present {
        source = source.or(Some("saved_policy_decision"));
    } else if let Some(reason) = &validation {
        saved_present = true;
        source = Some(if reason == INTEGRITY_FAILURE {
            "saved_policy_integrity"
        } else {
            "invalidated_saved_policy"
        });
    }
    let decision = evaluate_approval_reuse(
        &query.current_action,
        Some(&saved_action),
        Some(saved_present),
        validation.as_deref(),
        false,
        false,
    );
    let provenance_hash = if query.stored_present {
        &query.stored_artifact_hash
    } else {
        &diagnosed_hash
    };
    let reuse = with_provenance(decision, provenance_hash);
    json!({
        "approval_reuse": reuse,
        "approval_reuse_source": source,
        "policy_action": reuse_action(&reuse),
    })
}

pub(crate) fn saved_block_reuse(
    current_action: &Value,
    policy_action: &Value,
    stored_hash: &Value,
) -> Value {
    let decision = evaluate_approval_reuse(
        current_action,
        Some(&json!("block")),
        Some(true),
        None,
        false,
        false,
    );
    let reuse = with_provenance(decision, stored_hash);
    let policy = stricter(act(policy_action), act(&reuse_action(&reuse)));
    json!({ "approval_reuse": reuse, "policy_action": policy.as_str() })
}

/// The reuse a package request's own reasons record, settled with the saved
/// policy decision that carries them.
///
/// `_evaluate_package_request`'s reason scan (`commands_hook_native_eval`).
/// Python read the evaluation's reasons itself to decide whether a saved
/// approval or block had been applied, which disposition a claim had, and what
/// the action became; every one of those is a verdict. It asks here instead,
/// and the saved-block reuse of the same request is settled in this answer
/// rather than a second query, so the package branch still costs one round
/// trip.
///
/// The scan keeps the loop's precedence exactly: the first reason carrying an
/// `approval_reuse` mapping ends it, and a disposition is kept only when the
/// reason names one of the two the claim can report.
pub(crate) fn package_reuse_settle(query: &PackageReuseSettleQueryV1) -> Value {
    let mut reuse_applied = false;
    let mut saved_allow_applied = false;
    let mut claim_disposition = Value::Null;
    let mut reuse_evidence = Value::Null;
    let mut source = query.approval_reuse_source.clone();
    let mut evidence_appends: Vec<Value> = Vec::new();
    for reason in &query.reasons {
        let code = reason.get("code").and_then(Value::as_str);
        if matches!(
            code,
            Some("saved_package_approval") | Some("saved_package_block")
        ) {
            reuse_applied = true;
            source = json!(PACKAGE_POLICY_SOURCE);
        }
        if code == Some("saved_package_approval") {
            saved_allow_applied = true;
            if let Some(disposition) = reason
                .get("approval_claim_disposition")
                .and_then(Value::as_str)
                .filter(|named| matches!(*named, "consumed" | "retained"))
            {
                claim_disposition = json!(disposition);
            }
        }
        let raw_reuse = reason.get("approval_reuse");
        if let Some(raw_reuse) = raw_reuse.filter(|value| value.is_object()) {
            reuse_applied = true;
            reuse_evidence = raw_reuse.clone();
            evidence_appends.push(input_evidence(PACKAGE_POLICY_SOURCE, raw_reuse));
            source = json!(PACKAGE_POLICY_SOURCE);
            break;
        }
    }
    // A claimed saved allow is revalidated at the execution boundary, so the
    // caller stops here: the settlement below describes the pass that does not
    // revalidate, and its evidence belongs to that pass alone.
    let revalidate_required = saved_allow_applied && query.claim_saved_approval;
    let mut policy_action = if reuse_applied {
        coerce(&query.evaluation_policy_action).unwrap_or_else(|| act(&query.current_action))
    } else {
        act(&query.current_action)
    };
    let mut approval_reuse = Value::Null;
    let mut settled_evidence_appends: Vec<Value> = Vec::new();
    if query.stored_policy_action.as_str() == Some("block") {
        let settled = saved_block_reuse(
            &query.current_action,
            &json!(policy_action.as_str()),
            &query.stored_artifact_hash,
        );
        policy_action = act(settled.get("policy_action").unwrap_or(&Value::Null));
        approval_reuse = settled
            .get("approval_reuse")
            .cloned()
            .unwrap_or(Value::Null);
        if source.as_str().is_none() {
            source = json!(POLICY_DECISION_SOURCE);
        }
        if !reuse_applied {
            settled_evidence_appends.push(input_evidence(
                source.as_str().unwrap_or(POLICY_DECISION_SOURCE),
                &approval_reuse,
            ));
        }
    }
    json!({
        "reuse_applied": reuse_applied,
        "saved_allow_applied": saved_allow_applied,
        "claim_disposition": claim_disposition,
        "reuse_evidence": reuse_evidence,
        "revalidate_required": revalidate_required,
        "approval_reuse_source": source,
        "policy_action": policy_action.as_str(),
        "approval_reuse": approval_reuse,
        "evidence_appends": evidence_appends,
        "settled_evidence_appends": settled_evidence_appends,
    })
}

/// The input sources the package branch names for its reuse evidence.
const PACKAGE_POLICY_SOURCE: &str = "saved_package_policy";
const POLICY_DECISION_SOURCE: &str = "saved_policy_decision";

pub(crate) fn trusted_override(query: &TrustedOverrideQueryV1) -> Value {
    let mut reason = query.token_validation_reason.clone();
    let policy = act(&query.policy_action);
    if reason.is_none() && REVIEW_ACTIONS.contains(&policy.as_str()) {
        let exact_allow = query.stored_present
            && query.stored_action.as_str() == Some("allow")
            && matches!(
                query.stored_source.as_str(),
                Some("approval-gate" | "approval-gate-once")
            )
            && query.stored_validation_reason.is_none();
        if query.remembered_rule_rejected
            || query.prior_reuse_reason_code.as_deref() == Some(INTEGRITY_FAILURE)
        {
            reason = Some("trusted_request_override_integrity_failure".to_owned());
        } else if !exact_allow {
            reason = Some("trusted_request_override_allow_missing".to_owned());
        } else if query.claim_succeeded.is_none() {
            return json!({ "claim_required": true, "reason_code": null, "evidence": null });
        } else if query.claim_succeeded == Some(false) {
            reason = Some("trusted_request_override_claim_failed".to_owned());
        }
    }
    json!({
        "claim_required": false,
        "reason_code": reason,
        "evidence": {
            "source": "trusted_request_override",
            "applied": false,
            "reason_code": reason,
            "authoritative_action": policy.as_str(),
        },
    })
}

pub(crate) fn claimed_reuse(query: &ClaimedReuseQueryV1) -> Value {
    let context_changed = query.token_validation_reason.clone();
    let integrity = query.remembered_rule_rejected
        || query
            .prior_reuse
            .as_ref()
            .is_some_and(|prior| prior.reason_code.as_deref() == Some(INTEGRITY_FAILURE))
        || (query.workflow_capability_required && !query.workflow_authorization_claimed);
    let validation: Option<String> = if integrity {
        Some(INTEGRITY_FAILURE.to_owned())
    } else if query.post_claim_refresh_failed || context_changed.is_some() {
        Some(APPROVAL_REUSE_CONTEXT_CHANGED_AFTER_CLAIM.to_owned())
    } else {
        None
    };
    let policy = act(&query.policy_action);
    let saved_allow_accepted = query.prior_reuse.as_ref().is_some_and(|prior| {
        prior.saved_action.as_str() == Some("allow") && prior.action.as_str() == Some("allow")
    }) || (query.package_reuse_saved_action.as_str() == Some("allow")
        && policy == GuardAction::Allow);
    let mut post_claim = if saved_allow_accepted {
        act(&query.current_policy_action)
    } else {
        policy
    };
    let overridden = query.claimed_trusted_request_override;
    let in_review = REVIEW_ACTIONS.contains(&post_claim.as_str());
    if validation.is_some() {
        post_claim = stricter(post_claim, GuardAction::RequireReapproval);
    } else if query.workflow_authorization_claimed && post_claim == GuardAction::RequireReapproval {
        // The exact workflow capability is the fresh reapproval for this task;
        // stronger sandbox and block results remain authoritative.
        post_claim = GuardAction::Review;
    } else if overridden && in_review {
        // A just-resolved exact browser request is stronger than ordinary
        // remembered approval evidence once its one-shot row has been claimed.
        post_claim = GuardAction::Review;
    }
    let decision = evaluate_approval_reuse(
        &name(post_claim),
        Some(&json!("allow")),
        Some(true),
        validation.as_deref(),
        query.claimed_package_approval_consumed || overridden,
        false,
    );
    let accepted = decision.accepted();
    let reuse = with_provenance(decision, &query.claimed_hash);
    let applied = overridden && accepted && reuse_action(&reuse).as_str() == Some("allow");
    let source = if query.workflow_authorization_claimed {
        "claimed_github_workflow_capability"
    } else if overridden {
        "claimed_trusted_request_override"
    } else {
        "claimed_saved_policy_decision"
    };
    let mut evidence = input_evidence(source, &reuse);
    if let (Some(_), Value::Object(fields)) = (&validation, &mut evidence) {
        fields.insert(
            "post_claim_context_change_reason".into(),
            json!(context_changed),
        );
        fields.insert(
            "post_claim_refresh_failed".into(),
            json!(query.post_claim_refresh_failed),
        );
    }
    json!({
        "approval_reuse": reuse,
        "approval_reuse_source": source,
        "policy_action": reuse_action(&reuse),
        "trusted_request_override_applied": applied,
        "trusted_request_override_reason": if applied {
            json!("trusted_request_override_exact_context")
        } else {
            json!(validation)
        },
        "evidence": evidence,
    })
}

pub(crate) fn decision_build_copy(query: &DecisionBuildCopyQueryV1) -> Result<Value, String> {
    use guard_command::decisions::{decision_from_legacy_policy_action, parse_signals};

    let invalid = || "native_hook_artifact_compose_payload_invalid".to_owned();
    let action = query
        .copy
        .policy_action
        .as_str()
        .and_then(GuardAction::from_canonical)
        .ok_or_else(invalid)?;
    let signals = parse_signals(&query.signals).map_err(|error| error.to_string())?;
    let mut decision =
        decision_from_legacy_policy_action(action, &query.reason, &signals).to_value();
    let mut copy = query.copy.clone();
    copy.base_user_body = decision["user_body"].clone();
    copy.base_harness_message = decision["harness_message"].clone();
    copy.base_dashboard_primary_detail = decision["dashboard_primary_detail"].clone();
    let overlay = decision_copy(&copy);
    let fields = decision.as_object_mut().ok_or_else(invalid)?;
    let overrides = overlay["decision_overrides"]
        .as_object()
        .ok_or_else(invalid)?;
    fields.extend(overrides.clone());
    Ok(json!({"decision_v2": decision, "risk_headline": overlay["risk_headline"]}))
}

pub(crate) fn decision_copy(query: &DecisionCopyQueryV1) -> Value {
    let policy = act(&query.policy_action);
    let in_review = REVIEW_ACTIONS.contains(&policy.as_str());
    let mut copy: Map<String, Value> = Map::new();
    let mut base: Map<String, Value> = Map::new();
    base.insert("user_body".into(), query.base_user_body.clone());
    base.insert("harness_message".into(), query.base_harness_message.clone());
    base.insert(
        "dashboard_primary_detail".into(),
        query.base_dashboard_primary_detail.clone(),
    );
    let package = query.package.as_ref();
    if let Some(package) = package {
        if let Some(code) = CLOUD_REASON_CODES
            .iter()
            .find(|code| package.reason_codes.iter().any(|item| item == *code))
        {
            copy.insert("package_review_cloud_reason_code".into(), json!(code));
        }
    }
    let package_matches = coerce(&query.package_policy_action) == Some(policy);
    if let (Some(package), true, false) = (package, package_matches, query.has_compound_findings) {
        copy.insert("user_title".into(), json!(package.user_title));
        copy.insert("user_body".into(), json!(package.user_summary));
        copy.insert(
            "harness_message".into(),
            json!(package.user_harness_message),
        );
        copy.insert(
            "dashboard_primary_detail".into(),
            json!(package.user_summary),
        );
    } else if query.scanner_raised_to_block {
        // The scanner escalated a weaker package verdict to a block: surface
        // the escalated block copy, not the weaker package copy.
        copy.insert("user_title".into(), json!("Critical install blocked"));
        if let Some(package) = package {
            copy.insert("user_body".into(), json!(package.user_summary));
            copy.insert(
                "harness_message".into(),
                json!(package.user_harness_message),
            );
        }
    }
    if let (true, GuardAction::Block, Some(primary)) = (
        query.has_scanner_evidence,
        policy,
        &query.scanner_primary_signal,
    ) {
        copy.insert("dashboard_primary_detail".into(), json!(primary));
    }
    if let (true, Some(count)) = (query.has_compound_findings, query.compound_finding_count) {
        let phrase = match policy {
            GuardAction::Allow => "allowed",
            GuardAction::Warn => "allowed with a warning",
            GuardAction::SandboxRequired => "requires a sandbox for",
            GuardAction::Review | GuardAction::RequireReapproval => "paused for one review",
            GuardAction::Block => "blocked",
        };
        copy.insert(
            "user_body".into(),
            json!(format!(
                "Guard combined {count} findings for the complete command. {}",
                query.risk_summary
            )),
        );
        copy.insert(
            "harness_message".into(),
            json!(format!(
                "HOL Guard {phrase} this complete command after combining {count} findings. {}",
                query.risk_summary
            )),
        );
    }
    if let (Some(package), true) = (package, in_review) {
        if package
            .reason_codes
            .iter()
            .any(|code| code == "cloud_auth_error")
        {
            let command = "hol-guard connect";
            let instruction =
                format!("Run `{command}` to reconnect Guard Cloud, then retry the same install.");
            for field in ["user_body", "harness_message", "dashboard_primary_detail"] {
                let existing = copy
                    .get(field)
                    .or_else(|| base.get(field))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim()
                    .to_owned();
                if !existing.contains(command) {
                    copy.insert(
                        field.into(),
                        json!(format!("{existing} {instruction}").trim()),
                    );
                }
            }
            copy.insert("retry_instruction".into(), json!(instruction));
        }
    }
    let mut risk_headline = Value::Null;
    if let (Some(reason), true) = (&query.remembered_rule_reason, in_review) {
        copy.insert("harness_message".into(), json!(reason));
        copy.insert("dashboard_primary_detail".into(), json!(reason));
        copy.insert(
            "detail_reason_code".into(),
            json!("remembered_rule_ignored_degraded_trust"),
        );
        risk_headline = json!(reason);
    }
    json!({ "decision_overrides": copy, "risk_headline": risk_headline })
}

/// The state in which a remembered local rule is refused.
const REMEMBERED_RULES_DEGRADED: &str = "disabled_degraded";

/// Why a remembered local rule was ignored, or `null` when the reported state
/// does not refuse one. The integrity detail is appended as its own sentence.
pub(crate) fn remembered_rule_reason(query: &RememberedRuleReasonQueryV1) -> Value {
    if query.remembered_rules != REMEMBERED_RULES_DEGRADED {
        return json!({ "reason": Value::Null });
    }
    let detail = match query.integrity_message.as_deref().map(str::trim) {
        Some(message) if !message.is_empty() => {
            if message.ends_with('.') {
                format!(" {message}")
            } else {
                format!(" {message}.")
            }
        }
        _ => String::new(),
    };
    let reason = format!(
        "HOL Guard kept {} in review because a remembered local rule was ignored while local trust \
         is degraded.{detail} One-time approvals still work, but broader remembered rules stay \
         limited until local trust is protected.",
        query.artifact_summary
    );
    json!({ "reason": reason })
}
