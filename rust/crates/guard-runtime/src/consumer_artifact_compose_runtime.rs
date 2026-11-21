//! Saved/claimed approval reuse, trusted-request override, and runtime
//! detector authority for `ConsumerArtifactCompose`. Pure: Python performs the
//! store lookup before the query and records any pending claim after it.

use guard_command::approval_reuse::{
    evaluate_approval_reuse, ApprovalReuseDecision, APPROVAL_REUSE_ACCEPTED,
    APPROVAL_REUSE_NO_SAVED_DECISION,
};
use guard_contracts::{
    most_restrictive_of as stricter, ConsumerRuntimeDecisionQueryV1, ConsumerSavedDecisionV1,
    GuardAction,
};
use serde_json::{json, Map, Value};

const INTEGRITY_FAILURE: &str = "approval_reuse_integrity_failure";
const TRUSTED_REQUEST_OVERRIDE_REASON: &str = "trusted_request_override_exact_context";
const RUNTIME_DETECTOR_BLOCK_REASON: &str = "runtime_detector_block";
const RUNTIME_DETECTOR_REVIEW_REASON: &str = "runtime_detector_review";
const RUNTIME_DETECTOR_WARN_REASON: &str = "runtime_detector_warn";
const SKILL_DIRECTORY_IDENTITY_REASON: &str = "skill_directory_identity_non_reusable";
const RUNTIME_DETECTOR_ACTIONS: [GuardAction; 4] = [
    GuardAction::Allow,
    GuardAction::Warn,
    GuardAction::Review,
    GuardAction::Block,
];

pub(crate) fn runtime_decision(query: &ConsumerRuntimeDecisionQueryV1) -> Value {
    let current = &query.current_action;
    let context_hash = Value::String(query.approval_context_hash.clone());
    let reusable = query.skill_directory_identity_reusable != Some(false);
    let (mut reuse, mut has_saved_state) = saved_policy(query, &context_hash, reusable);
    let append_pending_claim = reuse.should_claim && query.saved_decision.is_some();

    let consumed = query.claimed_saved_approval_hash == context_hash;
    let retained = query.retained_saved_approval_hash == context_hash;
    let qualification = &query.saved_approval_qualification;
    let fresh = qualification.get("fresh_local_approval") == Some(&Value::Bool(true));
    let durable = qualification.get("durable_exact_approval") == Some(&Value::Bool(true));
    let claimed_reuse = || {
        evaluate_approval_reuse(
            current,
            Some(&json!("allow")),
            Some(true),
            None,
            fresh,
            durable,
        )
    };
    // A consumed claim with no surviving row is recomposed against the
    // current floor; a retained row must still resolve to an accepted exact
    // saved allow, so a stale proof cannot bypass a changed or blocking row.
    let claimed = reusable
        && (consumed || retained)
        && if consumed && !has_saved_state {
            let decision = claimed_reuse();
            decision.accepted() && decision.should_claim
        } else {
            reuse.accepted()
                && reuse.saved_action.map(|action| action.as_str()) == Some("allow")
                && reuse.reason_code == APPROVAL_REUSE_ACCEPTED
                && reuse.should_claim
        };
    let approval_claim = claimed.then(|| {
        json!({
            "status": if consumed { "consumed" } else { "retained" },
            "approval_context_hash": query.approval_context_hash,
            "reason_code": APPROVAL_REUSE_ACCEPTED,
        })
    });
    if claimed {
        reuse = claimed_reuse();
        has_saved_state = true;
    }
    let reuse_action = guard(reuse.action.as_str());
    // A fresh trusted request satisfies only a review prompt for the exact
    // re-evaluated context; it never lowers block, sandbox, or integrity.
    let trusted = query.trusted_request_override_hash == context_hash
        && matches!(
            reuse_action,
            GuardAction::Review | GuardAction::RequireReapproval
        )
        && reuse.reason_code != INTEGRITY_FAILURE;

    let (detector_action, detector_reason) =
        detector_authority(&query.runtime_detector_composition);
    let block_reason = query
        .runtime_detector_block_reason
        .as_deref()
        .filter(|reason| !reason.is_empty());
    let saved_allow = reuse.saved_action.map(|action| action.as_str()) == Some("allow");
    let review_approved =
        trusted || (reuse.accepted() && reuse.current_action.as_str() == "review" && saved_allow);
    let mut policy = if trusted {
        GuardAction::Allow
    } else {
        reuse_action
    };
    if detector_action == Some(GuardAction::Warn) {
        policy = stricter(policy, GuardAction::Warn);
    }
    if detector_action == Some(GuardAction::Review) && !review_approved {
        policy = stricter(policy, GuardAction::Review);
    }
    if detector_action == Some(GuardAction::Block) || block_reason.is_some() {
        policy = GuardAction::Block;
    }
    let authority_finalized = !reuse.should_claim || claimed || trusted;
    let evidence = full_evidence(&reuse);

    let mut scanner_evidence: Vec<Value> = Vec::new();
    if query.skill_directory_identity_reusable == Some(false) {
        scanner_evidence.push(json!({
            "source": "skill_directory_identity",
            "status": "incomplete",
            "reason_code": SKILL_DIRECTORY_IDENTITY_REASON,
            "reusable": false,
            "action_floor": "require-reapproval",
        }));
    }
    if has_saved_state || reuse.reason_code != APPROVAL_REUSE_NO_SAVED_DECISION {
        let mut item = Map::new();
        item.insert("source".into(), json!("approval_reuse"));
        item.extend(
            evidence
                .as_object()
                .into_iter()
                .flatten()
                .map(|(k, v)| (k.clone(), v.clone())),
        );
        scanner_evidence.push(Value::Object(item));
    }
    scanner_evidence.extend(query.runtime_signals.iter().map(|signal| {
        json!({
            "source": "runtime_detector_registry",
            "kind": "risk_signal_v2",
            "signal": signal,
        })
    }));
    if trusted {
        scanner_evidence.push(json!({
            "source": "trusted_request_override",
            "status": "accepted",
            "reason_code": TRUSTED_REQUEST_OVERRIDE_REASON,
            "artifact_hash": query.approval_context_hash,
        }));
    }
    if let Some(reason) = block_reason {
        scanner_evidence.push(json!({
            "source": "runtime_detector_registry",
            "status": "blocked",
            "reason_code": RUNTIME_DETECTOR_BLOCK_REASON,
            "reason": reason,
        }));
    }

    let decision_reason = if block_reason.is_some() {
        RUNTIME_DETECTOR_BLOCK_REASON.to_owned()
    } else if detector_action == Some(GuardAction::Warn) && policy == GuardAction::Warn {
        RUNTIME_DETECTOR_WARN_REASON.to_owned()
    } else if detector_action == Some(GuardAction::Review) && policy == GuardAction::Review {
        RUNTIME_DETECTOR_REVIEW_REASON.to_owned()
    } else if trusted {
        TRUSTED_REQUEST_OVERRIDE_REASON.to_owned()
    } else if has_saved_state {
        reuse.reason_code.clone()
    } else {
        policy.as_str().to_owned()
    };
    let approval_source = if block_reason.is_some() {
        "runtime-detector"
    } else if trusted {
        "fresh-approval"
    } else if reuse.accepted() && saved_allow {
        "saved-approval"
    } else if reuse.saved_action.map(|action| action.as_str()) == Some("block") {
        "saved-policy"
    } else {
        "policy"
    };

    let mut composition = Map::new();
    composition.insert("configured_action".into(), query.configured_action.clone());
    composition.insert("current_action".into(), current.clone());
    composition.insert("saved_action".into(), evidence["saved_action"].clone());
    composition.insert("saved_state_present".into(), json!(has_saved_state));
    composition.insert("scanner_action".into(), query.scanner_action.clone());
    composition.insert(
        "raw_scoring_recommendation".into(),
        query.raw_scoring_recommendation.clone(),
    );
    composition.insert(
        "scoring_recommendation_non_authoritative".into(),
        json!(true),
    );
    composition.insert("trusted_request_override".into(), json!(trusted));
    if query.skill_directory_identity_reusable == Some(false) {
        composition.insert("skill_directory_identity_reusable".into(), json!(false));
        composition.insert(
            "skill_directory_identity_floor".into(),
            json!("require-reapproval"),
        );
    }
    if let Some(claim) = &approval_claim {
        composition.insert("saved_approval_claim".into(), claim.clone());
    }
    if block_reason.is_some() || detector_action.is_some() {
        let action = if block_reason.is_some() {
            Some(GuardAction::Block)
        } else {
            detector_action
        };
        composition.insert(
            "runtime_detector_action".into(),
            json!(action.map(GuardAction::as_str)),
        );
        composition.insert(
            "runtime_detector_reason".into(),
            json!(block_reason.or(detector_reason.as_deref())),
        );
    }
    composition.insert("final_action".into(), json!(policy.as_str()));

    json!({
        "approval_reuse": evidence,
        "saved_state_present": has_saved_state,
        "append_pending_claim": append_pending_claim,
        "approval_claim": approval_claim,
        "trusted_request_override": trusted,
        "policy_action": policy.as_str(),
        "authority_finalized": authority_finalized,
        "scanner_evidence": scanner_evidence,
        "decision_reason": decision_reason,
        "approval_source": approval_source,
        "policy_composition": composition,
    })
}

/// Compose the current action with the resolved saved decision, if any.
fn saved_policy(
    query: &ConsumerRuntimeDecisionQueryV1,
    context_hash: &Value,
    reusable: bool,
) -> (ApprovalReuseDecision, bool) {
    let current = &query.current_action;
    let saved = query.saved_decision.as_ref();
    let integrity_failure = query.ignored_local_integrity;
    let (saved_action, validation_reason) =
        match (saved, integrity_failure, &query.diagnosed_reason) {
            (Some(decision), true, _) => {
                (decision.action.clone(), Some(INTEGRITY_FAILURE.to_owned()))
            }
            (Some(decision), false, _) => (
                decision.action.clone(),
                saved_allow_validation_reason(decision, context_hash),
            ),
            (None, true, _) => (
                json!("require-reapproval"),
                Some(INTEGRITY_FAILURE.to_owned()),
            ),
            (None, false, Some(reason)) => (json!("allow"), Some(reason.clone())),
            (None, false, None) => {
                // No saved evidence: the current action stands unchanged.
                return (
                    evaluate_approval_reuse(current, None, None, None, false, false),
                    false,
                );
            }
        };
    let flag = |pick: fn(&ConsumerSavedDecisionV1) -> &Value| {
        reusable && saved.is_some_and(|decision| pick(decision) == &Value::Bool(true))
    };
    let decision = evaluate_approval_reuse(
        current,
        Some(&saved_action),
        Some(true),
        validation_reason.as_deref(),
        flag(|decision| &decision.fresh_local_approval),
        flag(|decision| &decision.durable_exact_approval),
    );
    (decision, true)
}

/// Saved allows must still match the exact current context token; harness-
/// or global-scope allows without an artifact hash are scope-wide policy.
fn saved_allow_validation_reason(
    decision: &ConsumerSavedDecisionV1,
    context_hash: &Value,
) -> Option<String> {
    if decision.action.as_str() != Some("allow") {
        return None;
    }
    let scope_wide = matches!(decision.scope.as_str(), Some("harness" | "global"));
    if decision.artifact_hash.is_null() && scope_wide {
        return None;
    }
    crate::context_digest::validate_context_tokens(&decision.artifact_hash, context_hash)
}

/// Runtime-detector composition authority: only a known action counts, and
/// only a non-blank reason is carried into the composition trace.
fn detector_authority(composition: &Value) -> (Option<GuardAction>, Option<String>) {
    let Some(composition) = composition.as_object() else {
        return (None, None);
    };
    let action = composition
        .get("action")
        .and_then(Value::as_str)
        .and_then(GuardAction::from_canonical)
        .filter(|action| RUNTIME_DETECTOR_ACTIONS.contains(action));
    let Some(action) = action else {
        return (None, None);
    };
    let reason = composition
        .get("reason")
        .and_then(Value::as_str)
        .filter(|reason| !reason.trim_matches(python_space).is_empty())
        .map(str::to_owned);
    (Some(action), reason)
}

/// CPython `str.isspace`: Unicode whitespace plus the ASCII separators.
fn python_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

fn guard(action: &str) -> GuardAction {
    GuardAction::from_canonical(action).unwrap_or(GuardAction::Block)
}

/// Every `ApprovalReuseDecision.to_evidence()` key, absent values as `null`.
fn full_evidence(decision: &ApprovalReuseDecision) -> Value {
    let mut evidence = json!({
        "action": decision.action.as_str(),
        "status": decision.status,
        "reason_code": decision.reason_code,
        "current_action": decision.current_action.as_str(),
        "saved_action": decision.saved_action.map(|action| action.as_str()),
        "should_claim": decision.should_claim,
        "current_normalization_reason_code": decision.current_normalization_reason_code,
        "saved_normalization_reason_code": decision.saved_normalization_reason_code,
        "original_current_action": decision.original_current_action,
        "original_saved_action": decision.original_saved_action,
        "original_current_type": decision.original_current_type,
        "original_saved_type": decision.original_saved_type,
    });
    if let Some(is_token) = decision.saved_artifact_hash_is_context_token {
        evidence["saved_artifact_hash_is_context_token"] = json!(is_token);
    }
    evidence
}
