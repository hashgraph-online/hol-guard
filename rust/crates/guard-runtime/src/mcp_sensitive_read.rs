//! Sensitive-file-read decisions of the stdio MCP proxy.
//!
//! The proxy used to compose these in Python: the current action from the
//! configuration, the exact-context approval token, how a saved approval
//! composes with the recomputed action (including the claim and the rebuilt
//! post-claim context) and the response for a read that is not forwarded. The
//! caller now gathers facts and performs the store effects between queries;
//! every verdict, token and message is computed here.

use guard_command::approval_reuse::{
    evaluate_approval_reuse, ApprovalReuseDecision, APPROVAL_REUSE_CLAIM_FAILED,
    APPROVAL_REUSE_NO_SAVED_DECISION,
};
use guard_contracts::{
    most_restrictive_guard_action, ContextDigestComponentsV1, GuardAction,
    McpSensitiveReadConfigV1, McpSensitiveReadContextQueryV1, McpSensitiveReadHintQueryV1,
    McpSensitiveReadLookupV1, McpSensitiveReadReuseQueryV1, McpSensitiveReadStageV1,
};
use serde_json::{json, Map, Value};

use crate::context_digest::{build_context_token, validate_context_tokens};
use crate::mcp_proxy_actions::{
    config_refresh_failed_item, CONFIG_REFRESH_FAILED, REQUIRE_REAPPROVAL,
};

/// Bump when sensitive-read classification or action-composition semantics change.
const EVALUATOR_POLICY_VERSION: &str = "stdio-sensitive-read-evaluation-v1";
const INTEGRITY_FAILURE: &str = "approval_reuse_integrity_failure";

fn string(text: &str) -> Value {
    Value::String(text.to_owned())
}

fn current_action(config: &McpSensitiveReadConfigV1) -> GuardAction {
    let risk = config
        .risk_action
        .as_deref()
        .filter(|text| !text.is_empty())
        .unwrap_or(REQUIRE_REAPPROVAL);
    let configured = config
        .view_override
        .as_deref()
        .unwrap_or(&config.view_default_action);
    most_restrictive_guard_action(&[string(risk), string(configured)], GuardAction::Review)
}

fn policy_context(config: &McpSensitiveReadConfigV1, effective: GuardAction) -> Value {
    let mut policy = Map::new();
    policy.insert(
        "artifact_override".to_owned(),
        config.artifact_override.clone(),
    );
    policy.insert("default_action".to_owned(), config.default_action.clone());
    policy.insert("effective_action".to_owned(), string(effective.as_str()));
    policy.insert(
        "evaluator_policy_version".to_owned(),
        string(EVALUATOR_POLICY_VERSION),
    );
    policy.insert(
        "managed_locked_settings".to_owned(),
        json!(config.managed_locked_settings),
    );
    policy.insert(
        "managed_policy_hash".to_owned(),
        config.managed_policy_hash.clone(),
    );
    policy.insert(
        "managed_policy_status".to_owned(),
        config.managed_policy_status.clone(),
    );
    policy.insert("mode".to_owned(), config.mode.clone());
    if config.protection_posture_explicit {
        policy.insert(
            "protection_posture".to_owned(),
            config.protection_posture.clone(),
        );
        policy.insert("protection_posture_explicit".to_owned(), Value::Bool(true));
    }
    policy.insert("security_level".to_owned(), config.security_level.clone());
    if let Some(posture) = &config.harness_posture {
        policy.insert("harness_posture".to_owned(), string(posture));
    }
    Value::Object(policy)
}

/// The current action and the exact-context approval token of one read.
pub(crate) fn context(query: &McpSensitiveReadContextQueryV1) -> Value {
    let (effective, policy, sandbox) = match &query.config {
        Some(config) => {
            let effective = current_action(config);
            (
                effective,
                policy_context(config, effective),
                json!({ "analysis": config.sandbox_analysis }),
            )
        }
        None => {
            let effective = GuardAction::RequireReapproval;
            (
                effective,
                json!({
                    "config_valid": false,
                    "effective_action": effective.as_str(),
                    "evaluator_policy_version": EVALUATOR_POLICY_VERSION,
                }),
                json!({ "analysis": "unknown" }),
            )
        }
    };
    let token = build_context_token(&ContextDigestComponentsV1 {
        identity: query.identity.clone(),
        content: string(&query.content),
        capabilities: query.capabilities.clone(),
        policy,
        sandbox,
        extension_control_digest: query.extension_control_digest.clone(),
    });
    match token {
        Ok(artifact_hash) => json!({
            "current_action": effective.as_str(),
            "artifact_hash": artifact_hash,
        }),
        Err(_) => Value::Null,
    }
}

fn saved_action(lookup: &McpSensitiveReadLookupV1) -> Value {
    if lookup.decision_present {
        lookup.decision_action.clone()
    } else if lookup.ignored_integrity {
        string(REQUIRE_REAPPROVAL)
    } else if lookup.diagnosed_reason.is_some() {
        string("allow")
    } else {
        Value::Null
    }
}

/// Stored allows are valid only for the exact context they were saved for.
fn initial_validation(lookup: &McpSensitiveReadLookupV1, artifact_hash: &str) -> Option<String> {
    if lookup.ignored_integrity {
        return Some(INTEGRITY_FAILURE.to_owned());
    }
    if lookup.decision_present {
        if lookup.decision_action != "allow" {
            return None;
        }
        return validate_context_tokens(&lookup.decision_artifact_hash, &string(artifact_hash));
    }
    lookup.diagnosed_reason.clone()
}

fn evaluate(
    current: &str,
    saved: &Value,
    present: bool,
    validation: Option<&str>,
) -> ApprovalReuseDecision {
    evaluate_approval_reuse(
        &string(current),
        Some(saved),
        Some(present),
        validation,
        false,
        false,
    )
}

fn postclaim(
    query: &McpSensitiveReadReuseQueryV1,
    lookup: &McpSensitiveReadLookupV1,
) -> ApprovalReuseDecision {
    let claimed = query
        .claimed_allow_hash
        .as_deref()
        .map(string)
        .unwrap_or(Value::Null);
    let (saved, validation) = if lookup.ignored_integrity {
        let saved = if lookup.decision_present {
            lookup.decision_action.clone()
        } else {
            string(REQUIRE_REAPPROVAL)
        };
        (saved, Some(INTEGRITY_FAILURE.to_owned()))
    } else if lookup.decision_present && lookup.decision_action != "allow" {
        (lookup.decision_action.clone(), None)
    } else {
        (
            string("allow"),
            validate_context_tokens(&claimed, &string(&query.artifact_hash)),
        )
    };
    evaluate(&query.current_action, &saved, true, validation.as_deref())
}

fn non_forward(query: &McpSensitiveReadReuseQueryV1, policy_action: &str) -> Value {
    let tool = &query.tool_name;
    let class = &query.path_class;
    let message = |action: &str| -> Option<String> {
        Some(match action {
            "review" => format!(
                "Guard paused sensitive local file access for {tool} pending review: {class}."
            ),
            "require-reapproval" => format!(
                "Guard paused sensitive local file access for {tool} until fresh approval is granted: {class}."
            ),
            "sandbox-required" => format!(
                "Guard requires an enforceable sandbox before sensitive local file access for {tool}: {class}."
            ),
            "block" => format!("Guard blocked sensitive local file access for {tool}: {class}."),
            _ => return None,
        })
    };
    let Some(own) = message(policy_action) else {
        return Value::Null;
    };
    let terminal = matches!(policy_action, "block" | "sandbox-required");
    let (text, response_action, wrap) = if query.asks_for_approval {
        (own, policy_action, false)
    } else {
        (message("block").unwrap_or_default(), "block", true)
    };
    json!({
        "message": text,
        "response_action": response_action,
        "wrap_safe_alternative": wrap,
        "record_unprompted_review": query.store_present
            && !terminal
            && !query.asks_for_approval
            && matches!(policy_action, "review" | "require-reapproval"),
        "queue_approvals": query.store_present
            && query.approval_center_present
            && !terminal
            && query.asks_for_approval,
    })
}

/// The saved-approval composition of one stage, with everything the caller
/// records or renders once the stage is final.
pub(crate) fn reuse(query: &McpSensitiveReadReuseQueryV1) -> Value {
    let refresh_failed = query.stage == McpSensitiveReadStageV1::RefreshFailed;
    let decision = match (query.stage, query.lookup.as_ref()) {
        (McpSensitiveReadStageV1::RefreshFailed, _) => {
            evaluate(REQUIRE_REAPPROVAL, &string("allow"), true, None)
        }
        (McpSensitiveReadStageV1::Postclaim, Some(lookup)) => postclaim(query, lookup),
        (McpSensitiveReadStageV1::Initial, lookup) => match lookup {
            Some(lookup) => evaluate(
                &query.current_action,
                &saved_action(lookup),
                lookup.decision_present
                    || lookup.ignored_integrity
                    || lookup.diagnosed_reason.is_some(),
                initial_validation(lookup, &query.artifact_hash).as_deref(),
            ),
            None => evaluate(&query.current_action, &Value::Null, false, None),
        },
        (McpSensitiveReadStageV1::ClaimFailed, Some(lookup)) => evaluate(
            &query.current_action,
            &saved_action(lookup),
            true,
            Some(APPROVAL_REUSE_CLAIM_FAILED),
        ),
        _ => return Value::Null,
    };
    let policy_action = if decision.action.as_str() == "review"
        && decision.reason_code != APPROVAL_REUSE_NO_SAVED_DECISION
    {
        REQUIRE_REAPPROVAL
    } else {
        decision.action.as_str()
    };
    let mut evidence = Vec::new();
    let reuse_value = serde_json::to_value(&decision).unwrap_or(Value::Null);
    if decision.reason_code != APPROVAL_REUSE_NO_SAVED_DECISION {
        let mut item = reuse_value.as_object().cloned().unwrap_or_default();
        item.insert("source".to_owned(), string("approval_reuse"));
        evidence.push(Value::Object(item));
    }
    if refresh_failed {
        evidence.push(config_refresh_failed_item());
    }
    let claim_candidate = query.stage == McpSensitiveReadStageV1::Initial
        && decision.should_claim
        && query
            .lookup
            .as_ref()
            .is_some_and(|lookup| lookup.decision_present);
    let saved_block = decision.action.as_str() == "block"
        && decision.saved_action.map(|action| action.as_str()) == Some("block");
    json!({
        "reuse": reuse_value,
        "claim_candidate": claim_candidate,
        "policy_action": policy_action,
        "reuse_evidence": evidence,
        "terminal_saved_block": saved_block,
        "terminal_policy_action": matches!(policy_action, "block" | "sandbox-required"),
        "event_status": decision.status,
        "event_reason_code": if refresh_failed { CONFIG_REFRESH_FAILED } else { decision.reason_code.as_str() },
        "approval_source": if policy_action == REQUIRE_REAPPROVAL
            && query.approval_center_present
            && query.asks_for_approval { "approval_center" } else { "policy" },
        "non_forward": non_forward(query, policy_action),
    })
}

/// The review hint appended to a not-forwarded response once approvals are queued.
pub(crate) fn hint(query: &McpSensitiveReadHintQueryV1) -> Value {
    let instruction = match query.policy_action.as_str() {
        "review" => "review the waiting request",
        "require-reapproval" => "grant or deny fresh approval",
        _ => return Value::Null,
    };
    let review_hint = format!(
        "{} Open {} to {instruction}.",
        query.approval_summary, query.review_url
    );
    json!({
        "review_hint": review_hint,
        "message": format!("{} {review_hint}", query.message),
    })
}
