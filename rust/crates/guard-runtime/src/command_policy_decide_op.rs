//! `CommandPolicyDecide` - decide one shell command against the command
//! expressions of a policy document and explain every rule considered.
//!
//! The precedence is the lattice's: `block` beats `review` beats `warn` beats
//! `allow`, and among the rules asking for the winning action the first in
//! document order decides while the rest tie with it. Python used to hold that
//! ladder and a second regex dialect beside it, which is how a command could
//! read as allowed in `policy test` and be blocked by enforcement.
//!
//! Pure: the caller ships the rules it compiled, and the op never opens the
//! store, the keyring or a policy file.

use guard_command::command_expression_match::matches_expression;
use guard_contracts::{
    CommandPolicyDecisionRequestV1, CommandPolicyDecisionResultV1, CommandPolicyRuleV1,
    COMMAND_POLICY_DECISION_MAX_BYTES, COMMAND_POLICY_DECISION_MAX_RULES,
    COMMAND_POLICY_DECISION_REQUEST_SCHEMA, COMMAND_POLICY_DECISION_RESULT_SCHEMA,
};
use serde_json::{json, Value};

use crate::package_authority_op::request_digest_with_limit;

#[cfg(test)]
#[path = "command_policy_decide_op_tests.rs"]
mod tests;

/// The action ladder, strongest last. A document rule can only carry one of
/// these four, and the strongest matching one decides the command.
const ACTIONS: [&str; 4] = ["allow", "warn", "review", "block"];

pub(crate) fn evaluate_command_policy_decision_request(
    request: &CommandPolicyDecisionRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest_with_limit(request, COMMAND_POLICY_DECISION_MAX_BYTES)
        .map_err(|_| "native_command_policy_decision_too_large".to_owned())?;
    let (status, code, payload) = match evaluate(request) {
        Ok(payload) => ("ok".to_owned(), "ok".to_owned(), Some(payload)),
        Err(code) => ("error".to_owned(), code, None),
    };
    crate::encode_response(&CommandPolicyDecisionResultV1 {
        schema: COMMAND_POLICY_DECISION_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status,
        code,
        payload,
    })
}

pub(crate) fn evaluate(request: &CommandPolicyDecisionRequestV1) -> Result<Value, String> {
    // A request that names another schema was built against another contract;
    // deciding it anyway would answer a question nobody asked.
    if request.schema != COMMAND_POLICY_DECISION_REQUEST_SCHEMA {
        return Err("native_command_policy_decision_schema_mismatch".to_owned());
    }
    if request.rules.len() > COMMAND_POLICY_DECISION_MAX_RULES {
        return Err("native_command_policy_decision_too_large".to_owned());
    }
    for rule in &request.rules {
        if rule.rule_id.is_empty() {
            return Err("native_command_policy_decision_rule_invalid".to_owned());
        }
        if !ACTIONS.contains(&rule.action.as_str()) {
            return Err("native_command_policy_decision_rule_action_unknown".to_owned());
        }
    }
    let matched = matches(&request.rules, &request.command)?;
    Ok(decide(&request.rules, &matched, &request.now))
}

/// `matches` - which rules this command satisfies, in document order. A rule
/// the dialect rejects refuses the whole decision rather than losing quietly.
fn matches(rules: &[CommandPolicyRuleV1], command: &str) -> Result<Vec<bool>, String> {
    rules
        .iter()
        .map(|rule| {
            matches_expression(&rule.expression, command)
                .map_err(|code| format!("native_command_policy_decision_{code}"))
        })
        .collect()
}

fn rank(action: &str) -> usize {
    ACTIONS
        .iter()
        .position(|candidate| *candidate == action)
        .unwrap_or_default()
}

/// `decide` - the winning action, the rule that carried it, and why each other
/// rule lost.
fn decide(rules: &[CommandPolicyRuleV1], matched: &[bool], now: &str) -> Value {
    let winning = rules
        .iter()
        .zip(matched)
        .filter(|(_, hit)| **hit)
        .map(|(rule, _)| rule.action.as_str())
        .max_by_key(|action| rank(action));
    let selected = winning.and_then(|action| {
        rules
            .iter()
            .zip(matched)
            .find(|(rule, hit)| **hit && rule.action == action)
            .map(|(rule, _)| rule.rule_id.clone())
    });
    let mut candidates = Vec::with_capacity(rules.len());
    let mut tied: Vec<String> = Vec::new();
    for (index, (rule, hit)) in rules.iter().zip(matched).enumerate() {
        let state = if !*hit {
            json!({"ruleId":rule.rule_id,"rowIndex":index,"state":"unmatched","reason":"command"})
        } else if Some(&rule.rule_id) == selected.as_ref() {
            json!({"ruleId":rule.rule_id,"rowIndex":index,"state":"selected","reason":Value::Null})
        } else if Some(rule.action.as_str()) != winning {
            json!({"ruleId":rule.rule_id,"rowIndex":index,"state":"outranked","reason":"block_wins"})
        } else {
            tied.push(rule.rule_id.clone());
            json!({"ruleId":rule.rule_id,"rowIndex":index,"state":"outranked","reason":"tie"})
        };
        candidates.push(state);
    }
    tied.sort();
    // Only `allow` and `block` are effects a document can enforce; `warn` and
    // `review` matched, but they leave the effect at the harness default and
    // report the action they asked for instead.
    let effect = winning
        .filter(|action| matches!(*action, "allow" | "block"))
        .unwrap_or("default");
    let mut decision = json!({
        "effect": effect,
        "ruleId": selected,
        "ambiguous": !tied.is_empty(),
        "matchLimitExceeded": false,
        "tiedRuleIds": tied,
        "candidates": candidates,
        "lookup": {"artifactId": Value::Null, "familyKey": Value::Null, "at": now},
    });
    if let Some(action) = winning {
        decision["action"] = json!(action);
    }
    decision
}
