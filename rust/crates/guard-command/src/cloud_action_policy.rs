//! Workspace policy rules and effect floors for hosted cloud actions.
//!
//! Precedence follows the local enforcement lookup: a matching `block` beats
//! every other matching rule, then the most specific rule wins, and a tie goes
//! to the more restrictive action. With no matching rule the binding's effect
//! sets the floor. Admin effects are never dispatched in this contract.

use serde::Deserialize;

use crate::cloud_action_canonical::domain_digest;

use crate::cloud_action_binding::{valid_action_id, valid_label, ActionEffect};
use crate::effect_decision::GuardAction;

pub const MAX_POLICY_RULES: usize = 4096;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudPolicyRule {
    pub rule_id: String,
    pub action: GuardAction,
    #[serde(rename = "match")]
    pub matcher: CloudPolicyMatch,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudPolicyMatch {
    /// Exact action id, a `<prefix>.*` family, or `*`.
    pub action_id: String,
    #[serde(default)]
    pub connection_id: Option<String>,
    #[serde(default)]
    pub resource_id: Option<String>,
}

/// The facts a rule can match.
pub struct PolicySubject<'a> {
    pub action_id: &'a str,
    pub connection_id: &'a str,
    pub resource_id: Option<&'a str>,
}

pub struct PolicyOutcome {
    pub action: GuardAction,
    pub matched_rule_id: Option<String>,
    pub reason_code: &'static str,
}

const RULES_DOMAIN: &str = "guard.cloud-action-policy-rules.v1";

/// Digest of the rules exactly as evaluated, in request order, so a reused
/// snapshot label cannot hide a rule change.
pub fn rules_digest(rules: &[CloudPolicyRule]) -> String {
    fn optional(value: Option<&String>) -> Vec<u8> {
        value.map_or_else(|| b"-".to_vec(), |v| [b"+", v.as_bytes()].concat())
    }
    let fields: Vec<[Vec<u8>; 5]> = rules
        .iter()
        .map(|rule| {
            [
                rule.rule_id.as_bytes().to_vec(),
                rule.action.as_str().as_bytes().to_vec(),
                rule.matcher.action_id.as_bytes().to_vec(),
                optional(rule.matcher.connection_id.as_ref()),
                optional(rule.matcher.resource_id.as_ref()),
            ]
        })
        .collect();
    let parts: Vec<&[u8]> = fields.iter().flatten().map(Vec::as_slice).collect();
    domain_digest(RULES_DOMAIN, &parts)
}

pub fn validate_rules(rules: &[CloudPolicyRule]) -> Result<(), &'static str> {
    if rules.len() > MAX_POLICY_RULES {
        return Err("limit");
    }
    for rule in rules {
        let pattern = rule.matcher.action_id.as_str();
        let pattern_ok = pattern == "*"
            || valid_action_id(pattern)
            || pattern
                .strip_suffix(".*")
                .is_some_and(|prefix| valid_action_id(&format!("{prefix}.x")));
        let optional_ok = |value: &Option<String>| value.as_deref().is_none_or(valid_label);
        if !valid_label(&rule.rule_id)
            || !pattern_ok
            || !optional_ok(&rule.matcher.connection_id)
            || !optional_ok(&rule.matcher.resource_id)
        {
            return Err("invalid_request");
        }
    }
    Ok(())
}

/// Specificity of a matching rule, or `None` when it does not match.
fn specificity(rule: &CloudPolicyMatch, subject: &PolicySubject<'_>) -> Option<usize> {
    let pattern = rule.action_id.as_str();
    let action_score = if pattern == subject.action_id {
        1000
    } else if pattern == "*" {
        0
    } else {
        let prefix = pattern.strip_suffix(".*")?;
        let rest = subject.action_id.strip_prefix(prefix)?;
        if !rest.starts_with('.') {
            return None;
        }
        prefix.len()
    };
    let mut score = action_score * 4;
    if let Some(connection) = &rule.connection_id {
        if connection != subject.connection_id {
            return None;
        }
        score += 2;
    }
    if let Some(resource) = &rule.resource_id {
        if Some(resource.as_str()) != subject.resource_id {
            return None;
        }
        score += 1;
    }
    Some(score)
}

/// The binding's floor when no workspace rule matches.
pub const fn effect_floor(effect: ActionEffect) -> GuardAction {
    match effect {
        ActionEffect::Read => GuardAction::Allow,
        ActionEffect::Write => GuardAction::Review,
        ActionEffect::Destructive => GuardAction::RequireReapproval,
        ActionEffect::Admin => GuardAction::Block,
    }
}

pub fn decide_policy(
    rules: &[CloudPolicyRule],
    subject: &PolicySubject<'_>,
    effect: ActionEffect,
) -> PolicyOutcome {
    if effect == ActionEffect::Admin {
        return PolicyOutcome {
            action: GuardAction::Block,
            matched_rule_id: None,
            reason_code: "admin_effect_unsupported",
        };
    }
    let matches: Vec<(usize, &CloudPolicyRule)> = rules
        .iter()
        .filter_map(|rule| specificity(&rule.matcher, subject).map(|score| (score, rule)))
        .collect();
    if let Some((_, rule)) = matches
        .iter()
        .find(|(_, rule)| rule.action == GuardAction::Block)
    {
        return PolicyOutcome {
            action: GuardAction::Block,
            matched_rule_id: Some(rule.rule_id.clone()),
            reason_code: "policy_rule",
        };
    }
    let selected = matches
        .iter()
        .max_by_key(|(score, rule)| (*score, rule.action.severity()));
    match selected {
        Some((_, rule)) => PolicyOutcome {
            action: rule.action,
            matched_rule_id: Some(rule.rule_id.clone()),
            reason_code: "policy_rule",
        },
        None => PolicyOutcome {
            action: effect_floor(effect),
            matched_rule_id: None,
            reason_code: "effect_floor",
        },
    }
}
