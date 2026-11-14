//! Guard Cloud rules that name a command risk group ("ask before any
//! permanent delete"). Such a rule is saved under `risk-group:<group>` and
//! applies to every command whose steps fall in that group
//! ([`crate::command_risk_groups`]), the same groups Guard Cloud shows on the
//! request. It only asks or blocks; it never allows a command.

use std::collections::HashMap;

use super::LiveRule;

pub(super) const GROUP_REVIEW: &str = "policy_risk_group_review";
pub(super) const GROUP_BLOCK: &str = "policy_risk_group_block";
/// The id prefix a command risk-group rule is saved under.
const GROUP_PREFIX: &str = "risk-group:";

/// The rule that named a command: its source and, for a risk-group rule, the
/// group the command falls in.
pub(super) struct Hit {
    pub(super) source: String,
    pub(super) group: Option<&'static str>,
}

/// The first live risk-group block and review rule that name one of `texts`.
#[derive(Default)]
pub(super) struct GroupRules {
    pub(super) block: Option<Hit>,
    pub(super) review: Option<Hit>,
}

/// Look each spelling of the command up by the groups its steps fall in. A
/// block ends the search; otherwise the first review is kept.
pub(super) fn matching(live: &HashMap<String, LiveRule>, texts: &[String]) -> GroupRules {
    let mut rules = GroupRules::default();
    for text in texts {
        for group in crate::command_risk_groups::command_risk_groups(text) {
            match live.get(format!("{GROUP_PREFIX}{group}").as_str()) {
                Some(LiveRule {
                    block: true,
                    source,
                }) => {
                    rules.block = Some(Hit {
                        source: source.clone(),
                        group: Some(group),
                    });
                    return rules;
                }
                Some(LiveRule { source, .. }) if rules.review.is_none() => {
                    rules.review = Some(Hit {
                        source: source.clone(),
                        group: Some(group),
                    });
                }
                _ => {}
            }
        }
    }
    rules
}

/// Why a risk-group rule holds a command, in the group's own words.
pub(super) fn review_reason(group: &str) -> &'static str {
    match group {
        "deletes" => "Your Guard policy asks a person before commands that delete files or data.",
        "bulk_changes" => "Your Guard policy asks a person before commands that change many things at once.",
        "sending_and_sharing" => "Your Guard policy asks a person before commands that send or share data.",
        "secrets" => "Your Guard policy asks a person before commands that read or move secrets.",
        "code_and_deploys" => "Your Guard policy asks a person before commands that push code or deploy.",
        "packages_and_scripts" => "Your Guard policy asks a person before commands that install packages or run downloaded scripts.",
        _ => "Your Guard policy asks a person before commands like this one.",
    }
}

/// Why a risk-group rule stops a command, in the group's own words.
pub(super) fn block_reason(group: &str) -> &'static str {
    match group {
        "deletes" => "Your Guard policy blocks commands that delete files or data.",
        "bulk_changes" => "Your Guard policy blocks commands that change many things at once.",
        "sending_and_sharing" => "Your Guard policy blocks commands that send or share data.",
        "secrets" => "Your Guard policy blocks commands that read or move secrets.",
        "code_and_deploys" => "Your Guard policy blocks commands that push code or deploy.",
        "packages_and_scripts" => {
            "Your Guard policy blocks commands that install packages or run downloaded scripts."
        }
        _ => "Your Guard policy blocks commands like this one.",
    }
}

#[cfg(test)]
#[path = "edge_risk_group_rule_tests.rs"]
mod tests;
