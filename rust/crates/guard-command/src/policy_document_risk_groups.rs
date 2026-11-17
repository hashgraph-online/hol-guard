//! Guard Cloud rules that name a command risk group compile to
//! `risk-group:<group>` decisions the hook applies to every command in that
//! group.

use serde_json::{json, Value};

use super::compiler;
use super::Error;

/// Command risk groups a Guard Cloud rule may name. They match the groups the
/// hook reads from a command (`guard_runtime::command_risk_groups`); "other"
/// names no group, so a rule on it would ask about nothing.
pub(super) const RISK_GROUPS: &[&str] = &[
    "deletes",
    "bulk_changes",
    "sending_and_sharing",
    "secrets",
    "code_and_deploys",
    "packages_and_scripts",
];

/// `riskGroups` selectors as `risk-group:<group>` artifact ids. A group rule
/// only asks or blocks: a command named by its group is never allowed by it,
/// so an Allow is refused, and it cannot be narrowed by artifact, command,
/// tool or publisher selectors the hook would not apply.
pub(super) fn selectors(
    matcher: &Value,
    effect: &Value,
    id: &str,
) -> Result<Option<Vec<Value>>, Error> {
    if !compiler::has_selector(matcher, "riskGroups") {
        return Ok(None);
    }
    if ["artifacts", "commands", "tools", "publishers"]
        .iter()
        .any(|key| compiler::has_selector(matcher, key))
    {
        return Err(compiler::error("unsupported_policy_match", id));
    }
    if !matches!(effect.as_str(), Some("review" | "block")) {
        return Err(compiler::error("unsupported_risk_group_effect", id));
    }
    compiler::selectors(matcher, "riskGroups", id)?
        .iter()
        .map(|group| {
            let group = group.as_str().unwrap_or("");
            if !RISK_GROUPS.contains(&group) {
                return Err(compiler::error("unsupported_risk_group", id));
            }
            Ok(json!(format!("risk-group:{group}")))
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Some)
}
