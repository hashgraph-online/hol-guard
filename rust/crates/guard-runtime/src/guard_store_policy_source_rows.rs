//! Row helpers for policy decision source context: SQL cell text, artifact
//! family matching and the remembered command of a resolved approval.

use serde_json::Value;

use crate::guard_store_db::Row;
use crate::guard_store_policy_source_labels::{
    artifact_family_key, backtick_phrases, is_human_policy_label, sanitize_remembered_command,
    truthy,
};

/// `str(row[name])`, or `None` for SQL null.
pub(crate) fn cell(row: &Row, name: &str) -> Option<String> {
    match row.get(name) {
        None | Some(Value::Null) => None,
        Some(Value::String(value)) => Some(value.clone()),
        Some(other) => Some(other.to_string()),
    }
}

/// A decision without an artifact id matches any candidate; otherwise the ids
/// match exactly or share an artifact family.
pub(crate) fn artifact_matches_candidate(
    policy_id: Option<&str>,
    candidate_id: Option<&str>,
) -> bool {
    if !truthy(policy_id) || candidate_id == policy_id {
        return true;
    }
    let policy_family = artifact_family_key(policy_id);
    policy_family.is_some() && policy_family == artifact_family_key(candidate_id)
}

/// The remembered command for a resolved approval: the first human backtick
/// phrase of its trigger or launch target, then the target, then its name.
pub(crate) fn approval_command(row: &Row) -> Option<String> {
    let human = |phrase: &str| {
        Some(sanitize_remembered_command(phrase)).filter(|value| is_human_policy_label(Some(value)))
    };
    if let Some(trigger) = cell(row, "trigger_summary") {
        if let Some(command) = backtick_phrases(&trigger).into_iter().find_map(human) {
            return Some(command);
        }
    }
    if let Some(target) = cell(row, "launch_target") {
        if let Some(command) = backtick_phrases(&target).into_iter().find_map(human) {
            return Some(command);
        }
        if is_human_policy_label(Some(&target)) {
            return Some(sanitize_remembered_command(&target));
        }
    }
    cell(row, "artifact_name")
        .filter(|name| is_human_policy_label(Some(name)))
        .map(|name| sanitize_remembered_command(&name))
}
