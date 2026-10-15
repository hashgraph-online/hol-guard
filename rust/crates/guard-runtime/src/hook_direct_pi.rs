//! Oh My Pi hooks the resident answers as the daemon does.
//!
//! The daemon reviews a `pi` or `omp` hook as it reviews any other, with two
//! steps of its own. It lets the edge resolve a `guard_source_ref` outside
//! the workspace, a flag that both the request digest and the decision
//! receipt carry, so the lane sets it as the daemon does. After a
//! `PostToolUse` it resolves structured output mediation from the managed
//! policy. The publisher binds the managed-policy view the daemon resolves
//! it from, and the resident resolves that view with the same native query.
//! Only when nothing is required does the daemon return the edge response
//! unchanged, so only then does the resident answer; every hook it mediates
//! keeps the daemon path.

use super::POST_TOOL_USE;
use serde_json::{json, Value};
use std::time::{Duration, Instant};

/// The harnesses the daemon treats as Oh My Pi.
const PI_HARNESSES: [&str; 2] = ["pi", "omp"];
/// The keys of the managed-policy view `_config_wire` builds.
const CONFIG_VIEW_KEYS: [&str; 4] = [
    "managed_policy_status",
    "managed_policy_hash",
    "managed_locked_settings",
    "managed_policy",
];
/// What resolving one bounded managed-policy view may take.
const RESOLUTION_BUDGET: Duration = Duration::from_millis(100);
/// The spellings `canonical_harness_name` maps onto them.
const PI_ALIASES: [(&str, &str); 3] = [
    ("pi-agent", "pi"),
    ("pi-coding-agent", "pi"),
    ("oh-my-pi", "omp"),
];

/// `value.strip().lower().replace("_", "-")`. Python strips the separators
/// U+001C to U+001F as whitespace; Rust does not.
fn normalized(value: &str) -> String {
    value
        .trim_matches(|character: char| {
            character.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&character)
        })
        .to_lowercase()
        .replace('_', "-")
}

/// `default_harness.strip().lower().replace("_", "-") in {"pi", "omp"}`, the
/// `source_ref_external_allowed` that `_review_native_edge_with_snapshot`
/// passes the edge.
pub(super) fn source_ref_external_allowed(harness: &str) -> bool {
    PI_HARNESSES.contains(&normalized(harness).as_str())
}

/// Whether `_apply_structured_mediation` projects this hook: a `PostToolUse`
/// for a harness `canonical_harness_name` names `pi` or `omp`.
pub(super) fn structured_mediation(harness: &str, event: &str) -> bool {
    if event != POST_TOOL_USE {
        return false;
    }
    let name = normalized(harness);
    let canonical = PI_ALIASES
        .iter()
        .find(|(alias, _)| *alias == name.as_str())
        .map_or(name.as_str(), |&(_, canonical)| canonical);
    PI_HARNESSES.contains(&canonical)
}

/// Whether `_apply_structured_mediation` returns the edge response unchanged:
/// the `resolution` query `resolve_managed_structured_output_resolution`
/// sends finds nothing required for the bound managed-policy view. Without a
/// view of `_config_wire`'s shape, or when the query fails, the hook keeps
/// the daemon path, which then resolves and mediates itself.
pub(super) fn structured_output_unrequired(harness: &str, view: Option<&Value>) -> bool {
    let Some(config) = view else {
        return false;
    };
    let Value::Object(fields) = config else {
        return false;
    };
    if fields.len() != CONFIG_VIEW_KEYS.len()
        || CONFIG_VIEW_KEYS
            .iter()
            .any(|key| !fields.contains_key(*key))
    {
        return false;
    }
    let query = json!({"config": config, "harness": harness});
    let deadline = Instant::now() + RESOLUTION_BUDGET;
    guard_command::content_sensitivity::evaluate("resolution", &query, deadline)
        .is_ok_and(|result| result["ok"]["required"].as_bool() == Some(false))
}
