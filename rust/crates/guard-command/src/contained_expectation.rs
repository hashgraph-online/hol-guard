//! `contained_expectation` operation: the containment reason and execution
//! profile a contained run's receipt must carry once its planner has run.
//! Ported from the expectation table in `run_authorized_contained_test`.
//!
//! `{"kind", "plan_profile", "command"}` answers `{"reason", "profile"}`.
//! `kind` names the planner `contained_kind` chose: `inline_eval`,
//! `node_tool`, `git`, `vitest`, `node_test` or `pytest`. `plan_profile` is
//! the profile the inline-evaluation or Node tool planner settled on, and is
//! `null` for the others. `command` is the planned argv; only its program name
//! is read, to tell Bun evaluation from Node evaluation. Any other key is
//! refused, except the `search_path` the transport adds to every request.
//!
//! The profile comes from the hook's own reason table, so the receipt the sink
//! waits for is the one the hook renders for the same reason. A kind and plan
//! profile that do not belong together answer an error, and the sink refuses
//! the run rather than guessing a reason.

use serde_json::{json, Value};

use crate::contained_argv::program_name;
use crate::restricted_command::RestrictedPytestError;

/// `search_path` rides on every restricted request the Python transport sends;
/// this operation never reads it.
const FIELDS: [&str; 4] = ["kind", "plan_profile", "command", "search_path"];
const INVALID: &str = "contained_expectation_invalid";

fn invalid() -> RestrictedPytestError {
    RestrictedPytestError::new(INVALID, "Invalid contained run expectation request.")
}

pub(crate) fn expectation(input: &Value) -> Result<Value, RestrictedPytestError> {
    let fields = input.as_object().ok_or_else(invalid)?;
    if fields.keys().any(|key| !FIELDS.contains(&key.as_str())) {
        return Err(invalid());
    }
    let kind = fields
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(invalid)?;
    let plan_profile = match fields.get("plan_profile") {
        None | Some(Value::Null) => None,
        Some(Value::String(profile)) => Some(profile.as_str()),
        Some(_) => return Err(invalid()),
    };
    let words = match fields.get("command") {
        Some(Value::Array(words)) if !words.is_empty() => words,
        _ => return Err(invalid()),
    };
    let words = words
        .iter()
        .map(Value::as_str)
        .collect::<Option<Vec<_>>>()
        .ok_or_else(invalid)?;
    let program = program_name(words[0]);
    let reason = reason(kind, plan_profile, program).ok_or_else(invalid)?;
    let profile = crate::hook_responses::contained_execution_profile(reason).ok_or_else(invalid)?;
    Ok(json!({"reason": reason, "profile": profile}))
}

fn reason(kind: &str, plan_profile: Option<&str>, program: &str) -> Option<&'static str> {
    Some(match (kind, plan_profile) {
        ("inline_eval", Some("node-eval-readonly-v1")) if program == "bun" => {
            "native_bun_eval_readonly_containment_required"
        }
        ("inline_eval", Some("node-eval-readonly-v1")) => {
            "native_node_eval_readonly_containment_required"
        }
        ("inline_eval", Some("python-eval-readonly-v1")) => {
            "native_python_eval_readonly_containment_required"
        }
        ("node_tool", Some("node-build-output-v1")) => {
            "native_node_build_output_containment_required"
        }
        ("node_tool", Some("node-tool-readonly-v1")) => {
            "native_node_tool_readonly_containment_required"
        }
        ("git", None) => "native_git_readonly_containment_required",
        ("vitest", None) => "native_vitest_readonly_containment_required",
        ("node_test", None) => "native_node_test_readonly_containment_required",
        ("pytest", None) => "native_pytest_readonly_containment_required",
        _ => return None,
    })
}

#[cfg(test)]
#[path = "contained_expectation_tests.rs"]
mod tests;
