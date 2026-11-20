//! Oh My Pi's `goal` keeps the session's own objective: the sentence the model
//! writes for itself, the token budget it plans against, and which of the five
//! operations it is performing on them. Nothing in that input names a file, a
//! command, a package or a host, so the call changes only the session's
//! bookkeeping, the way `todo` does, and this file names that shape so the
//! call is allowed instead of reviewed. Any other key, any value of another
//! type, and any input carrying a path is not Oh My Pi's goal input and keeps
//! the ordinary review.

use super::{generic_action, generic_result, strict_tool_input, GenericSignals, OmpContext};
use guard_contracts::{PreToolActionTypeV1, PreToolOperationV1, PreToolResultV1};
use serde_json::{Map, Value};

/// `op` is one of `create`, `get`, `complete`, `drop` and `resume`;
/// `objective` is the sentence the model writes for itself and `token_budget`
/// a number. Every other key, and any value of another type, is not Oh My Pi's
/// goal input.
pub(super) fn goal_input(input: &Map<String, Value>) -> bool {
    let known_shape = |key: &str, value: &Value| match key {
        "op" => matches!(
            value.as_str(),
            Some("complete" | "create" | "drop" | "get" | "resume")
        ),
        "objective" => value.is_string(),
        "token_budget" => value.is_u64(),
        _ => false,
    };
    input.contains_key("op") && input.iter().all(|(key, value)| known_shape(key, value))
}

/// The bookkeeping proof for `goal`. `get` reads the objective; the other ops
/// write it. Neither reaches past the session, so both are allowed once the
/// input is Oh My Pi's own shape and carries no path.
pub(super) fn goal_state(
    payload: &Value,
    signals: &GenericSignals,
    context: &OmpContext<'_>,
) -> Option<PreToolResultV1> {
    let input = strict_tool_input(payload)?;
    if !signals.path_values.is_empty() || !goal_input(input) {
        return None;
    }
    let operation = match input.get("op").and_then(Value::as_str) {
        Some("get") => PreToolOperationV1::Read,
        _ => PreToolOperationV1::Set,
    };
    Some(generic_result(
        generic_action(
            context.harness,
            context.event,
            PreToolActionTypeV1::Harness,
            operation,
            true,
            false,
        ),
        "allow",
        "native_omp_goal_state",
        "The Rust authority allowed this Oh My Pi goal call; it reads or sets the session's own objective and reaches nothing outside it.",
    ))
}
