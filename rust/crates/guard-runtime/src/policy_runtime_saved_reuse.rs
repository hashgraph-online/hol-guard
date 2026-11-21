//! The runtime hook's `saved_reuse` verdict, composed onto its saved-decision
//! read.
//!
//! `commands_hook_native_eval.py` (the non-package branch) checked a stored
//! allow's context token, checked a fresh Cursor native allowance's token,
//! explained a miss through the approval-reuse diagnostic, and then asked for
//! the `HookArtifactCompose` `saved_reuse` verdict, each a resident call. The
//! runtime saved-decision lookup now gathers the same inputs on its own
//! connection and answers that unchanged query in the same call. The query is
//! echoed so the caller can re-ask after a failed claim without recomputing.

use guard_contracts::{RuntimeSavedReuseV1, SavedReuseQueryV1};
use serde_json::{json, Value};

use crate::context_digest::{python_strip, validate_context_tokens};
use crate::hook_artifact_compose_reuse::saved_reuse;
use crate::policy_lookup_reuse::MissDiagnosis;

fn field<'a>(value: &'a Value, key: &str) -> &'a Value {
    value.get(key).unwrap_or(&Value::Null)
}

/// `_optional_string`: a non-blank string, stripped, or `null`.
fn optional_text(value: &Value) -> Value {
    value
        .as_str()
        .map(python_strip)
        .filter(|text| !text.is_empty())
        .map_or(Value::Null, |text| Value::String(text.to_owned()))
}

/// `{answer, query}`: the `saved_reuse` answer and the query it answered.
pub(crate) fn saved_reuse_answer<D>(
    reuse: &RuntimeSavedReuseV1,
    current_hash: &str,
    composed: &Value,
    diagnose: D,
) -> Value
where
    D: FnOnce() -> MissDiagnosis,
{
    let query = saved_reuse_query(
        reuse,
        current_hash,
        composed,
        validate_context_tokens,
        diagnose,
    );
    json!({
        "answer": saved_reuse(&query),
        "query": serde_json::to_value(&query).unwrap_or(Value::Null),
    })
}

/// Build the `saved_reuse` query from the runtime lookup's `{lookup,
/// decision}` exactly as the hook did.
///
/// A stored allow's token is checked only without integrity evidence and,
/// like `_runtime_saved_allow_validation_reason`, with no `runtime-exact:`
/// exemption. The miss is diagnosed only when nothing was stored, no Cursor
/// allowance was offered and no integrity evidence was found.
pub(crate) fn saved_reuse_query<V, D>(
    reuse: &RuntimeSavedReuseV1,
    current_hash: &str,
    composed: &Value,
    mut validate: V,
    diagnose: D,
) -> SavedReuseQueryV1
where
    V: FnMut(&Value, &Value) -> Option<String>,
    D: FnOnce() -> MissDiagnosis,
{
    let decision = field(composed, "decision");
    let stored_present = !decision.is_null();
    let integrity_failure = !field(field(composed, "lookup"), "ignored_local_integrity").is_null();
    let stored_action = if stored_present {
        optional_text(field(decision, "action"))
    } else {
        Value::Null
    };
    let current = Value::String(current_hash.to_owned());
    let stored_validation_reason =
        if stored_present && !integrity_failure && stored_action == json!("allow") {
            validate(&optional_text(field(decision, "artifact_hash")), &current)
        } else {
            None
        };
    let cursor = reuse.cursor_native_token.clone().map(Value::String);
    let cursor_validation_reason = cursor.as_ref().and_then(|token| validate(token, &current));
    let (diagnostic_reason, diagnostic_stored_hash) =
        if !stored_present && cursor.is_none() && !integrity_failure {
            diagnose()
        } else {
            (None, None)
        };
    SavedReuseQueryV1 {
        current_action: reuse.current_action.clone(),
        stored_present,
        stored_action,
        stored_artifact_hash: field(decision, "artifact_hash").clone(),
        integrity_failure,
        stored_validation_reason,
        cursor_native_present: cursor.is_some(),
        cursor_validation_reason,
        diagnostic_reason,
        diagnostic_stored_hash: diagnostic_stored_hash.map_or(Value::Null, Value::String),
    }
}

#[cfg(test)]
#[path = "policy_runtime_saved_reuse_tests.rs"]
mod tests;
