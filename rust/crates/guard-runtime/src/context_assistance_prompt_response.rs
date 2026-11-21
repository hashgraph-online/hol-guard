//! Writing CIGAR's context into a prompt hook's answer.
use super::{PROMPT_CONTEXT_APPS, PROMPT_CONTEXT_FLAG};
use serde_json::Value;

/// Whether this harness's prompt hook passes added context to the model.
pub(super) fn takes_context(harness: &str, payload: &Value) -> bool {
    match harness {
        "pi" | "omp" => payload.get(PROMPT_CONTEXT_FLAG).and_then(Value::as_bool) == Some(true),
        _ => PROMPT_CONTEXT_APPS.contains(&harness),
    }
}

/// An allowed prompt whose answer has a place for context.
pub(super) fn allowed(response: &Value) -> bool {
    response.get("decision").and_then(Value::as_str) != Some("block")
        && response.get("continue").and_then(Value::as_bool) != Some(false)
        && response
            .get("hookSpecificOutput")
            .is_some_and(Value::is_object)
}

pub(super) fn add_context(response: &mut Value, context: &str) {
    let Some(output) = response
        .get_mut("hookSpecificOutput")
        .and_then(Value::as_object_mut)
    else {
        return;
    };
    let combined = match output.get("additionalContext").and_then(Value::as_str) {
        Some(existing) if !existing.is_empty() => format!("{existing}\n\n{context}"),
        _ => context.to_owned(),
    };
    output.insert("additionalContext".into(), Value::String(combined));
}

/// Kimi Code hands a prompt hook's `message` to the model and drops
/// `additionalContext`, so the context goes there too.
pub(super) fn kimi_message(response: &mut Value) {
    let output = response
        .get_mut("hookSpecificOutput")
        .and_then(Value::as_object_mut);
    let Some(output) = output else { return };
    let context = output.get("additionalContext").and_then(Value::as_str);
    if let Some(context) = context.filter(|text| !text.is_empty()).map(str::to_owned) {
        output.insert("message".into(), Value::String(context));
    }
}

pub(super) fn context_len(response: &Value) -> usize {
    response
        .pointer("/hookSpecificOutput/additionalContext")
        .and_then(Value::as_str)
        .map_or(0, str::len)
}
