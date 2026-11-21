//! Codex: the one failure an install, install plan, uninstall or hook
//! publication answer ends in.
//!
//! Each of these ops reports why it stopped in a field of its own: a
//! `conflict` for a file that changed after the caller read it, a `fault`, a
//! publication `error` with the `rollback_error` that failed beside it, or a
//! `retire_error` and whether the committed generation was `withdrawn`. The
//! runtime decides which of them the caller must raise and names it once, as
//! `raise`; the caller only renders the exception.
//!
//! `raise` is `{"fault": F}`, `{"fault": F, "rollback": R}` (the rollback
//! failed too) or `{"runtime": message, "cause": F}`. `F` is a fault as
//! `transition_files` shapes it, or `{"runtime": message}`.

use serde_json::{json, Value};

/// Legacy JSON removal failed and the committed generation could not be
/// withdrawn, so the sources are not fully restored.
const MIGRATION_ROLLBACK_FAILED: &str = "codex_hook_migration_rollback_failed: Guard could not fully \
restore Codex hook sources after legacy JSON removal failed. Run `hol-guard install codex` to repair \
the installation.";

/// The answer with its `raise`, when it ended in a failure.
pub(super) fn with_raise(mut answer: Value) -> Value {
    if let (Some(raise), Some(fields)) = (raise(&answer), answer.as_object_mut()) {
        fields.insert("raise".to_owned(), raise);
    }
    answer
}

fn raise(answer: &Value) -> Option<Value> {
    if answer.get("conflict").and_then(Value::as_bool) == Some(true) {
        return Some(json!({
            "fault": { "transition": "adapter_preparation_generation_conflict" }
        }));
    }
    if let Some(fault) = answer.get("fault") {
        return Some(json!({ "fault": fault }));
    }
    if let Some(error) = answer.get("error") {
        return Some(match answer.get("rollback_error") {
            Some(rollback) => json!({ "fault": error, "rollback": rollback }),
            None => json!({ "fault": error }),
        });
    }
    let retire = answer.get("retire_error")?;
    if answer.get("withdrawn").and_then(Value::as_bool) == Some(true) {
        return Some(json!({ "fault": retire }));
    }
    Some(json!({ "runtime": MIGRATION_ROLLBACK_FAILED, "cause": retire }))
}

#[cfg(test)]
#[path = "codex_failure_tests.rs"]
mod tests;
