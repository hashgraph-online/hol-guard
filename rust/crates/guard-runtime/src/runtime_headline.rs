//! `runtime_headline` runner-authority kind: the headline of the local runtime
//! snapshot. Ported from the approval center's
//! `_resolve_runtime_headline_state`, `_runtime_headline_label` and
//! `_runtime_headline_detail`.
//!
//! Python reads the queue and the protection-health report, then ships:
//!
//! - `pending_count`, the number of requests waiting for a decision;
//! - `runtime_state_present`, whether a runtime row (or the serving process)
//!   stands for the local runtime;
//! - `protection_state`, the protection-health report's state, or `""` when
//!   the report is unavailable.
//!
//! The answer carries `headline_state`, `headline_label` and
//! `headline_detail`. An unavailable report is never read as protection: it
//! falls to `degraded`.

use serde_json::{json, Value};

use crate::runner_authority_op::{KindResult, ERR_INVALID};

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let pending_count = args
        .get("pending_count")
        .and_then(Value::as_u64)
        .ok_or(ERR_INVALID)?;
    let runtime_state_present = args
        .get("runtime_state_present")
        .and_then(Value::as_bool)
        .ok_or(ERR_INVALID)?;
    let protection_state = args
        .get("protection_state")
        .and_then(Value::as_str)
        .ok_or(ERR_INVALID)?;
    let state = if !runtime_state_present {
        "setup"
    } else if pending_count > 0 {
        "needs_decision"
    } else if matches!(protection_state, "protected" | "partial") {
        protection_state
    } else {
        "degraded"
    };
    let (label, detail) = copy(state);
    Ok(json!({
        "headline_state": state,
        "headline_label": label,
        "headline_detail": detail,
    }))
}

fn copy(state: &str) -> (&'static str, &'static str) {
    match state {
        "setup" => (
            "Setup required",
            "The local Guard runtime is offline. Start the daemon or rerun hol-guard bootstrap.",
        ),
        "protected" => (
            "Protected",
            "This machine is protected and the local queue is clear.",
        ),
        "partial" => (
            "Partial",
            "Core protection checks pass, but complete local evidence health cannot be proven.",
        ),
        "needs_decision" => (
            "Decision needed",
            "One or more actions are waiting for a decision in the current review queue.",
        ),
        _ => (
            "Degraded",
            "One or more required protection checks failed or remain unproven.",
        ),
    }
}

#[cfg(test)]
#[path = "runtime_headline_tests.rs"]
mod tests;
