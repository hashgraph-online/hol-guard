//! Per-event protection proof states for one harness coverage answer.
//!
//! The vocabulary is the published capability contract's: `configured`,
//! `transport_ready`, `live_block_proven`, `live_allow_proven`,
//! `observe_only`, `partial`, `unsupported` and `stale`. A state is derived
//! only from the evidence already in the coverage answer. File presence,
//! a declared row or a unit test never reaches a `live_*` state, and a
//! version or build the evidence does not name is `stale`, never proven.
//!
//! `transport_ready` and `live_allow_proven` need evidence kinds the bundled
//! manifest does not carry yet, so this derivation never emits them. They
//! stay in the vocabulary so every projection renders them the same way.

use serde_json::{json, Value};

use super::CapabilityRow;

/// Every state a projection must be able to render. The tests hold it equal
/// to the shared fixture that the dashboard and CLI labels are checked against.
#[cfg(test)]
const PROTECTION_STATES: [&str; 8] = [
    "configured",
    "transport_ready",
    "live_block_proven",
    "live_allow_proven",
    "observe_only",
    "partial",
    "unsupported",
    "stale",
];

/// Coverage reasons that mean evidence exists, but not for what is running.
const STALE_REASONS: [&str; 3] = [
    "version_not_in_evidence",
    "observation_stale",
    "no_evidence_for_this_build",
];

fn unsupported(row: &CapabilityRow) -> bool {
    matches!(row.transport.as_str(), "none" | "adapter_declared")
        || row
            .declared_actions
            .iter()
            .any(|action| action == "unavailable")
}

/// Whether a live-block record in the answer's evidence names this row's
/// event on this row's transport. A harness can declare one event on more
/// than one transport, and a block proven on one proves nothing on another.
fn live_block_proven(payload: &Value, row: &CapabilityRow) -> bool {
    payload["state"] == "tested"
        && payload["evidence"].as_array().is_some_and(|records| {
            records.iter().any(|record| {
                record["evidence_level"] == "live_block"
                    && record["transport"].as_str() == Some(row.transport.as_str())
                    && record["events"]
                        .as_array()
                        .is_some_and(|events| events.iter().any(|item| item == &row.event))
            })
        })
}

fn event_state(payload: &Value, row: &CapabilityRow) -> (&'static str, Option<&'static str>) {
    if unsupported(row) {
        return ("unsupported", Some("no_enforceable_boundary"));
    }
    if row.mode.as_deref() == Some("observe") {
        return ("observe_only", Some("runs_after_execution"));
    }
    if live_block_proven(payload, row) {
        return ("live_block_proven", None);
    }
    let reason = payload["reason"].as_str().unwrap_or_default();
    if let Some(stale) = STALE_REASONS.iter().find(|item| **item == reason) {
        return ("stale", Some(stale));
    }
    ("configured", Some("no_live_evidence"))
}

/// The harness-level state across its enforceable events.
fn aggregate(states: &[&'static str]) -> &'static str {
    let enforceable: Vec<_> = states
        .iter()
        .copied()
        .filter(|state| !matches!(*state, "unsupported" | "observe_only"))
        .collect();
    if enforceable.is_empty() {
        return if states.contains(&"observe_only") {
            "observe_only"
        } else {
            "unsupported"
        };
    }
    let proven = enforceable
        .iter()
        .filter(|state| **state == "live_block_proven")
        .count();
    if proven == enforceable.len() {
        "live_block_proven"
    } else if proven > 0 {
        "partial"
    } else if enforceable.contains(&"stale") {
        "stale"
    } else {
        "configured"
    }
}

/// Add `event_states` and `protection_state` to a coverage answer.
pub(super) fn with_event_states(mut payload: Value, rows: Option<&Vec<CapabilityRow>>) -> Value {
    let mut states = Vec::new();
    let event_states: Vec<Value> = rows
        .into_iter()
        .flatten()
        .map(|row| {
            let (state, reason) = event_state(&payload, row);
            states.push(state);
            json!({
                "event": row.event,
                "tools": row.tools,
                "surface": row.surface,
                "transport": row.transport,
                "mode": row.mode,
                "state": state,
                "reason": reason,
            })
        })
        .collect();
    payload["protection_state"] = json!(aggregate(&states));
    payload["event_states"] = json!(event_states);
    payload
}

#[cfg(test)]
#[path = "harness_protection_state_tests.rs"]
mod tests;
