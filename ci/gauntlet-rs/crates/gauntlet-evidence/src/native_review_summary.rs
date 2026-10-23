//! Recompute Python's Native Pre/Post review accounting from supplied events.
//! This relation does not authenticate the event producer or kernel effects.

use crate::{EvidenceError, Result};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};

const INCOMPLETE: &str = "native output review incomplete or unavailable";
const UNREVIEWABLE_REASONS: &[&str] = &[
    "native_policy_not_ready",
    "native_policy_update_in_progress",
    "native_hook_event_unavailable",
    "native_pre_tool_unavailable",
    "native_post_tool_unavailable",
    "native_overloaded",
    "native_hook_worker_unavailable",
    "native_hook_worker_unavailable_before_compatibility",
    "native_hook_worker_unsupported",
    "native_hook_worker_exception",
    "native_hook_compatibility_disabled",
    "native_hook_edge_invalid_response",
    "native_hook_edge_unavailable",
    "python_hook_oracle_unavailable",
    "python_oracle_exception",
    "watch_recording_only",
    "daemon_hook_queue_capacity",
    "daemon_hook_deadline_exhausted",
    "daemon_hook_process_deadline_exhausted",
    "daemon_hook_process_not_ready",
    "daemon_hook_process_failed",
    "daemon_hook_process_invalid_request",
    "daemon_hook_process_guard_home_mismatch",
    "daemon_worker_exception",
    "harness_not_managed",
    "invalid_hook_payload_reference",
    "daemon_hook_queue_bytes",
    "native_prompt_unavailable",
];

/// Python's exact `review_completed` classification. A numeric `1` is not
/// the boolean `true`; an unknown reason is still a completed review.
pub fn native_review_completed(response: &Value) -> bool {
    let Some(value) = response.as_object() else {
        return false;
    };
    !value
        .get("reason_code")
        .and_then(Value::as_str)
        .is_some_and(|reason| UNREVIEWABLE_REASONS.contains(&reason))
        && value.get("recording_only") != Some(&Value::Bool(true))
        && value.get("observe_mode") != Some(&Value::Bool(true))
}

fn increment(counts: &mut BTreeMap<String, usize>, call: &str) {
    *counts.entry(call.to_owned()).or_default() += 1;
}

fn required_str<'a>(row: &'a Value, field: &str, missing: &'static str) -> Result<&'a str> {
    row.get(field)
        .and_then(Value::as_str)
        .ok_or(EvidenceError::Invalid(missing))
}

/// Python-frozen `review_summary` over already supplied builtin and contained
/// transport rows. The returned counts are only data relations.
pub fn recompute_native_review_summary(events: &Value, contained_events: &Value) -> Result<Value> {
    let events = events
        .as_array()
        .filter(|rows| rows.len() <= 10_000)
        .ok_or(EvidenceError::Invalid(
            "bounded native review events required",
        ))?;
    let contained_events = contained_events
        .as_array()
        .filter(|rows| rows.len() <= 10_000)
        .ok_or(EvidenceError::Invalid("bounded contained events required"))?;
    let mut consumed = BTreeMap::new();
    for row in contained_events {
        if row.get("kind") == Some(&json!("contained-route-consumed")) {
            let payload = required_str(row, "payload_digest", "KeyError: 'payload_digest'")?;
            increment(&mut consumed, payload);
        }
    }
    let mut required = BTreeMap::new();
    let mut completed = BTreeMap::new();
    let mut attempted = BTreeMap::new();
    let mut denied = BTreeSet::new();
    let mut unreviewable = BTreeSet::new();
    let mut pre_count = 0;
    let mut post_count = 0;
    for row in events {
        if row.get("kind") != Some(&json!("actual-hook-response")) {
            continue;
        }
        let call = required_str(row, "tool_call_id", "KeyError: 'tool_call_id'")?;
        let response = row
            .get("product_response")
            .ok_or(EvidenceError::Invalid("KeyError: 'product_response'"))?;
        let reviewed = native_review_completed(response);
        if !reviewed {
            unreviewable.insert(call.to_owned());
        }
        let event = required_str(row, "hook_event_name", "KeyError: 'hook_event_name'")?;
        if event == "PreToolUse" {
            pre_count += 1;
        }
        if event == "PostToolUse" {
            post_count += 1;
            increment(&mut attempted, call);
            if reviewed {
                increment(&mut completed, call);
            }
        } else {
            let decision = required_str(response, "decision", "KeyError: 'decision'")?;
            if decision == "allow" {
                increment(&mut required, call);
            } else {
                let payload = required_str(row, "payload_digest", "KeyError: 'payload_digest'")?;
                let available = consumed.entry(payload.to_owned()).or_insert(0);
                if *available > 0 {
                    increment(&mut required, call);
                    *available -= 1;
                } else {
                    denied.insert(call.to_owned());
                }
            }
        }
    }
    let missing: Vec<String> = required
        .iter()
        .filter(|(call, count)| completed.get(*call).copied().unwrap_or(0) < **count)
        .map(|(call, _)| call.clone())
        .collect();
    let required_ids: Vec<String> = required.keys().cloned().collect();
    let completed_ids: Vec<String> = completed.keys().cloned().collect();
    Ok(json!({
        "schema": "builtin-review-summary.v2",
        "pre_count": pre_count,
        "post_count": post_count,
        "native_pre_refusal_call_ids": denied.into_iter().collect::<Vec<_>>(),
        "backend_admission_call_ids": required_ids,
        "post_review_call_ids": completed_ids,
        "required_post_counts": required,
        "post_attempt_counts": attempted,
        "unreviewable_hook_call_ids": unreviewable.into_iter().collect::<Vec<_>>(),
        "post_review_counts": completed,
        "missing_required_post_call_ids": missing,
    }))
}

/// Compare a producer's stored summary with Rust's recomputed relation. An
/// internally complete summary still cannot establish genuine Native reviews.
pub fn verify_native_review_summary(builtin: &Value) -> Result<Value> {
    let summary = recompute_native_review_summary(
        builtin
            .get("transport_observations")
            .ok_or(EvidenceError::Invalid(INCOMPLETE))?,
        builtin
            .get("contained_transport_observations")
            .ok_or(EvidenceError::Invalid(INCOMPLETE))?,
    )?;
    if builtin.get("review_summary") != Some(&summary) {
        return Err(EvidenceError::Invalid(INCOMPLETE));
    }
    let complete = summary["missing_required_post_call_ids"] == json!([])
        && summary["unreviewable_hook_call_ids"] == json!([]);
    Ok(json!({"review_complete": complete, "execution_eligible": false}))
}
