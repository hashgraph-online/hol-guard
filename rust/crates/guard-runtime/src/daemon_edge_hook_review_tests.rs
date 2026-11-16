use serde_json::json;

use super::*;

fn unavailable(harness: &str, event: &str) -> Value {
    fail_safe(
        harness,
        event,
        WORKER_UNAVAILABLE_REASON,
        WORKER_UNAVAILABLE_CODE,
    )
}

#[test]
fn routes_name_the_harness_and_the_readiness_check() {
    assert_eq!(route("/v1/hooks/codex"), Some(("codex", false)));
    assert_eq!(route("/v1/hooks/pi/readiness"), Some(("pi", true)));
    assert_eq!(route("/v1/hooks/"), None);
    assert_eq!(route("/v1/hooks/pi/other"), None);
    assert_eq!(route("/v1/requests/pi"), None);
    assert!(owns("/v1/hooks/claude-code"));
}

#[test]
fn a_tool_event_fails_closed_with_the_worker_reason() {
    let body = unavailable("Claude_Code", "PreToolUse");
    assert_eq!(body["policy_action"], "block");
    assert_eq!(body["reason_code"], WORKER_UNAVAILABLE_CODE);
    assert_eq!(body["hookSpecificOutput"]["permissionDecision"], "deny");
    assert_eq!(
        body["hookSpecificOutput"]["permissionDecisionReason"],
        WORKER_UNAVAILABLE_REASON
    );
}

#[test]
fn a_before_event_is_a_tool_event() {
    let body = unavailable("codex", "before_tool_call");
    assert_eq!(body["hookSpecificOutput"]["permissionDecision"], "deny");
}

#[test]
fn a_prompt_event_fails_closed_with_the_prompt_reason() {
    let body = unavailable("codex", "user_prompt_submit");
    assert_eq!(body["decision"], "block");
    let contract: serde_json::Value = serde_json::from_str(ENVELOPES).unwrap();
    assert_eq!(body["reason"], contract["defaults"]["prompt_reason"]);
    assert!(body["reason"]
        .as_str()
        .is_some_and(|reason| !reason.is_empty()));
}

#[test]
fn a_lifecycle_event_carries_no_verdict() {
    let body = unavailable("codex", "PostToolUse");
    assert_eq!(body["continue"], true);
    assert_eq!(body["hookSpecificOutput"]["hookEventName"], "PostToolUse");
    assert_eq!(body["reason_code"], WORKER_UNAVAILABLE_CODE);
}

#[test]
fn placeholders_fill_only_whole_strings() {
    let filled = fill(
        json!({"a": "$reason", "b": ["$reason", "x $reason"], "c": 1}),
        &[("$reason", "why")],
    );
    assert_eq!(
        filled,
        json!({"a": "why", "b": ["why", "x $reason"], "c": 1})
    );
}

#[test]
fn a_capacity_refusal_names_its_cause() {
    let body = fail_safe(
        "codex",
        "PreToolUse",
        capacity_reason(hook_scheduler::DEADLINE_EXHAUSTED),
        hook_scheduler::DEADLINE_EXHAUSTED,
    );
    let text = body.to_string();
    assert!(text.contains("within the hook deadline"));
    assert!(text.contains(hook_scheduler::DEADLINE_EXHAUSTED));
    assert!(capacity_reason(hook_scheduler::QUEUE_CAPACITY).contains("queueing"));
}

#[test]
fn a_step_refusal_needs_a_reason_and_a_code() {
    assert_eq!(
        refusal(&json!({"reason": "r", "reason_code": "c"})),
        Some(("r", "c"))
    );
    assert_eq!(refusal(&json!({"reason": "r"})), None);
}

#[test]
fn an_unmanaged_app_passes_through_in_its_own_envelope() {
    assert_eq!(
        envelope("unmanaged", "PI", &[]),
        json!({"decision": "allow", "reason_code": "harness_not_managed"})
    );
    assert_eq!(envelope("unmanaged", "grok", &[]), json!({}));
    assert_eq!(
        envelope("unmanaged", "codex", &[]),
        json!({"continue": true, "reason_code": "harness_not_managed"})
    );
}
