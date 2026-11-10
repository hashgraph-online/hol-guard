use serde_json::json;

use super::*;

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
    let body = fail_safe("Claude_Code", "PreToolUse");
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
    let body = fail_safe("codex", "before_tool_call");
    assert_eq!(body["hookSpecificOutput"]["permissionDecision"], "deny");
}

#[test]
fn a_prompt_event_fails_closed_with_the_prompt_reason() {
    let body = fail_safe("codex", "user_prompt_submit");
    assert_eq!(body["decision"], "block");
    assert_eq!(
        body["reason"],
        "HOL Guard could not complete native prompt review safely."
    );
}

#[test]
fn a_lifecycle_event_carries_no_verdict() {
    let body = fail_safe("codex", "PostToolUse");
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
fn a_hook_reply_needs_a_status_an_object_body_and_a_cache_rule() {
    assert_eq!(
        reply_parts(&json!({"status": 200, "body": {"ok": true}, "no_store": false})),
        Some((200, json!({"ok": true}), false))
    );
    assert_eq!(
        reply_parts(&json!({"status": 700, "body": {}, "no_store": false})),
        None
    );
    assert_eq!(
        reply_parts(&json!({"status": 200, "body": [], "no_store": false})),
        None
    );
    assert_eq!(reply_parts(&json!({"status": 200, "body": {}})), None);
}
