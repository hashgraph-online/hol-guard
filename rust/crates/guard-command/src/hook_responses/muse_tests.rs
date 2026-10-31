use super::*;
use serde_json::json;

fn object(value: Value) -> Object {
    value.as_object().cloned().expect("object")
}

fn render(response: Value, event_name: &str) -> (Option<Object>, i64) {
    bridge_response(&object(response), event_name)
}

/// The fail-closed reply the daemon sends when the resident cannot answer a
/// PreToolUse hook.
fn fail_closed_pre_tool() -> Value {
    json!({
        "policy_action": "block",
        "reason_code": "native_hook_render_unavailable",
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": "HOL Guard could not complete native review safely.",
        },
    })
}

/// The same reply for a PermissionRequest, whose verdict sits one level
/// deeper and which names no `policy_action` at all.
fn fail_closed_permission_request() -> Value {
    json!({
        "reason_code": "native_hook_render_unavailable",
        "hookSpecificOutput": {
            "hookEventName": "PermissionRequest",
            "decision": {
                "behavior": "deny",
                "message": "HOL Guard could not complete native review safely.",
            },
        },
    })
}

fn fail_closed_prompt() -> Value {
    json!({
        "policy_action": "block",
        "decision": "block",
        "reason": "HOL Guard could not complete native prompt review safely.",
        "reason_code": "native_prompt_unavailable",
        "systemMessage": "HOL Guard could not complete native prompt review safely.",
        "hookSpecificOutput": {"hookEventName": "UserPromptSubmit"},
    })
}

/// The reply for a hook that belongs to an app Guard does not manage.
fn unmanaged_passthrough() -> Value {
    json!({"continue": true, "reason_code": "harness_not_managed"})
}

#[test]
fn an_allow_is_empty_stdout() {
    // Muse rejects a bare permissionDecision allow; allow is silence.
    assert_eq!(
        render(json!({"policy_action": "allow"}), "PreToolUse"),
        (None, 0)
    );
}

#[test]
fn a_block_is_a_deny_document_on_exit_zero() {
    let (document, exit_code) = render(
        json!({"policy_action": "block", "reason": "nope"}),
        "PreToolUse",
    );
    assert_eq!(exit_code, 0);
    let document = document.expect("document");
    assert_eq!(
        document["hookSpecificOutput"]["permissionDecision"],
        json!("deny")
    );
    assert_eq!(
        document["hookSpecificOutput"]["permissionDecisionReason"],
        json!("nope")
    );
}

#[test]
fn a_blocked_prompt_uses_the_decision_field() {
    let (document, exit_code) = render(
        json!({"policy_action": "review", "reason": "needs approval"}),
        "UserPromptSubmit",
    );
    assert_eq!(exit_code, 0);
    assert_eq!(
        document.expect("document"),
        object(json!({"decision": "block", "reason": "needs approval"}))
    );
}

#[test]
fn a_permission_request_under_review_defers_to_muses_own_prompt() {
    assert_eq!(
        render(json!({"policy_action": "review"}), "PermissionRequest"),
        (None, 0)
    );
}

#[test]
fn a_blocked_permission_request_denies() {
    let (document, _exit_code) = render(
        json!({"policy_action": "block", "reason": "never"}),
        "PermissionRequest",
    );
    assert_eq!(
        document.expect("document")["hookSpecificOutput"]["permissionDecision"],
        json!("deny")
    );
}

#[test]
fn a_post_tool_use_adds_context_and_never_denies() {
    let (document, exit_code) = render(
        json!({"policy_action": "block", "reason": "output flagged"}),
        "PostToolUse",
    );
    assert_eq!(exit_code, 0);
    assert_eq!(
        document.expect("document")["hookSpecificOutput"]["additionalContext"],
        json!("output flagged")
    );
}

#[test]
fn a_session_start_adds_guard_context() {
    let (document, _exit_code) = render(json!({"policy_action": "allow"}), "SessionStart");
    let document = document.expect("document");
    let context = document["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .expect("context");
    assert!(context.contains("HOL Guard"), "{context}");
}

#[test]
fn a_stop_keeps_its_own_event_name_and_never_denies() {
    let (document, exit_code) = render(
        json!({"policy_action": "block", "reason": "output flagged"}),
        "Stop",
    );
    assert_eq!(exit_code, 0);
    let document = document.expect("document");
    // Muse rejects a hookSpecificOutput whose event name mismatches.
    assert_eq!(
        document["hookSpecificOutput"]["hookEventName"],
        json!("Stop")
    );
    assert!(document["hookSpecificOutput"]
        .as_object()
        .expect("output")
        .get("permissionDecision")
        .is_none());
}

#[test]
fn a_fail_closed_permission_request_denies() {
    let (document, exit_code) = render(fail_closed_permission_request(), "PermissionRequest");
    assert_eq!(exit_code, 0);
    assert_eq!(
        document.expect("document")["hookSpecificOutput"]["permissionDecision"],
        json!("deny")
    );
}

#[test]
fn a_fail_closed_pre_tool_use_denies() {
    let (document, exit_code) = render(fail_closed_pre_tool(), "PreToolUse");
    assert_eq!(exit_code, 0);
    assert_eq!(
        document.expect("document")["hookSpecificOutput"]["permissionDecision"],
        json!("deny")
    );
}

#[test]
fn a_fail_closed_prompt_blocks() {
    let (document, exit_code) = render(fail_closed_prompt(), "UserPromptSubmit");
    assert_eq!(exit_code, 0);
    assert_eq!(document.expect("document")["decision"], json!("block"));
}

#[test]
fn an_answer_with_no_verdict_denies_a_deciding_event() {
    let (document, exit_code) = render(json!({"reason_code": "whatever"}), "PreToolUse");
    assert_eq!(exit_code, 0);
    let document = document.expect("document");
    assert_eq!(
        document["hookSpecificOutput"]["permissionDecision"],
        json!("deny")
    );
    let reason = document["hookSpecificOutput"]["permissionDecisionReason"]
        .as_str()
        .expect("reason");
    assert!(reason.contains("could not read a verdict"), "{reason}");
}

#[test]
fn an_answer_with_no_verdict_is_silence_on_an_observing_event() {
    assert_eq!(
        render(json!({"reason_code": "whatever"}), "PostToolUse"),
        (None, 0)
    );
}

#[test]
fn an_unmanaged_passthrough_stays_silent() {
    // Guard does not manage this app; a continue reply must not deny the call.
    assert_eq!(render(unmanaged_passthrough(), "PreToolUse"), (None, 0));
}

#[test]
fn an_unknown_policy_action_is_restrictive() {
    let (document, _exit_code) = render(
        json!({"policy_action": "tomorrow", "reason": "unreadable"}),
        "PreToolUse",
    );
    assert_eq!(
        document.expect("document")["hookSpecificOutput"]["permissionDecision"],
        json!("deny")
    );
}

#[test]
fn an_event_name_is_read_however_the_harness_spells_it() {
    assert_eq!(compact_event("pre_tool-use"), "pretooluse");
    assert_eq!(
        render(json!({"policy_action": "allow"}), "pre_tool_use"),
        (None, 0)
    );
}
