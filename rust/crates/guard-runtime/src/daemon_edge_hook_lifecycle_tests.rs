use serde_json::{json, Map, Value};

use super::{claude_op, fallback, request, PERMISSION_REQUEST, TURN_STOP};

fn object(value: Value) -> Map<String, Value> {
    value.as_object().unwrap().clone()
}

#[test]
fn only_a_permission_prompt_notification_runs_the_prompt_op() {
    let prompt = object(json!({"notification_type": "permission_prompt"}));
    let idle = object(json!({"notification_type": "idle_prompt"}));
    assert_eq!(
        claude_op("Notification", &prompt),
        Some("claude_permission_prompt")
    );
    assert_eq!(claude_op("Notification", &idle), None);
    assert_eq!(
        claude_op("PermissionRequest", &idle),
        Some(PERMISSION_REQUEST)
    );
    assert_eq!(claude_op("Stop", &idle), Some(TURN_STOP));
    assert_eq!(claude_op("PreToolUse", &prompt), None);
}

#[test]
fn an_unanswered_op_falls_back_as_the_python_worker_did() {
    assert_eq!(fallback(TURN_STOP), None);
    assert_eq!(
        fallback(PERMISSION_REQUEST),
        Some(json!({
            "guard_permission_passthrough": true,
            "hookSpecificOutput": {"hookEventName": "PermissionRequest"},
        }))
    );
    let notice = fallback("claude_permission_prompt").unwrap();
    assert_eq!(
        notice["hookSpecificOutput"]["hookEventName"],
        "Notification"
    );
    assert_eq!(
        notice["systemMessage"],
        notice["hookSpecificOutput"]["additionalContext"]
    );
}

#[test]
fn the_request_carries_the_key_the_session_and_only_lifecycle_fields() {
    let payload = object(json!({
        "session_id": "  s-1 ",
        "tool_name": "Bash",
        "message": "m",
        "tool_input": {"command": "ls"},
    }));
    let key = object(json!({"integrity_key_b64": "a2V5", "integrity_key_id": "k1"}));
    let built = request(
        "/g/guard.db",
        "/g",
        TURN_STOP,
        "2026-11-11T00:00:00+00:00",
        Some(&key),
        &payload,
    )
    .unwrap();
    assert_eq!(built.schema, "guard-hook-authority-state-request.v1");
    assert!(built.request_id.starts_with("hook-authority-state-"));
    assert_eq!(built.op, TURN_STOP);
    assert_eq!(built.integrity_key_b64.as_deref(), Some("a2V5"));
    assert_eq!(built.integrity_key_id.as_deref(), Some("k1"));
    assert_eq!(built.session_id.as_deref(), Some("s-1"));
    assert_eq!(
        built.payload,
        Some(json!({"session_id": "  s-1 ", "tool_name": "Bash", "message": "m"}))
    );
}

#[test]
fn a_blank_session_and_a_missing_key_are_left_out() {
    let payload = object(json!({"session_id": "   "}));
    let built = request("/g/guard.db", "/g", TURN_STOP, "now", None, &payload).unwrap();
    assert_eq!(built.session_id, None);
    assert_eq!(built.integrity_key_b64, None);
}
