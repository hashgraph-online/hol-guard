use super::*;
use serde_json::json;

#[test]
fn availability_is_resident_owned() {
    let mut req = request("availability");
    req.cli = Some(json!({"payload": {"hook_event_name": "copilotPermissionRequest"}}));
    let response = decode(evaluate_hook_render_request(&req).expect("encoded"))
        .payload
        .expect("payload")["response"]
        .clone();
    assert_eq!(response["event_name"], "PermissionRequest");
    assert_eq!(response["pauses"], true);
    assert_eq!(response["permission_request"], true);

    req.cli = Some(json!({"payload": {"hook_event_name": "PostToolUse"}}));
    let response = decode(evaluate_hook_render_request(&req).expect("encoded"))
        .payload
        .expect("payload")["response"]
        .clone();
    assert_eq!(response["pauses"], false);

    req.cli = Some(json!({"payload": {"hook_event_name": "SubagentEnd"}}));
    let response = decode(evaluate_hook_render_request(&req).expect("encoded"))
        .payload
        .expect("payload")["response"]
        .clone();
    assert_eq!(response["event_name"], "SubagentEnd");
    assert_eq!(response["pauses"], false);
}

#[test]
fn structured_outage_uses_the_native_renderer_with_an_unreadable_view() {
    let mut req = request("structured_outage");
    req.harness = "oh_my_pi".into();
    req.cli = Some(json!({"event_name": "PostToolUse", "view": {}}));
    let response = decode(evaluate_hook_render_request(&req).expect("encoded"));
    assert_eq!(response.status, "ok");
    let response = response.payload.expect("payload");
    assert_eq!(response["outcome"], "document");
    assert_eq!(
        response["response"]["structured_content_mediation"]["reason_code"],
        "structured_native_edge_unavailable"
    );
}

#[test]
fn availability_response_uses_the_contract_envelope() {
    let mut req = request("availability_response");
    req.harness = "cursor".into();
    req.cli = Some(json!({
        "event_name": "PreToolUse",
        "reason": "Native review unavailable.",
        "reason_code": "native_pre_tool_unavailable",
    }));
    let response = decode(evaluate_hook_render_request(&req).expect("encoded"));
    assert_eq!(response.status, "ok");
    let response = response.payload.expect("payload");
    assert_eq!(response["outcome"], "document");
    assert_eq!(
        response["response"]["hookSpecificOutput"]["permissionDecision"],
        "deny"
    );
    assert_eq!(
        response["response"]["reason_code"],
        "native_pre_tool_unavailable"
    );
}

#[test]
fn unavailable_event_projects_aliases_and_permission_passthrough_in_rust() {
    let mut req = request("unavailable_event");
    req.harness = "copilot".into();
    req.cli = Some(json!({
        "payload": {"hook_event_name": "copilotPermissionRequest"},
        "record_post_tool_activity": false,
    }));
    let response = decode(evaluate_hook_render_request(&req).expect("encoded"));
    let document = response.payload.expect("payload");
    assert_eq!(document["outcome"], "document");
    assert_eq!(document["response"]["event_name"], "PermissionRequest");
    assert_eq!(
        document["response"]["response"]["hookSpecificOutput"]["hookEventName"],
        "PermissionRequest"
    );
}

#[test]
fn unavailable_event_denies_pre_tool_and_preserves_post_tool_activity_marker() {
    let mut req = request("unavailable_event");
    req.harness = "cursor".into();
    req.cli = Some(json!({
        "payload": {"hook_event_name": "PreToolUse"},
        "record_post_tool_activity": true,
    }));
    let response = decode(evaluate_hook_render_request(&req).expect("encoded"));
    let document = response.payload.expect("payload")["response"].clone();
    assert_eq!(document["event_name"], "PreToolUse");
    assert_eq!(document["activity_recorded"], false);
    assert_eq!(
        document["response"]["hookSpecificOutput"]["permissionDecision"],
        "deny"
    );
}
#[test]
fn fail_closed_verdict_uses_the_rust_contract_envelope() {
    let mut req = request("fail_closed_verdict");
    req.harness = "pi".into();
    req.cli = Some(json!({
        "verdict": {
            "decision": "allow",
            "minimum_action": "allow",
            "policy_action": "allow",
        }
    }));
    let response = decode(evaluate_hook_render_request(&req).expect("encoded"));
    assert_eq!(response.status, "ok");
    let response = response.payload.expect("payload");
    assert_eq!(response["outcome"], "document");
    assert_eq!(response["response"]["decision"], "deny");
    assert_eq!(response["response"]["policy_action"], "block");
    assert_eq!(
        response["response"]["reason_code"],
        "native_hook_render_unavailable"
    );
}

#[test]
fn fail_closed_verdict_trims_reason_fields_like_the_python_adapter() {
    let mut req = request("fail_closed_verdict");
    req.harness = "cursor".into();
    req.cli = Some(json!({
        "verdict": {
            "decision": "deny",
            "minimum_action": "block",
            "reason": "  blocked  ",
            "reason_code": " native_block ",
        }
    }));
    let response = decode(evaluate_hook_render_request(&req).expect("encoded"));
    let response = response.payload.expect("payload")["response"].clone();
    assert_eq!(
        response["hookSpecificOutput"]["permissionDecisionReason"],
        "blocked"
    );
    assert_eq!(response["reason_code"], "native_block");
}
