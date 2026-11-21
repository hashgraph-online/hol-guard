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
