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
