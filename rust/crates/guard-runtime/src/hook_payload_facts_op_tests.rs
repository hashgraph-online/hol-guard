use super::*;
use serde_json::json;

#[test]
fn event_aliases_are_normalized_by_the_resident() {
    let request = HookPayloadFactsRequestV1 {
        schema: "guard-hook-payload-facts-request.v1".to_owned(),
        request_id: "facts-1".to_owned(),
        payload: json!({"event": "before-shell-execution"}),
    };
    let output: Value = serde_json::from_slice(&evaluate(&request).expect("facts")).expect("json");
    assert_eq!(output["result"]["event_name"], "PreToolUse");
}

#[test]
fn copilot_permission_alias_preserves_the_raw_event_name() {
    let request = HookPayloadFactsRequestV1 {
        schema: "guard-hook-payload-facts-request.v1".to_owned(),
        request_id: "facts-copilot-permission".to_owned(),
        payload: json!({"event": "copilotPermissionRequest"}),
    };
    let output: Value = serde_json::from_slice(&evaluate(&request).expect("facts")).expect("json");
    assert_eq!(output["result"]["event_name"], "copilotPermissionRequest");
}

#[test]
fn python_control_strip_is_preserved() {
    let request = HookPayloadFactsRequestV1 {
        schema: "guard-hook-payload-facts-request.v1".to_owned(),
        request_id: "facts-2".to_owned(),
        payload: json!({"event": "\u{1c}PreToolUse\u{1c}"}),
    };
    let output: Value = serde_json::from_slice(&evaluate(&request).expect("facts")).expect("json");
    assert_eq!(output["result"]["event_name"], "PreToolUse");
}

#[test]
fn command_and_launch_facts_are_resident_owned() {
    let request = HookPayloadFactsRequestV1 {
        schema: "guard-hook-payload-facts-request.v1".to_owned(),
        request_id: "facts-3".to_owned(),
        payload: json!({
            "toolName": "Bash",
            "toolInput": {"command": "  echo hi  "}
        }),
    };
    let output: Value = serde_json::from_slice(&evaluate(&request).expect("facts")).expect("json");
    assert_eq!(output["result"]["command"], "  echo hi  ");
    assert_eq!(output["result"]["tool_name"], "Bash");
    assert_eq!(output["result"]["launch_target"], "  echo hi  ");
}

#[test]
fn oversized_tool_input_is_rejected_before_response_encoding() {
    let request = HookPayloadFactsRequestV1 {
        schema: "guard-hook-payload-facts-request.v1".to_owned(),
        request_id: "facts-large".to_owned(),
        payload: json!({"toolInput": {"command": "x".repeat(guard_contracts::MAX_NATIVE_RESPONSE_BYTES)}}),
    };
    assert_eq!(
        evaluate(&request).unwrap_err(),
        "hook_payload_facts_response_too_large"
    );
}
