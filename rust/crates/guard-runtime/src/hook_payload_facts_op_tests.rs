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
