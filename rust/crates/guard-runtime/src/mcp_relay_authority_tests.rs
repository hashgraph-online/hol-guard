use serde_json::{json, Map, Value};

use super::{no_decision_response, undecided_response, NO_DECISION, VERSION_SKEW};

fn call() -> (Value, Map<String, Value>) {
    let params = json!({ "name": "read_file", "arguments": {} });
    let id = json!(7);
    (id, params.as_object().cloned().unwrap())
}

fn text(response: &Value) -> &str {
    response["error"]["message"].as_str().unwrap_or_default()
}

#[test]
fn version_skew_is_refused_with_its_repair() {
    let (id, params) = call();
    for cause in ["mcp_relay_runtime_superseded", "mcp_relay_store_newer"] {
        let response = undecided_response(Some(&id), &params, cause);
        assert_eq!(text(&response), VERSION_SKEW);
        assert!(text(&response).contains("hol-guard repair"), "{response}");
        assert_eq!(response["id"], id);
        assert_eq!(response["error"]["data"]["guardPolicyAction"], "block");
    }
}

#[test]
fn any_other_cause_keeps_the_generic_refusal() {
    let (id, params) = call();
    for cause in [
        "mcp_relay_resident_unreachable",
        "direct_lane_unbound",
        "mcp_relay_a_code_added_later",
    ] {
        let response = undecided_response(Some(&id), &params, cause);
        assert_eq!(response, no_decision_response(Some(&id), &params));
        assert_eq!(text(&response), NO_DECISION);
    }
}
