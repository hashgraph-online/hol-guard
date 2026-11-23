//! How the relay answers a claim the authority refused.

use serde_json::json;

use super::refused_claim;
use crate::mcp_relay_authority::{no_decision_response, undecided_response};

fn message() -> serde_json::Value {
    json!({
        "jsonrpc": "2.0",
        "id": 9,
        "method": "tools/call",
        "params": {"name": "read_file", "arguments": {}},
    })
}

fn refusal(reason: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema": "guard-mcp-relay-decide-result.v1",
        "outcome": "defer",
        "reason": reason,
    }))
    .unwrap()
}

/// A claim refused for a version skew names the restart or repair, as a
/// refused decision does; any other refusal keeps the generic answer.
#[test]
fn a_refused_claim_names_a_version_skew() {
    let message = message();
    let params = message["params"].as_object().unwrap().clone();
    for cause in ["mcp_relay_runtime_superseded", "mcp_relay_store_newer"] {
        let answered = refusal(cause);
        assert_eq!(
            refused_claim(&message, Some(&answered)),
            undecided_response(message.get("id"), &params, cause)
        );
        assert_ne!(
            refused_claim(&message, Some(&answered)),
            no_decision_response(message.get("id"), &params)
        );
    }
    let answered = refusal("mcp_relay_package_claim_declined");
    assert_eq!(
        refused_claim(&message, Some(&answered)),
        no_decision_response(message.get("id"), &params)
    );
    assert_eq!(
        refused_claim(&message, None),
        no_decision_response(message.get("id"), &params)
    );
}
