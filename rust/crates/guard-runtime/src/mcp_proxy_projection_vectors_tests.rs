//! Replays `call_projection` vectors recorded from the Python MCP proxy
//! helpers this op replaced (see the recorder beside the fixture).

use guard_contracts::McpProxyQueryV1;
use serde_json::Value;

use crate::mcp_proxy_decision_op::evaluate_query;

const VECTORS: &str =
    include_str!("../../../../tests/fixtures/mcp_proxy_decision/call_projection_vectors.json");

#[test]
fn call_projection_matches_recorded_python_vectors() {
    let document: Value = serde_json::from_str(VECTORS).unwrap();
    let vectors = document["vectors"].as_array().unwrap();
    assert!(vectors.len() >= 35, "only {} vectors", vectors.len());
    for vector in vectors {
        let label = vector["label"].as_str().unwrap();
        let query: McpProxyQueryV1 = serde_json::from_value(vector["query"].clone())
            .unwrap_or_else(|error| panic!("{label}: {error}"));
        let actual = match evaluate_query(&query) {
            Ok(payload) => payload,
            Err(code) => serde_json::json!({"error": code}),
        };
        assert_eq!(actual, vector["expected"], "{label}");
    }
}
