//! Replays the Kimi hook-config vectors recorded from the original Python
//! (see `testdata/kimi/record_kimi_hook_config_vectors.py`).

use serde_json::{json, Value};

use super::kimi_hook_config::dispatch;
use super::runner_authority_op::ERR_INVALID;

const VECTORS: &str = include_str!("../../../testdata/kimi/hook_config_vectors.json");

#[test]
fn replays_every_recorded_hook_config_case() {
    let document: Value = serde_json::from_str(VECTORS).expect("vectors parse");
    let cases = document["cases"].as_array().expect("cases");
    assert_eq!(cases.len(), 44);
    for case in cases {
        let answer = dispatch(&case["request"]).expect("request accepted");
        assert_eq!(answer, json!({ "text": case["text"] }), "{}", case["name"]);
    }
}

#[test]
fn malformed_requests_are_refused() {
    let requests = [
        json!([]),
        json!({ "op": "install", "text": "x" }),
        json!({ "op": "install", "text": "x", "hook_command": 1 }),
        json!({ "op": "install", "text": 1, "hook_command": "c" }),
        json!({ "op": "uninstall", "text": "x", "hook_command": "c" }),
        json!({ "op": "uninstall" }),
        json!({ "op": "remove", "text": "x" }),
        json!({ "text": "x" }),
    ];
    for request in requests {
        assert_eq!(dispatch(&request), Err(ERR_INVALID), "{request}");
    }
}
