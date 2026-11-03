//! Parity vectors recorded from Guard's Python prompt copy
//! (`scripts/record_claude_prompt_notice_vectors.py`).

use serde_json::{json, Value};

use super::{brand, HookDirectDefer};

const VECTORS: &str = include_str!("../tests/fixtures/claude_prompt_notice_vectors.json");

#[test]
fn the_notice_matches_the_daemon() {
    let document: Value = serde_json::from_str(VECTORS).unwrap();
    let vectors = document["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 273);
    for case in vectors {
        let name = case["name"].as_str().unwrap();
        let mut response = case["response"].clone();
        brand(&mut response, &case["result"]).unwrap_or_else(|error| panic!("{name}: {error:?}"));
        assert_eq!(response, case["expected"], "{name}");
    }
}

#[test]
fn a_reason_the_daemon_would_stringify_defers() {
    for reason in [
        json!(3),
        json!(true),
        json!(["reason"]),
        json!({ "text": "reason" }),
    ] {
        let mut response = json!({ "hookSpecificOutput": {} });
        let result = json!({ "minimum_action": "block", "reason": reason });
        assert_eq!(
            brand(&mut response, &result),
            Err(HookDirectDefer::PromptNotice),
            "{reason}"
        );
    }
}
