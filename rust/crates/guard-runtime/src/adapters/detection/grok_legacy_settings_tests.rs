//! Replays the Grok legacy-settings vectors recorded from the original Python
//! (see `testdata/grok/record_grok_legacy_settings_vectors.py`).

use serde_json::{json, Value};

use super::grok_legacy_settings::dispatch;
use super::runner_authority_op::ERR_INVALID;

const VECTORS: &str = include_str!("../../../testdata/grok/legacy_settings_vectors.json");

#[test]
fn replays_every_recorded_legacy_settings_case() {
    let document: Value = serde_json::from_str(VECTORS).expect("vectors parse");
    let cases = document["cases"].as_array().expect("cases");
    assert_eq!(cases.len(), 36);
    for case in cases {
        let answer = dispatch(&case["request"]).expect("request accepted");
        assert_eq!(answer, json!({ "text": case["text"] }), "{}", case["name"]);
    }
}

#[test]
fn malformed_requests_are_refused() {
    let requests = [
        json!([]),
        json!({ "text": "x" }),
        json!({ "text": 1, "prior_compat_hooks": [] }),
        json!({ "text": "x", "prior_compat_hooks": {} }),
        json!({ "text": "x", "prior_compat_hooks": [["claude"]] }),
        json!({ "text": "x", "prior_compat_hooks": [[1, "true"]] }),
        json!({ "text": "x", "prior_compat_hooks": ["claude"] }),
        json!({ "text": "x", "prior_compat_hooks": [], "extra": true }),
    ];
    for request in requests {
        assert_eq!(dispatch(&request), Err(ERR_INVALID), "{request}");
    }
}
