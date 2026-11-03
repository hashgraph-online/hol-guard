//! Replays `entitlement_vectors.json`, recorded from the original Python
//! `build_oauth_package_firewall_entitlement`, through the native operation.

use serde_json::{json, Value};

use super::dispatch;
use crate::runner_authority_op::ERR_INVALID;

const VECTORS: &str =
    include_str!("../testdata/oauth_package_firewall_entitlement/entitlement_vectors.json");

#[test]
fn entitlements_match_the_python_vectors() {
    let vectors: Value = serde_json::from_str(VECTORS).expect("vectors");
    let cases = vectors.as_array().expect("cases");
    assert!(cases.len() > 40);
    for case in cases {
        let answer = dispatch(&case["request"]).expect("answer");
        assert_eq!(answer["entitlement"], case["expected"], "{}", case["label"]);
    }
}

#[test]
fn a_record_without_an_expiry_lasts_until_the_fallback() {
    let answer = dispatch(&json!({
        "record": {"tier": "team"},
        "fallback_expires_at": "2026-09-06T01:02:03.456789+00:00",
    }))
    .expect("answer");
    assert_eq!(
        answer,
        json!({"entitlement": {
            "plan_id": "team",
            "supply_chain_entitlement_expires_at": "2026-09-06T01:02:03.456789+00:00",
            "supply_chain_firewall": true,
            "supply_chain_plan_id": "team",
        }})
    );
}

#[test]
fn malformed_requests_are_refused() {
    let valid = json!({"record": {}, "fallback_expires_at": "2026-09-06T00:00:00+00:00"});
    assert_eq!(
        dispatch(&valid).expect("answer"),
        json!({"entitlement": null})
    );
    for request in [
        json!(null),
        json!([]),
        json!({"fallback_expires_at": "2026-09-06T00:00:00+00:00"}),
        json!({"record": {}}),
        json!({"record": null, "fallback_expires_at": "2026-09-06T00:00:00+00:00"}),
        json!({"record": [], "fallback_expires_at": "2026-09-06T00:00:00+00:00"}),
        json!({"record": {}, "fallback_expires_at": ""}),
        json!({"record": {}, "fallback_expires_at": 1}),
        json!({"record": {}, "fallback_expires_at": null}),
        json!({"record": {}, "fallback_expires_at": "x", "now": "x"}),
    ] {
        assert_eq!(dispatch(&request), Err(ERR_INVALID), "{request}");
    }
}
