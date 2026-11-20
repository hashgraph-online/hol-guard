use serde_json::{json, Value};

use super::dispatch;
use crate::runner_authority_op::ERR_INVALID;

fn ask(candidate: Value, stored_legacy: Value, existing: Value) -> Value {
    dispatch(&json!({
        "candidate": candidate,
        "stored_legacy": stored_legacy,
        "existing": existing,
    }))
    .expect("answer")
}

fn v2(issued_at: Value) -> Value {
    json!({"contractVersion": "guard-policy-bundle.v2", "issuedAt": issued_at})
}

fn v1(issued_at: Value) -> Value {
    json!({"contractVersion": "guard-policy-bundle.v1", "issuedAt": issued_at})
}

#[test]
fn the_stored_legacy_bundle_is_the_shadow_before_the_active_one() {
    let answer = ask(
        v2(json!("2026-11-20T10:00:00+00:00")),
        v1(json!("2026-11-20T10:00:00Z")),
        v1(json!("2026-11-20T09:00:00Z")),
    );
    assert_eq!(answer, json!({"legacy": "stored", "evaluating": false}));
}

#[test]
fn an_active_v1_bundle_stands_in_when_nothing_is_stored() {
    let candidate = v2(json!("2026-11-20T10:00:00Z"));
    assert_eq!(
        ask(candidate.clone(), json!(null), v1(json!(null)))["legacy"],
        json!("existing")
    );
    assert_eq!(
        ask(candidate.clone(), json!(null), json!({}))["legacy"],
        json!("existing")
    );
    assert_eq!(
        ask(candidate.clone(), json!(null), v2(json!(null)))["legacy"],
        Value::Null
    );
    assert_eq!(
        ask(candidate, json!(null), json!(null))["legacy"],
        Value::Null
    );
}

#[test]
fn a_shadow_issued_before_the_candidate_is_dropped() {
    let answer = ask(
        v2(json!("2026-11-20T10:00:00.000001Z")),
        v1(json!("2026-11-20T10:00:00Z")),
        v1(json!("2026-11-20T11:00:00Z")),
    );
    assert_eq!(answer["legacy"], Value::Null);
    let naive_is_utc = ask(
        v2(json!("2026-11-20T11:00:00+01:00")),
        v1(json!("2026-11-20T10:00:00")),
        json!(null),
    );
    assert_eq!(naive_is_utc["legacy"], json!("stored"));
    let compact = ask(
        v2(json!("20261120T100000Z")),
        v1(json!("20261119T100000Z")),
        json!(null),
    );
    assert_eq!(compact["legacy"], Value::Null);
}

#[test]
fn unreadable_issue_times_keep_the_comparison() {
    for (legacy, candidate) in [
        (json!("yesterday"), json!("2026-11-20T10:00:00Z")),
        (json!("2026-11-19T10:00:00Z"), json!("")),
        (json!(0), json!("2026-11-20T10:00:00Z")),
        (json!(null), json!("2026-11-20T10:00:00Z")),
    ] {
        let answer = ask(v2(candidate), v1(legacy), json!(null));
        assert_eq!(answer["legacy"], json!("stored"));
    }
}

#[test]
fn an_observe_default_marks_the_candidate_as_evaluating() {
    let mut candidate = v2(json!(null));
    candidate["payload"] = json!({"spec": {"defaults": {"mode": "observe"}}});
    assert_eq!(
        ask(candidate.clone(), json!(null), json!(null))["evaluating"],
        json!(true)
    );
    candidate["payload"] = json!({"spec": {"defaults": {"mode": "enforce"}}});
    assert_eq!(
        ask(candidate.clone(), json!(null), json!(null))["evaluating"],
        json!(false)
    );
    candidate["payload"] = json!({"spec": ["observe"]});
    assert_eq!(
        ask(candidate, json!(null), json!(null))["evaluating"],
        json!(false)
    );
}

#[test]
fn malformed_requests_are_refused() {
    assert_eq!(dispatch(&json!("not-an-object")), Err(ERR_INVALID));
    assert_eq!(
        dispatch(&json!({"candidate": [], "stored_legacy": null, "existing": null})),
        Err(ERR_INVALID)
    );
    assert_eq!(
        dispatch(&json!({"candidate": {}, "stored_legacy": "bundle", "existing": null})),
        Err(ERR_INVALID)
    );
    assert_eq!(
        dispatch(&json!({"candidate": {}, "stored_legacy": null, "existing": null, "extra": 1})),
        Err(ERR_INVALID)
    );
}
