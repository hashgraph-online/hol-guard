//! Version 2 saved consent scopes.

use super::v2::{assert_v2, fact_rule, facts, v2_request};
use super::*;
use crate::cloud_action_v2_consent::consent_selector_digest;
use guard_contracts::FactSelectorV2;

fn bounded(consent_id: &str, kind: &str, action_id: &str, selector: Value) -> Value {
    let parsed: FactSelectorV2 = serde_json::from_value(selector.clone()).unwrap();
    json!({"consent_id": consent_id, "kind": kind, "scope": {"bounded": {
        "action_id": action_id, "connection_id": "conn-synthetic-1", "selector": selector,
        "selector_sha256": consent_selector_digest(&parsed).unwrap()}}})
}

fn resource(consent_id: &str, kind: &str, action_id: &str, resource_id: &str) -> Value {
    json!({"consent_id": consent_id, "kind": kind, "scope": {"resource": {
        "action_id": action_id, "connection_id": "conn-synthetic-1", "resource_id": resource_id}}})
}

fn archive_request(evaluator: &CloudActionEvaluator) -> Value {
    let mut request = v2_request(evaluator);
    set_action(&mut request, ARCHIVE, json!({"channel": "C0SYNTH01"}));
    request["facts"] = facts("delete");
    request
}

#[test]
fn resource_consent_covers_the_same_resource_only() {
    let evaluator = evaluator();
    let mut request = v2_request(&evaluator);
    request["saved_consents"] = json!([resource("c-res", "always", POST, "C0SYNTH01")]);
    let result = run(&evaluator, &request);
    assert_v2(&result);
    assert_eq!(result["action"], "allow");
    assert_eq!(result["consent_scope"], "resource");
    assert_eq!(result["consent_applied"], "always");

    set_action(
        &mut request,
        POST,
        json!({"channel": "C0OTHER01", "text": "hi"}),
    );
    let other = run(&evaluator, &request);
    assert_eq!(other["action"], "review");
    assert_eq!(other["consent_applied"], "none");
}

#[test]
fn bounded_consent_covers_equivalent_calls_and_nothing_wider_or_unknown() {
    let evaluator = evaluator();
    let mut request = archive_request(&evaluator);
    request["saved_consents"] = json!([bounded(
        "c-b",
        "always",
        ARCHIVE,
        json!({"max_record_count": 25})
    )]);
    let covered = run(&evaluator, &request);
    assert_eq!(covered["action"], "allow", "{covered}");
    assert_eq!(covered["consent_scope"], "bounded");

    let mut wider = request.clone();
    wider["facts"]["record_count"] = json!({"state": "known", "value": 40});
    assert_eq!(run(&evaluator, &wider)["action"], "require-reapproval");

    let mut unknown = request.clone();
    unknown["facts"]["record_count"] = json!({"state": "unknown"});
    unknown["facts"]["scope"] = json!({"state": "unknown"});
    assert_eq!(run(&evaluator, &unknown)["action"], "require-reapproval");

    let mut other_action = request.clone();
    other_action["saved_consents"] = json!([bounded(
        "c-b",
        "always",
        POST,
        json!({"max_record_count": 25})
    )]);
    assert_eq!(
        run(&evaluator, &other_action)["action"],
        "require-reapproval"
    );
}

#[test]
fn broad_scopes_do_not_answer_a_permanent_or_unknown_reapproval() {
    let evaluator = evaluator();
    let mut request = archive_request(&evaluator);
    let identity = run(&evaluator, &request)["action_identity_sha256"]
        .as_str()
        .unwrap()
        .to_owned();
    request["saved_consents"] = json!([
        bounded("c-b", "always", ARCHIVE, json!({"max_record_count": 25})),
        resource("c-r", "always", ARCHIVE, "C0SYNTH01"),
    ]);
    for reversibility in [
        json!({"state": "known", "value": "permanent"}),
        json!({"state": "unknown"}),
    ] {
        request["facts"]["reversibility"] = reversibility;
        let held = run(&evaluator, &request);
        assert_eq!(held["action"], "require-reapproval", "{held}");
        assert_eq!(held["consent_options"].as_array().unwrap().len(), 2);
    }
    // Exact consent still answers it, as in version 1.
    request["saved_consents"] = json!([{"consent_id": "c-x", "kind": "always",
        "scope": {"exact": {"action_identity_sha256": identity}}}]);
    let exact = run(&evaluator, &request);
    assert_eq!(exact["action"], "allow");
    assert_eq!(exact["consent_scope"], "exact");
}

#[test]
fn consent_never_beats_a_block() {
    let evaluator = evaluator();
    let mut request = archive_request(&evaluator);
    let identity = run(&evaluator, &request)["action_identity_sha256"]
        .as_str()
        .unwrap()
        .to_owned();
    request["policy"]["fact_rules"] = json!([fact_rule(
        "no-deletes",
        "block",
        json!({"classes": ["delete"]})
    )]);
    request["saved_consents"] = json!([
        bounded("c-b", "always", ARCHIVE, json!({"max_record_count": 25})),
        resource("c-r", "always", ARCHIVE, "C0SYNTH01"),
        {"consent_id": "c-x", "kind": "always", "scope": {"exact": {"action_identity_sha256": identity}}},
    ]);
    let result = run(&evaluator, &request);
    assert_eq!(result["action"], "block");
    assert_eq!(result["consent_applied"], "none");
    assert_eq!(result["review_eligible"], false);
}

#[test]
fn every_review_offers_allow_once_and_always_allow() {
    let evaluator = evaluator();
    let review = run(&evaluator, &v2_request(&evaluator));
    assert_eq!(review["action"], "review");
    assert_eq!(review["review_eligible"], true);
    let options = review["consent_options"].as_array().unwrap();
    for kind in ["once", "always"] {
        assert!(
            options.contains(&json!({"kind": kind, "scope": "exact"})),
            "{review}"
        );
        assert!(
            options.contains(&json!({"kind": kind, "scope": "resource"})),
            "{review}"
        );
    }
    let reapproval = run(&evaluator, &archive_request(&evaluator));
    assert_eq!(reapproval["review_eligible"], true);
    let options = reapproval["consent_options"].as_array().unwrap();
    for kind in ["once", "always"] {
        assert!(
            options.contains(&json!({"kind": kind, "scope": "exact"})),
            "{reapproval}"
        );
    }
}

#[test]
fn a_tampered_bounded_selector_is_refused() {
    let evaluator = evaluator();
    let mut request = archive_request(&evaluator);
    let mut consent = bounded("c-b", "always", ARCHIVE, json!({"max_record_count": 25}));
    consent["scope"]["bounded"]["selector"]["max_record_count"] = 2500.into();
    request["saved_consents"] = json!([consent]);
    assert_eq!(
        run(&evaluator, &request)["error"]["code"],
        "invalid_request"
    );
    request["saved_consents"] = json!([{"consent_id": "c", "kind": "always",
        "scope": {"exact": {"action_identity_sha256": "0".repeat(64)}, "extra": 1}}]);
    assert_eq!(
        run(&evaluator, &request)["error"]["code"],
        "invalid_request"
    );
}
