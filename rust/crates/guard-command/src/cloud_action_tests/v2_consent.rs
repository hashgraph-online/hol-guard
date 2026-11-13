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

fn bounded_offers(result: &Value) -> Vec<Value> {
    result["consent_options"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|option| option["scope"] == "bounded")
        .cloned()
        .collect()
}

fn save_offer(offer: &Value, action_id: &str) -> Value {
    json!({"consent_id": "c-offer", "kind": offer["kind"], "scope": {"bounded": {
        "action_id": action_id, "connection_id": "conn-synthetic-1",
        "selector": offer["selector"], "selector_sha256": offer["selector_sha256"]}}})
}

#[test]
fn a_review_offers_bounded_always_allow_that_covers_equivalent_calls_only() {
    let evaluator = evaluator();
    let mut request = archive_request(&evaluator);
    let review = run(&evaluator, &request);
    assert_eq!(review["action"], "require-reapproval", "{review}");
    let offers = bounded_offers(&review);
    let bounds: Vec<_> = offers
        .iter()
        .map(|offer| offer["selector"]["max_record_count"].clone())
        .collect();
    assert_eq!(bounds, vec![json!(25), json!(50)], "{review}");
    assert_eq!(
        offers[0]["selector"],
        json!({"providers": ["slack"], "classes": ["delete"], "objects": ["message"],
               "reversibility": ["recoverable"], "max_record_count": 25})
    );
    assert!(offers.iter().all(|offer| offer["kind"] == "always"));

    request["saved_consents"] = json!([save_offer(&offers[0], ARCHIVE)]);
    let mut equivalent = request.clone();
    equivalent["facts"]["record_count"] = json!({"state": "known", "value": 25});
    let silenced = run(&evaluator, &equivalent);
    assert_eq!(silenced["action"], "allow", "{silenced}");
    assert_eq!(silenced["consent_scope"], "bounded");

    let mut larger = request.clone();
    larger["facts"]["record_count"] = json!({"state": "known", "value": 200});
    let held = run(&evaluator, &larger);
    assert_eq!(held["action"], "require-reapproval", "{held}");
    assert_eq!(held["consent_applied"], "none");
}

#[test]
fn bounded_offers_need_known_bounding_facts() {
    let evaluator = evaluator();
    let mut request = archive_request(&evaluator);
    for (pointer, fact) in [
        ("record_count", json!({"state": "unknown"})),
        ("object", json!({"state": "unknown"})),
        ("record_count", json!({"state": "known", "value": 1001})),
    ] {
        let mut changed = request.clone();
        changed["facts"][pointer] = fact;
        if pointer == "record_count" {
            changed["facts"]["scope"] = json!({"state": "unknown"});
        }
        assert!(bounded_offers(&run(&evaluator, &changed)).is_empty());
    }
    request["facts"]["reversibility"] = json!({"state": "known", "value": "permanent"});
    assert!(bounded_offers(&run(&evaluator, &request)).is_empty());
}

#[test]
fn tainted_sessions_are_answered_only_by_exact_consent() {
    let evaluator = evaluator();
    let mut archive = archive_request(&evaluator);
    let identity = run(&evaluator, &archive)["action_identity_sha256"].clone();
    archive["saved_consents"] = json!([
        bounded("c-b", "always", ARCHIVE, json!({"max_record_count": 25})),
        resource("c-r", "always", ARCHIVE, "C0SYNTH01"),
    ]);
    assert_eq!(run(&evaluator, &archive)["action"], "allow");
    archive["session_flow"]["injection_signal_seen"] = true.into();
    let held = run(&evaluator, &archive);
    assert_eq!(held["action"], "require-reapproval", "{held}");
    assert!(bounded_offers(&held).is_empty());
    assert_eq!(held["consent_options"].as_array().unwrap().len(), 2);
    archive["saved_consents"] = json!([{"consent_id": "c-x", "kind": "always",
        "scope": {"exact": {"action_identity_sha256": identity}}}]);
    assert_eq!(run(&evaluator, &archive)["action"], "allow");

    // An outbound call after untrusted content, or with no journal at all.
    let mut send = v2_request(&evaluator);
    send["saved_consents"] = json!([resource("c-r", "always", POST, "C0SYNTH01")]);
    assert_eq!(run(&evaluator, &send)["action"], "allow");
    let mut untrusted = send.clone();
    untrusted["session_flow"]["untrusted_content_seen"] = true.into();
    assert_eq!(run(&evaluator, &untrusted)["action"], "review");
    let mut unjournaled = send.clone();
    unjournaled["session_flow"] = Value::Null;
    assert_eq!(run(&evaluator, &unjournaled)["action"], "review");
    // A delete after untrusted content stays answerable by its bounded consent.
    let mut delete = archive_request(&evaluator);
    delete["session_flow"]["untrusted_content_seen"] = true.into();
    delete["saved_consents"] = json!([bounded(
        "c-b",
        "always",
        ARCHIVE,
        json!({"max_record_count": 25})
    )]);
    assert_eq!(run(&evaluator, &delete)["action"], "allow");
}

#[test]
fn bounded_offers_never_reach_outside_or_bound_a_payment() {
    let evaluator = evaluator();
    let base = archive_request(&evaluator);
    let with = |class: &str, external: Value| {
        let mut request = base.clone();
        request["facts"]["class"] = class.into();
        request["facts"]["audience"]["kind"] = json!({"state": "unknown"});
        request["facts"]["audience"]["external"] = external;
        request["facts"]["audience"]["recipient_domains"] =
            json!({"state": "known", "value": ["example.org"]});
        request["facts"]["recipient_count"] = json!({"state": "known", "value": 3});
        run(&evaluator, &request)
    };
    let known = |value: bool| json!({"state": "known", "value": value});
    let unknown = json!({"state": "unknown"});

    // A send known to reach outside, and an update or execute that might.
    for (class, external) in [
        ("send", known(true)),
        ("share", known(true)),
        ("update", unknown.clone()),
        ("execute", unknown.clone()),
        ("send", unknown.clone()),
        ("delete", known(true)),
    ] {
        let review = with(class, external.clone());
        assert_eq!(review["action"], "require-reapproval", "{class}: {review}");
        assert!(bounded_offers(&review).is_empty(), "{class} {external}: {review}");
    }
    // No selector bounds an amount, so a payment gets none even when internal.
    let mut pay = base.clone();
    pay["facts"]["class"] = "pay".into();
    pay["facts"]["audience"]["kind"] = json!({"state": "unknown"});
    pay["facts"]["audience"]["external"] = known(false);
    pay["facts"]["money"] = json!({"state": "known", "value": {"amount_minor": 500, "currency": "USD", "direction": "out"}});
    let paid = run(&evaluator, &pay);
    assert_eq!(paid["action"], "require-reapproval", "{paid}");
    assert!(bounded_offers(&paid).is_empty(), "{paid}");

    // Known to stay inside: every offer pins `external: false`.
    for class in ["send", "update"] {
        let offers = bounded_offers(&with(class, known(false)));
        assert!(!offers.is_empty(), "{class}");
        assert!(offers.iter().all(|offer| offer["selector"]["external"] == false), "{offers:?}");
    }
}
