//! Saved consent and action identity.

use super::*;

// ---- saved consent ----

#[test]
fn an_exact_saved_consent_turns_review_into_allow() {
    let evaluator = evaluator();
    let mut request = request_for(&evaluator);
    let identity = identity_of(&evaluator, &request);
    for (kind, reason) in [
        ("once", "saved_consent_once"),
        ("always", "saved_consent_always"),
    ] {
        request["saved_consents"] = json!([consent("consent-1", kind, &identity)]);
        let result = run(&evaluator, &request);
        assert_success(&result);
        assert_eq!(result["action"], "allow", "{kind}");
        assert_eq!(result["dispatch_permitted"], true, "{kind}");
        assert_eq!(result["consent_applied"], kind);
        assert_eq!(result["consent_id"], "consent-1");
        assert_eq!(result["review_eligible"], false);
        assert_eq!(result["reason_codes"], json!(["effect_floor", reason]));
        assert_eq!(result["action_identity_sha256"], identity.as_str());
    }
}

#[test]
fn an_exact_saved_consent_also_answers_require_reapproval() {
    let evaluator = evaluator();
    let mut request = request_for(&evaluator);
    set_action(&mut request, ARCHIVE, json!({"channel": "C0SYNTH01"}));
    let pending = run(&evaluator, &request);
    assert_eq!(pending["action"], "require-reapproval");
    assert_eq!(pending["review_eligible"], true);
    let identity = pending["action_identity_sha256"].as_str().unwrap();
    request["saved_consents"] = json!([consent("consent-1", "once", identity)]);
    let result = run(&evaluator, &request);
    assert_eq!(result["action"], "allow");
    assert_eq!(result["consent_applied"], "once");
}

#[test]
fn an_always_consent_is_reported_ahead_of_a_once_consent() {
    let evaluator = evaluator();
    let mut request = request_for(&evaluator);
    let identity = identity_of(&evaluator, &request);
    for consents in [
        json!([
            consent("once-1", "once", &identity),
            consent("always-1", "always", &identity)
        ]),
        json!([
            consent("always-1", "always", &identity),
            consent("once-1", "once", &identity)
        ]),
    ] {
        request["saved_consents"] = consents;
        let result = run(&evaluator, &request);
        assert_eq!(result["consent_applied"], "always");
        assert_eq!(result["consent_id"], "always-1");
    }
}

#[test]
fn a_consent_for_a_different_identity_does_not_apply() {
    let evaluator = evaluator();
    let mut request = request_for(&evaluator);
    request["saved_consents"] = json!([
        consent("consent-1", "always", &"0".repeat(64)),
        consent("consent-2", "once", &"f".repeat(64)),
    ]);
    let result = run(&evaluator, &request);
    assert_success(&result);
    assert_eq!(result["action"], "review");
    assert_eq!(result["dispatch_permitted"], false);
    assert_eq!(result["consent_applied"], "none");
    assert_eq!(result["review_eligible"], true);
}

#[test]
fn any_change_to_the_action_changes_its_identity_and_voids_the_consent() {
    let evaluator = evaluator();
    let base = request_for(&evaluator);
    let identity = identity_of(&evaluator, &base);
    let edits: [(&str, Edit); 7] = [
        ("argument value", |r| {
            r["action"]["arguments"]["text"] = "goodbye".into()
        }),
        ("added argument", |r| {
            r["action"]["arguments"]["thread"] = "T1".into()
        }),
        ("resource", |r| {
            r["action"]["arguments"]["channel"] = "C0SYNTH02".into()
        }),
        ("account_digest", |r| {
            r["connection"]["account_digest"] = "2".repeat(64).into();
        }),
        ("connection", |r| {
            r["connection"]["connection_id"] = "conn-synthetic-2".into()
        }),
        ("workspace", |r| {
            r["principal"]["workspace_id"] = "ws-synthetic-2".into()
        }),
        ("action", |r| {
            r["action"]["action_id"] = ARCHIVE.into();
        }),
    ];
    for (name, edit) in edits {
        let mut request = base.clone();
        edit(&mut request);
        let changed = identity_of(&evaluator, &request);
        assert_ne!(changed, identity, "{name}");
        request["saved_consents"] = json!([consent("consent-1", "always", &identity)]);
        let result = run(&evaluator, &request);
        assert_success(&result);
        assert_ne!(result["action"], "allow", "{name}");
        assert_eq!(result["consent_applied"], "none", "{name}");
    }
}

#[test]
fn identity_ignores_who_asks_and_how_the_arguments_are_spelled() {
    let evaluator = evaluator();
    let base = request_for(&evaluator);
    let identity = identity_of(&evaluator, &base);
    let mut other_caller = base.clone();
    other_caller["principal"]["subject_id"] = "subject-synthetic-2".into();
    other_caller["principal"]["client_grant_id"] = "grant-synthetic-2".into();
    other_caller["request_id"] = "req-0002".into();
    other_caller["evaluated_at"] = "2026-11-01T12:30:00Z".into();
    assert_eq!(identity_of(&evaluator, &other_caller), identity);

    let reordered = line_with_raw_arguments(
        &base,
        "{ \"text\" : \"hello\",\n \"channel\" : \"C0SYNTH01\" }",
    );
    let result = evaluator.evaluate(reordered.as_bytes());
    assert_success(&result);
    assert_eq!(result["action_identity_sha256"], identity.as_str());
}

#[test]
fn a_changed_binding_changes_the_execution_identity() {
    let evaluator = evaluator();
    let mut changed: Value = serde_json::from_str(BINDINGS).unwrap();
    changed["bindings"][1]["adapter"]["identity"] = "connector:slack-synthetic-v2".into();
    let other = CloudActionEvaluator::new(
        load_binding_set(changed.to_string().as_bytes()).unwrap(),
        None,
    );
    assert_ne!(other.binding_set_digest(), evaluator.binding_set_digest());
    let before = run(&evaluator, &request_for(&evaluator));
    let after = run(&other, &request_for(&other));
    assert_ne!(
        before["execution_identity_digest"],
        after["execution_identity_digest"]
    );
    assert_ne!(
        before["action_identity_sha256"],
        after["action_identity_sha256"]
    );
    // A binding that did not change keeps its identity.
    let mut list = request_for(&evaluator);
    set_action(&mut list, LIST, json!({}));
    let mut list_other = request_for(&other);
    set_action(&mut list_other, LIST, json!({}));
    assert_eq!(
        run(&evaluator, &list)["execution_identity_digest"],
        run(&other, &list_other)["execution_identity_digest"]
    );
}

#[test]
fn consent_never_lowers_a_block() {
    let evaluator = evaluator();
    let mut request = request_for(&evaluator);
    let identity = identity_of(&evaluator, &request);
    request["saved_consents"] = json!([
        consent("once-1", "once", &identity),
        consent("always-1", "always", &identity),
    ]);
    request["policy"]["rules"] = json!([rule("block-post", "block", POST)]);
    let result = run(&evaluator, &request);
    assert_success(&result);
    assert_eq!(result["action"], "block");
    assert_eq!(result["dispatch_permitted"], false);
    assert_eq!(result["consent_applied"], "none");
    assert_eq!(result["review_eligible"], false);

    let mut admin = request_for(&evaluator);
    set_action(&mut admin, TRANSFER, json!({"user": "U0SYNTH01"}));
    let admin_identity = identity_of(&evaluator, &admin);
    admin["saved_consents"] = json!([consent("always-1", "always", &admin_identity)]);
    admin["policy"]["rules"] = json!([rule("allow-all", "allow", "*")]);
    let result = run(&evaluator, &admin);
    assert_eq!(result["action"], "block");
    assert_eq!(result["consent_applied"], "none");
}

#[test]
fn consent_does_not_change_a_rule_that_already_allows() {
    let evaluator = evaluator();
    let mut request = request_for(&evaluator);
    set_action(&mut request, LIST, json!({}));
    let identity = identity_of(&evaluator, &request);
    request["saved_consents"] = json!([consent("consent-1", "always", &identity)]);
    let result = run(&evaluator, &request);
    assert_eq!(result["action"], "allow");
    assert_eq!(result["consent_applied"], "none");
    assert_eq!(result["reason_codes"], json!(["effect_floor"]));
}

#[test]
fn saved_consents_are_bounded_and_shaped() {
    let evaluator = evaluator();
    let mut request = request_for(&evaluator);
    request["saved_consents"] = Value::Array(
        (0..=MAX_SAVED_CONSENTS)
            .map(|i| consent(&format!("c{i}"), "once", &"a".repeat(64)))
            .collect(),
    );
    assert_error(&run(&evaluator, &request), "limit");
    for bad in [
        consent("c1", "once", "not-a-digest"),
        consent("c1", "once", &"A".repeat(64)),
        consent("c 1", "once", &"a".repeat(64)),
        consent("c1", "forever", &"a".repeat(64)),
    ] {
        request["saved_consents"] = json!([bad]);
        assert_error(&run(&evaluator, &request), "invalid_request");
    }
}
