//! Effect floors, workspace policy rules and target capabilities.

use super::*;

// ---- effect floors ----

#[test]
fn effect_floors_follow_the_binding_effect() {
    let evaluator = evaluator();
    let cases = [
        (LIST, json!({}), "allow", true, "effect_floor"),
        (
            POST,
            json!({"channel": "C0SYNTH01"}),
            "review",
            false,
            "effect_floor",
        ),
        (
            ARCHIVE,
            json!({"channel": "C0SYNTH01"}),
            "require-reapproval",
            false,
            "effect_floor",
        ),
        (
            TRANSFER,
            json!({"user": "U0SYNTH01"}),
            "block",
            false,
            "admin_effect_unsupported",
        ),
    ];
    for (action_id, arguments, action, dispatch, reason) in cases {
        let mut request = request_for(&evaluator);
        set_action(&mut request, action_id, arguments);
        let result = run(&evaluator, &request);
        assert_success(&result);
        assert_eq!(result["action"], action, "{action_id}");
        assert_eq!(result["dispatch_permitted"], dispatch, "{action_id}");
        assert_eq!(result["reason_codes"], json!([reason]), "{action_id}");
        assert_eq!(result["request_id"], "req-0001");
        assert!(is_hex_digest(&result["action_identity_sha256"]));
        assert!(is_hex_digest(&result["execution_identity_digest"]));
        assert!(is_hex_digest(&result["evaluation_provenance_digest"]));
    }
}

#[test]
fn review_results_are_review_eligible_and_allow_results_are_not() {
    let evaluator = evaluator();
    let mut request = request_for(&evaluator);
    let review = run(&evaluator, &request);
    assert_eq!(review["review_eligible"], true);
    assert_eq!(review["consent_applied"], "none");
    set_action(&mut request, LIST, json!({}));
    let allow = run(&evaluator, &request);
    assert_eq!(allow["review_eligible"], false);
}

#[test]
fn admin_is_blocked_even_when_a_rule_allows() {
    let evaluator = evaluator();
    let mut request = request_for(&evaluator);
    set_action(&mut request, TRANSFER, json!({"user": "U0SYNTH01"}));
    request["policy"]["rules"] = json!([
        rule("allow-all", "allow", "*"),
        rule("allow-exact", "allow", TRANSFER)
    ]);
    let result = run(&evaluator, &request);
    assert_success(&result);
    assert_eq!(result["action"], "block");
    assert_eq!(result["dispatch_permitted"], false);
    assert_eq!(result["reason_codes"], json!(["admin_effect_unsupported"]));
    assert_eq!(result["matched_rule_ids"], json!([]));
}

#[test]
fn a_remote_mcp_binding_without_a_catalog_match_keeps_its_effect_floor() {
    let evaluator = evaluator();
    let mut request = request_for(&evaluator);
    set_action(
        &mut request,
        "example.docs.search",
        json!({"query": "synthetic"}),
    );
    request["connection"]["provider"] = "example".into();
    let result = run(&evaluator, &request);
    assert_success(&result);
    assert_eq!(result["action"], "allow");
    assert_eq!(result["reason_codes"], json!(["effect_floor"]));
}

// ---- workspace policy ----

#[test]
fn a_block_rule_beats_a_more_specific_allow_rule() {
    let evaluator = evaluator();
    let mut request = request_for(&evaluator);
    request["policy"]["rules"] = json!([
        {"rule_id": "allow-exact", "action": "allow", "match": {
            "action_id": POST, "connection_id": "conn-synthetic-1", "resource_id": "C0SYNTH01"}},
        rule("block-family", "block", "slack.*"),
    ]);
    let result = run(&evaluator, &request);
    assert_success(&result);
    assert_eq!(result["action"], "block");
    assert_eq!(result["matched_rule_ids"], json!(["block-family"]));
    assert_eq!(result["reason_codes"], json!(["policy_rule"]));
}

#[test]
fn the_most_specific_rule_wins() {
    let wider_allow_narrower_reapproval = run_with_rules(json!([
        rule("family-allow", "allow", "slack.*"),
        rule("exact-reapproval", "require-reapproval", POST),
    ]));
    assert_eq!(
        wider_allow_narrower_reapproval["action"],
        "require-reapproval"
    );
    assert_eq!(
        wider_allow_narrower_reapproval["matched_rule_ids"],
        json!(["exact-reapproval"])
    );

    let wider_reapproval_narrower_allow = run_with_rules(json!([
        rule("exact-allow", "allow", POST),
        rule("any-reapproval", "require-reapproval", "*"),
    ]));
    assert_eq!(wider_reapproval_narrower_allow["action"], "allow");
    assert_eq!(
        wider_reapproval_narrower_allow["matched_rule_ids"],
        json!(["exact-allow"])
    );

    let longer_prefix = run_with_rules(json!([
        rule("short-prefix", "require-reapproval", "slack.*"),
        rule("long-prefix", "allow", "slack.chat.*"),
    ]));
    assert_eq!(longer_prefix["action"], "allow");
    assert_eq!(longer_prefix["matched_rule_ids"], json!(["long-prefix"]));
}

#[test]
fn connection_and_resource_narrow_a_rule_and_must_match_exactly() {
    let resource_rule = |resource: &str, action: &str, id: &str| json!({"rule_id": id, "action": action, "match": {"action_id": POST, "resource_id": resource}});
    let narrower = run_with_rules(json!([
        rule("exact-allow", "allow", POST),
        resource_rule("C0SYNTH01", "require-reapproval", "resource-reapproval"),
    ]));
    assert_eq!(narrower["action"], "require-reapproval");

    let other_resource = run_with_rules(json!([
        rule("exact-allow", "allow", POST),
        resource_rule("C0OTHER99", "require-reapproval", "resource-reapproval"),
    ]));
    assert_eq!(other_resource["action"], "allow");

    let other_connection = run_with_rules(json!([
        {"rule_id": "other-conn", "action": "allow", "match": {
            "action_id": POST, "connection_id": "conn-elsewhere"}},
    ]));
    assert_eq!(other_connection["action"], "review");
    assert_eq!(other_connection["reason_codes"], json!(["effect_floor"]));
}

#[test]
fn a_tie_goes_to_the_more_severe_action() {
    for rules in [
        json!([
            rule("a", "allow", POST),
            rule("b", "require-reapproval", POST)
        ]),
        json!([
            rule("b", "require-reapproval", POST),
            rule("a", "allow", POST)
        ]),
    ] {
        let result = run_with_rules(rules);
        assert_eq!(result["action"], "require-reapproval");
        assert_eq!(result["matched_rule_ids"], json!(["b"]));
    }
    let warn_versus_review = run_with_rules(json!([
        rule("warn", "warn", "slack.*"),
        rule("review", "review", "slack.*"),
    ]));
    assert_eq!(warn_versus_review["action"], "review");
}

#[test]
fn a_warn_rule_dispatches_without_a_review() {
    let result = run_with_rules(json!([rule("warn", "warn", POST)]));
    assert_eq!(result["action"], "warn");
    assert_eq!(result["dispatch_permitted"], true);
    assert_eq!(result["review_eligible"], false);
}

#[test]
fn provenance_records_the_rules_and_not_only_the_snapshot_label() {
    let evaluator = evaluator();
    let mut base = request_for(&evaluator);
    base["policy"]["rules"] = json!([rule("post", "review", POST)]);
    let digest = |request: &Value| run(&evaluator, request)["evaluation_provenance_digest"].clone();
    let original = digest(&base);
    assert!(is_hex_digest(&original));
    assert_eq!(digest(&base), original);
    let mut changed_action = base.clone();
    changed_action["policy"]["rules"] = json!([rule("post", "warn", POST)]);
    let mut changed_match = base.clone();
    changed_match["policy"]["rules"][0]["match"]["connection_id"] = "conn-other".into();
    let mut added = base.clone();
    added["policy"]["rules"] = json!([rule("post", "review", POST), rule("list", "allow", LIST)]);
    for changed in [changed_action, changed_match, added] {
        assert_eq!(
            changed["policy"]["snapshot_id"],
            base["policy"]["snapshot_id"]
        );
        let result = run(&evaluator, &changed);
        assert_success(&result);
        assert_ne!(result["evaluation_provenance_digest"], original);
    }
}

#[test]
fn policy_prefix_rules_match_whole_segments_only() {
    let subject = |action_id| PolicySubject {
        action_id,
        connection_id: "conn-synthetic-1",
        resource_id: None,
    };
    let rules: Vec<CloudPolicyRule> =
        serde_json::from_value(json!([rule("chat-family", "block", "slack.chat.*"),])).unwrap();
    let hit = decide_policy(
        &rules,
        &subject("slack.chat.post_message"),
        ActionEffect::Write,
    );
    assert_eq!(hit.action, GuardAction::Block);
    let near_miss = decide_policy(&rules, &subject("slack.chatter.post"), ActionEffect::Write);
    assert_eq!(near_miss.action, GuardAction::Review);
    assert_eq!(near_miss.reason_code, "effect_floor");
    let bare_prefix = decide_policy(&rules, &subject("slack.chat"), ActionEffect::Write);
    assert_eq!(bare_prefix.action, GuardAction::Review);
}

#[test]
fn invalid_rules_and_oversize_rule_lists_are_rejected() {
    let evaluator = evaluator();
    let bad_rules = [
        json!([rule("bad pattern", "allow", POST)]),
        json!([rule("r", "allow", "Slack.Chat")]),
        json!([rule("r", "allow", "slack.*.post")]),
        json!([{"rule_id": "r", "action": "allow", "match": {"action_id": POST}, "priority": 9}]),
        json!([{"rule_id": "r", "action": "permit", "match": {"action_id": POST}}]),
    ];
    for rules in bad_rules {
        let mut request = request_for(&evaluator);
        request["policy"]["rules"] = rules.clone();
        assert_error(&run(&evaluator, &request), "invalid_request");
    }
    let mut request = request_for(&evaluator);
    request["policy"]["rules"] = Value::Array(
        (0..=MAX_POLICY_RULES)
            .map(|i| rule(&format!("r{i}"), "allow", POST))
            .collect(),
    );
    assert_error(&run(&evaluator, &request), "limit");
}

// ---- target capabilities ----

#[test]
fn a_missing_required_capability_requires_a_sandbox_and_no_consent_lowers_it() {
    let evaluator = evaluator();
    let mut request = request_for(&evaluator);
    request["target_capabilities"] = json!(["egress-pinned", "bounded-output"]);
    let result = run(&evaluator, &request);
    assert_success(&result);
    assert_eq!(result["action"], "sandbox-required");
    assert_eq!(result["dispatch_permitted"], false);
    assert_eq!(
        result["missing_capabilities"],
        json!(["resource-allowlist"])
    );
    assert_eq!(
        result["reason_codes"],
        json!(["effect_floor", "capability_unavailable"])
    );

    let identity = result["action_identity_sha256"].as_str().unwrap();
    request["saved_consents"] = json!([
        consent("once-1", "once", identity),
        consent("always-1", "always", identity),
    ]);
    let with_consent = run(&evaluator, &request);
    assert_success(&with_consent);
    assert_eq!(with_consent["action"], "sandbox-required");
    assert_eq!(with_consent["dispatch_permitted"], false);
    assert_eq!(with_consent["consent_applied"], "none");
    assert_eq!(with_consent["consent_id"], Value::Null);
    assert_eq!(with_consent["review_eligible"], false);
}

#[test]
fn a_missing_capability_also_overrides_an_allow() {
    let evaluator = evaluator();
    let mut request = request_for(&evaluator);
    set_action(&mut request, LIST, json!({}));
    request["target_capabilities"] = json!(["egress-pinned"]);
    let result = run(&evaluator, &request);
    assert_success(&result);
    assert_eq!(result["action"], "sandbox-required");
    assert_eq!(result["missing_capabilities"], json!(["bounded-output"]));
}

#[test]
fn a_missing_capability_never_lowers_a_block() {
    let evaluator = evaluator();
    let mut request = request_for(&evaluator);
    request["target_capabilities"] = json!([]);
    request["policy"]["rules"] = json!([rule("block-post", "block", POST)]);
    let result = run(&evaluator, &request);
    assert_success(&result);
    assert_eq!(result["action"], "block");
    assert_eq!(
        result["missing_capabilities"],
        json!(["egress-pinned", "resource-allowlist", "bounded-output"])
    );
    assert_eq!(result["reason_codes"], json!(["policy_rule"]));
}

#[test]
fn unknown_target_capabilities_are_rejected_rather_than_ignored() {
    let evaluator = evaluator();
    let mut request = request_for(&evaluator);
    request["target_capabilities"] = json!(["egress-pinned", "root-access"]);
    assert_error(&run(&evaluator, &request), "invalid_request");
}
