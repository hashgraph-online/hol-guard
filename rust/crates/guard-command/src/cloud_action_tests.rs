use base64::{engine::general_purpose::STANDARD, Engine};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{json, Value};

use crate::cloud_action::{error_result, CloudActionEvaluator, MAX_SAVED_CONSENTS, RESULT_SCHEMA};
use crate::cloud_action_activation::{
    parse_public_key, verify_activation, ActivationContext, SignedActivation, ACTIVATION_SCHEMA,
};
use crate::cloud_action_binding::load_binding_set;
use crate::cloud_action_binding::ActionEffect;
use crate::cloud_action_canonical::{
    canonical_arguments, canonical_bytes, domain_digest, parse_strict, CanonicalError,
    MAX_ARGUMENT_BYTES, MAX_DEPTH,
};
use crate::cloud_action_policy::{decide_policy, CloudPolicyRule, PolicySubject, MAX_POLICY_RULES};
use crate::effect_decision::GuardAction;
use crate::native_command_program::packaged_command_program;

const BINDINGS: &str = include_str!("../tests/fixtures/cloud-action/binding-set.json");
const REQUEST: &str = include_str!("../tests/fixtures/cloud-action/request.json");

/// A mutation applied to a base request or binding document.
type Edit = fn(&mut Value);

const POST: &str = "slack.chat.post_message";
const ARCHIVE: &str = "slack.channels.archive";
const LIST: &str = "slack.channels.list";
const TRANSFER: &str = "slack.workspace.transfer_ownership";

fn evaluator() -> CloudActionEvaluator {
    CloudActionEvaluator::new(load_binding_set(BINDINGS.as_bytes()).unwrap(), None)
}

fn request_for(evaluator: &CloudActionEvaluator) -> Value {
    let mut request: Value = serde_json::from_str(REQUEST).unwrap();
    request["binding_set_digest"] = evaluator.binding_set_digest().into();
    request
}

fn run(evaluator: &CloudActionEvaluator, request: &Value) -> Value {
    evaluator.evaluate(request.to_string().as_bytes())
}

fn run_with_rules(rules: Value) -> Value {
    let evaluator = evaluator();
    let mut request = request_for(&evaluator);
    request["policy"]["rules"] = rules;
    run(&evaluator, &request)
}

fn set_action(request: &mut Value, action_id: &str, arguments: Value) {
    request["action"]["action_id"] = action_id.into();
    request["action"]["arguments"] = arguments;
}

fn rule(rule_id: &str, action: &str, action_id: &str) -> Value {
    json!({"rule_id": rule_id, "action": action, "match": {"action_id": action_id}})
}

fn consent(consent_id: &str, kind: &str, identity: &str) -> Value {
    json!({"consent_id": consent_id, "kind": kind, "action_identity_sha256": identity})
}

fn identity_of(evaluator: &CloudActionEvaluator, request: &Value) -> String {
    let result = run(evaluator, request);
    assert_success(&result);
    result["action_identity_sha256"].as_str().unwrap().into()
}

fn assert_success(result: &Value) {
    assert!(result.get("error").is_none(), "{result}");
    assert_eq!(result["schema"], RESULT_SCHEMA);
}

fn assert_error(result: &Value, code: &str) {
    assert_eq!(result["error"]["code"], code, "{result}");
    assert_eq!(result["schema"], RESULT_SCHEMA, "{result}");
    assert_eq!(result["action"], "block", "{result}");
    assert_eq!(result["dispatch_permitted"], false, "{result}");
    assert!(result.get("action_identity_sha256").is_none(), "{result}");
}

/// The request with its arguments replaced by `raw` JSON text, for inputs a
/// `Value` cannot hold (duplicate keys, floats, numbers past 2^53).
fn line_with_raw_arguments(request: &Value, raw: &str) -> String {
    let mut request = request.clone();
    request["action"]["arguments"] = "@@arguments@@".into();
    request.to_string().replace("\"@@arguments@@\"", raw)
}

fn is_hex_digest(value: &Value) -> bool {
    value.as_str().is_some_and(|text| {
        text.len() == 64
            && text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

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

// ---- strict request intake ----

#[test]
fn duplicate_keys_are_rejected_at_any_depth() {
    let evaluator = evaluator();
    let base = request_for(&evaluator);
    let line = line_with_raw_arguments(&base, r#"{"channel":"C0SYNTH01","channel":"C0SYNTH02"}"#);
    assert_error(&evaluator.evaluate(line.as_bytes()), "duplicate_key");
    let nested = line_with_raw_arguments(
        &base,
        r#"{"channel":"C0SYNTH01","a":{"b":[{"c":1,"c":2}]}}"#,
    );
    assert_error(&evaluator.evaluate(nested.as_bytes()), "duplicate_key");
    let top_level = base
        .to_string()
        .replacen('{', "{\"request_id\":\"req-0009\",", 1);
    assert_error(&evaluator.evaluate(top_level.as_bytes()), "duplicate_key");
    // An escaped spelling is the same key.
    let escaped =
        line_with_raw_arguments(&base, r#"{"channel":"C0SYNTH01","channel":"C0SYNTH02"}"#);
    assert_error(&evaluator.evaluate(escaped.as_bytes()), "duplicate_key");
}

#[test]
fn deeply_nested_requests_are_rejected() {
    let evaluator = evaluator();
    let base = request_for(&evaluator);
    let deep = format!(
        "{{\"channel\":\"C0SYNTH01\",\"x\":{}1{}}}",
        "[".repeat(40),
        "]".repeat(40)
    );
    let line = line_with_raw_arguments(&base, &deep);
    assert_error(&evaluator.evaluate(line.as_bytes()), "too_deep");
    let unclosed = "[".repeat(100_000);
    assert_error(&evaluator.evaluate(unclosed.as_bytes()), "too_deep");
}

#[test]
fn nesting_up_to_the_limit_parses_and_one_more_does_not() {
    let nest = |levels: usize| format!("{}1{}", "[".repeat(levels), "]".repeat(levels));
    assert!(parse_strict(nest(MAX_DEPTH).as_bytes()).is_ok());
    assert_eq!(
        parse_strict(nest(MAX_DEPTH + 1).as_bytes()),
        Err(CanonicalError::TooDeep)
    );
    let objects = |levels: usize| format!("{}1{}", "{\"k\":".repeat(levels), "}".repeat(levels));
    assert!(parse_strict(objects(MAX_DEPTH).as_bytes()).is_ok());
    assert_eq!(
        parse_strict(objects(MAX_DEPTH + 1).as_bytes()),
        Err(CanonicalError::TooDeep)
    );
}

#[test]
fn non_integral_and_out_of_range_numbers_are_rejected() {
    let evaluator = evaluator();
    let base = request_for(&evaluator);
    for number in [
        "1.5",
        "1.0",
        "-0.5",
        "1e2",
        "1E2",
        "1e400",
        "9007199254740992",
        "-9007199254740992",
        "12345678901234567890",
        "123456789012345678901234567890",
    ] {
        let line = line_with_raw_arguments(
            &base,
            &format!("{{\"channel\":\"C0SYNTH01\",\"n\":{number}}}"),
        );
        assert_error(&evaluator.evaluate(line.as_bytes()), "unsupported_number");
    }
    let nested = line_with_raw_arguments(&base, r#"{"channel":"C0SYNTH01","a":[{"b":0.1}]}"#);
    assert_error(&evaluator.evaluate(nested.as_bytes()), "unsupported_number");
}

#[test]
fn integers_inside_the_safe_range_are_accepted_and_normalized() {
    let evaluator = evaluator();
    let base = request_for(&evaluator);
    for number in [
        "0",
        "-0",
        "7",
        "-7",
        "9007199254740991",
        "-9007199254740991",
    ] {
        let line = line_with_raw_arguments(
            &base,
            &format!("{{\"channel\":\"C0SYNTH01\",\"n\":{number}}}"),
        );
        assert_success(&evaluator.evaluate(line.as_bytes()));
    }
    let zero = serde_json::from_str::<Value>("-0").unwrap();
    assert_eq!(canonical_bytes(&zero).unwrap(), b"0");
    let limit = serde_json::from_str::<Value>("9007199254740991").unwrap();
    assert_eq!(canonical_bytes(&limit).unwrap(), b"9007199254740991");
}

#[test]
fn arguments_over_64_kib_are_rejected_and_the_limit_is_exact() {
    let evaluator = evaluator();
    let mut request = request_for(&evaluator);
    let overhead = canonical_bytes(&json!({"channel": "C0SYNTH01", "text": ""}))
        .unwrap()
        .len();
    let exact = "a".repeat(MAX_ARGUMENT_BYTES - overhead);
    request["action"]["arguments"]["text"] = exact.clone().into();
    assert_success(&run(&evaluator, &request));
    request["action"]["arguments"]["text"] = format!("{exact}a").into();
    assert_error(&run(&evaluator, &request), "too_large");
    request["action"]["arguments"]["text"] = "a".repeat(1024 * 1024).into();
    assert_error(&run(&evaluator, &request), "too_large");
}

#[test]
fn arguments_must_be_an_object() {
    let evaluator = evaluator();
    let mut request = request_for(&evaluator);
    for arguments in [json!([]), json!("channel"), json!(1), json!(null)] {
        request["action"]["arguments"] = arguments;
        assert_error(&run(&evaluator, &request), "malformed");
    }
}

#[test]
fn unknown_and_missing_fields_are_invalid_requests() {
    let evaluator = evaluator();
    let edits: [(&str, Edit); 10] = [
        ("top level", |r| r["extra"] = 1.into()),
        ("principal", |r| r["principal"]["role"] = "admin".into()),
        ("connection", |r| r["connection"]["scopes"] = json!(["all"])),
        ("action effect", |r| r["action"]["effect"] = "read".into()),
        ("policy", |r| r["policy"]["default"] = "allow".into()),
        ("missing policy", |r| {
            r.as_object_mut().unwrap().remove("policy");
        }),
        ("missing consents", |r| {
            r.as_object_mut().unwrap().remove("saved_consents");
        }),
        ("bad timestamp", |r| r["evaluated_at"] = "2026-11-01".into()),
        ("bad account digest", |r| {
            r["connection"]["account_digest"] = "abc".into()
        }),
        ("blank label", |r| r["principal"]["subject_id"] = "".into()),
    ];
    for (name, edit) in edits {
        let mut request = request_for(&evaluator);
        edit(&mut request);
        let result = run(&evaluator, &request);
        assert_error(&result, "invalid_request");
        assert!(result["error"]["code"] == "invalid_request", "{name}");
    }
}

#[test]
fn a_wrong_or_missing_schema_is_an_unsupported_version() {
    let evaluator = evaluator();
    let mut request = request_for(&evaluator);
    request["schema"] = "guard.cloud-action-evaluation.v2".into();
    assert_error(&run(&evaluator, &request), "unsupported_version");
    request["schema"] = 1.into();
    assert_error(&run(&evaluator, &request), "unsupported_version");
    request.as_object_mut().unwrap().remove("schema");
    assert_error(&run(&evaluator, &request), "unsupported_version");
    // The version check comes before the field check, so a future request
    // with new fields is reported as a version problem.
    let mut future = request_for(&evaluator);
    future["schema"] = "guard.cloud-action-evaluation.v2".into();
    future["new_field"] = true.into();
    assert_error(&run(&evaluator, &future), "unsupported_version");
}

#[test]
fn a_missing_or_malformed_resource_argument_is_an_invalid_request() {
    let evaluator = evaluator();
    for arguments in [
        json!({"text": "hello"}),
        json!({"channel": 7}),
        json!({"channel": ""}),
        json!({"channel": "has space"}),
        json!({"channel": {"id": "C0SYNTH01"}}),
    ] {
        let mut request = request_for(&evaluator);
        request["action"]["arguments"] = arguments;
        assert_error(&run(&evaluator, &request), "invalid_request");
    }
}

#[test]
fn malformed_json_is_rejected_without_a_request_id() {
    let evaluator = evaluator();
    for line in ["", "   ", "not json", "{", "{}{}", "[1,2", "null", "7"] {
        let result = evaluator.evaluate(line.as_bytes());
        assert_eq!(result["action"], "block", "{line:?}");
        assert_eq!(result["dispatch_permitted"], false, "{line:?}");
        assert!(result["error"]["code"].is_string(), "{line:?}");
    }
    assert_error(&evaluator.evaluate(b""), "malformed");
    assert_error(&evaluator.evaluate(b"{} trailing"), "malformed");
    assert_error(&evaluator.evaluate(&[0xff, 0xfe, 0x7b]), "malformed");
    assert_eq!(evaluator.evaluate(b"{")["request_id"], Value::Null);
}

#[test]
fn arbitrary_bytes_never_panic_and_always_block() {
    let evaluator = evaluator();
    let base = request_for(&evaluator).to_string().into_bytes();
    let mut seed: u64 = 0x9e37_79b9_7f4a_7c15;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for round in 0..400 {
        let mut line = base.clone();
        for _ in 0..=(round % 5) {
            let at = (next() as usize) % line.len();
            match next() % 3 {
                0 => line[at] = (next() & 0xff) as u8,
                1 => line.truncate(at),
                _ => line.insert(at, b"{}[]\",:\\0e-."[(next() % 12) as usize]),
            }
            if line.is_empty() {
                line.push(b'{');
            }
        }
        let result = evaluator.evaluate(&line);
        if result.get("error").is_some() {
            assert_eq!(result["action"], "block");
            assert_eq!(result["dispatch_permitted"], false);
        }
    }
}

// ---- binding resolution ----

#[test]
fn a_binding_set_digest_mismatch_is_binding_unavailable() {
    let evaluator = evaluator();
    let mut request = request_for(&evaluator);
    request["binding_set_digest"] = "0".repeat(64).into();
    let result = run(&evaluator, &request);
    assert_error(&result, "binding_unavailable");
    assert_eq!(result["request_id"], "req-0001");
    request["binding_set_digest"] = "".into();
    assert_error(&run(&evaluator, &request), "binding_unavailable");
}

#[test]
fn an_unknown_action_is_action_unknown() {
    let evaluator = evaluator();
    for action_id in [
        "slack.chat.delete_message",
        "slack.chat",
        "SLACK.CHAT.POST_MESSAGE",
        "slack.*",
    ] {
        let mut request = request_for(&evaluator);
        set_action(&mut request, action_id, json!({"channel": "C0SYNTH01"}));
        assert_error(&run(&evaluator, &request), "action_unknown");
    }
}

#[test]
fn a_provider_mismatch_is_connection_mismatch() {
    let evaluator = evaluator();
    let mut request = request_for(&evaluator);
    request["connection"]["provider"] = "example".into();
    assert_error(&run(&evaluator, &request), "connection_mismatch");
}

#[test]
fn a_caller_cannot_give_an_unknown_action_a_known_effect() {
    let evaluator = evaluator();
    let mut request = request_for(&evaluator);
    set_action(
        &mut request,
        "slack.channels.purge",
        json!({"channel": "C0SYNTH01"}),
    );
    request["policy"]["rules"] = json!([rule("allow-all", "allow", "*")]);
    assert_error(&run(&evaluator, &request), "action_unknown");
}

#[test]
fn evaluation_is_stateless_and_repeatable() {
    let evaluator = evaluator();
    let request = request_for(&evaluator);
    let first = run(&evaluator, &request);
    let second = run(&evaluator, &request);
    assert_eq!(first, second);
    assert_error(&evaluator.evaluate(b"{"), "malformed");
    assert_eq!(run(&evaluator, &request), first);
}

// ---- binding set admission ----

fn edited_set(edit: impl FnOnce(&mut Value)) -> Vec<u8> {
    let mut set: Value = serde_json::from_str(BINDINGS).unwrap();
    edit(&mut set);
    set.to_string().into_bytes()
}

#[test]
fn the_fixture_binding_set_loads_with_a_stable_digest() {
    let set = load_binding_set(BINDINGS.as_bytes()).unwrap();
    assert_eq!(set.len(), 5);
    assert!(!set.is_empty());
    let post = set.get(POST).unwrap();
    assert_eq!(post.binding.adapter.provider, "slack");
    assert!(is_hex_digest(&Value::from(
        post.execution_identity_digest.as_str()
    )));
    assert!(set.get("slack.chat.unknown").is_none());
    // Spelling and key order do not change the digest.
    let reordered = edited_set(|_| {});
    assert_eq!(load_binding_set(&reordered).unwrap().digest, set.digest);
}

#[test]
fn a_binding_without_egress_pinning_rejects_the_whole_set() {
    let bytes = edited_set(|set| {
        set["bindings"][1]["required_capabilities"] =
            json!(["bounded-output", "resource-allowlist"]);
    });
    assert_eq!(
        load_binding_set(&bytes).unwrap_err(),
        "binding_missing_required_capability"
    );
}

#[test]
fn a_binding_without_bounded_output_rejects_the_whole_set() {
    let bytes = edited_set(|set| {
        set["bindings"][4]["required_capabilities"] = json!(["egress-pinned", "no-filesystem"]);
    });
    assert_eq!(
        load_binding_set(&bytes).unwrap_err(),
        "binding_missing_required_capability"
    );
}

#[test]
fn duplicate_actions_reject_the_whole_set() {
    let bytes = edited_set(|set| {
        let copy = set["bindings"][0].clone();
        set["bindings"].as_array_mut().unwrap().push(copy);
    });
    assert_eq!(
        load_binding_set(&bytes).unwrap_err(),
        "binding_duplicate_action"
    );
}

#[test]
fn a_non_https_remote_mcp_url_rejects_the_whole_set() {
    for url in [
        "http://mcp.example.invalid/v1",
        "ws://mcp.example.invalid/v1",
        "mcp.example.invalid/v1",
        "",
    ] {
        let bytes = edited_set(|set| set["bindings"][4]["remote_mcp"]["url"] = url.into());
        assert_eq!(
            load_binding_set(&bytes).unwrap_err(),
            "binding_malformed",
            "{url:?}"
        );
    }
    let bytes = edited_set(|set| set["bindings"][4]["remote_mcp"]["tool_name"] = " ".into());
    assert_eq!(load_binding_set(&bytes).unwrap_err(), "binding_malformed");
}

#[test]
fn adapter_kind_and_remote_mcp_section_must_agree() {
    let native_with_remote = edited_set(|set| {
        set["bindings"][0]["remote_mcp"] =
            json!({"url": "https://mcp.example.invalid/v1", "tool_name": "t"});
    });
    assert_eq!(
        load_binding_set(&native_with_remote).unwrap_err(),
        "binding_malformed"
    );
    let remote_without_section = edited_set(|set| set["bindings"][4]["remote_mcp"] = Value::Null);
    assert_eq!(
        load_binding_set(&remote_without_section).unwrap_err(),
        "binding_malformed"
    );
}

#[test]
fn malformed_bindings_and_sets_are_rejected() {
    let cases: [(&str, Edit, &str); 9] = [
        (
            "set schema",
            |s| s["schema"] = "guard.cloud-action-binding-set.v2".into(),
            "binding_set_unsupported_version",
        ),
        (
            "binding schema",
            |s| s["bindings"][0]["schema"] = "guard.cloud-action-binding.v2".into(),
            "binding_unsupported_version",
        ),
        (
            "set field",
            |s| s["extra"] = 1.into(),
            "binding_set_malformed",
        ),
        (
            "binding field",
            |s| s["bindings"][0]["extra"] = 1.into(),
            "binding_malformed",
        ),
        (
            "action id case",
            |s| s["bindings"][0]["action_id"] = "Slack.Channels.List".into(),
            "binding_malformed",
        ),
        (
            "action id depth",
            |s| s["bindings"][0]["action_id"] = "slack".into(),
            "binding_malformed",
        ),
        (
            "effect",
            |s| s["bindings"][0]["effect"] = "owner".into(),
            "binding_malformed",
        ),
        (
            "input schema",
            |s| s["bindings"][0]["adapter"]["input_schema"] = "object".into(),
            "binding_malformed",
        ),
        (
            "float",
            |s| {
                s["bindings"][0]["adapter"]["input_schema"]["maximum"] =
                    serde_json::from_str("1.5").unwrap()
            },
            "binding_set_malformed",
        ),
    ];
    for (name, edit, code) in cases {
        let bytes = edited_set(edit);
        assert_eq!(load_binding_set(&bytes).unwrap_err(), code, "{name}");
    }
    assert_eq!(load_binding_set(b"").unwrap_err(), "binding_set_malformed");
    assert_eq!(
        load_binding_set(b"[]").unwrap_err(),
        "binding_set_malformed"
    );
    let duplicate_key = BINDINGS.replacen("\"bindings\"", "\"schema\": \"x\", \"bindings\"", 1);
    assert_eq!(
        load_binding_set(duplicate_key.as_bytes()).unwrap_err(),
        "binding_set_malformed"
    );
}

#[test]
fn a_changed_binding_changes_the_set_digest() {
    let original = load_binding_set(BINDINGS.as_bytes()).unwrap();
    let changed = load_binding_set(&edited_set(|set| {
        set["bindings"][0]["effect"] = "write".into()
    }))
    .unwrap();
    assert_ne!(original.digest, changed.digest);
    assert_eq!(
        changed.get(LIST).unwrap().binding.effect,
        ActionEffect::Write
    );
    assert_ne!(
        original.get(LIST).unwrap().execution_identity_digest,
        changed.get(LIST).unwrap().execution_identity_digest
    );
    assert_eq!(
        original.get(POST).unwrap().execution_identity_digest,
        changed.get(POST).unwrap().execution_identity_digest
    );
}

// ---- activation ----

struct Signer {
    pair: Ed25519KeyPair,
    public: [u8; 32],
}

fn signer() -> Signer {
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let public = pair.public_key().as_ref().try_into().unwrap();
    Signer { pair, public }
}

fn catalog_digest() -> String {
    packaged_command_program().unwrap().catalog_digest.clone()
}

fn payload(workspace_id: &str) -> Value {
    json!({
        "schema": ACTIVATION_SCHEMA,
        "workspace_id": workspace_id,
        "catalog_digest": catalog_digest(),
        "global_lockdown": false,
        "controls": [{"extension_id": "command.mcp-synthetic", "state": "enabled"}],
        "issued_at": "2026-11-01T00:00:00Z",
        "expires_at": "2026-11-02T00:00:00Z",
    })
}

fn sign(signer: &Signer, payload: &Value) -> Value {
    let message = canonical_bytes(payload).unwrap();
    json!({
        "payload": payload,
        "signature": STANDARD.encode(signer.pair.sign(&message).as_ref()),
    })
}

fn evaluator_trusting(signer: &Signer) -> CloudActionEvaluator {
    CloudActionEvaluator::new(
        load_binding_set(BINDINGS.as_bytes()).unwrap(),
        Some(signer.public),
    )
}

fn run_with_activation(evaluator: &CloudActionEvaluator, activation: Value) -> Value {
    let mut request = request_for(evaluator);
    request["activation"] = activation;
    run(evaluator, &request)
}

#[test]
fn a_validly_signed_activation_is_accepted_and_recorded_in_provenance() {
    let signer = signer();
    let evaluator = evaluator_trusting(&signer);
    let without = run(&evaluator, &request_for(&evaluator));
    assert_success(&without);
    let signed = sign(&signer, &payload("ws-synthetic-1"));
    let with = run_with_activation(&evaluator, signed);
    assert_success(&with);
    assert_eq!(with["action"], without["action"]);
    assert_ne!(
        with["evaluation_provenance_digest"],
        without["evaluation_provenance_digest"]
    );
    let mut other = payload("ws-synthetic-1");
    other["global_lockdown"] = true.into();
    let other_result = run_with_activation(&evaluator, sign(&signer, &other));
    assert_success(&other_result);
    assert_ne!(
        other_result["evaluation_provenance_digest"],
        with["evaluation_provenance_digest"]
    );
}

#[test]
fn an_activation_signed_by_another_key_is_rejected() {
    let trusted = signer();
    let attacker = signer();
    let evaluator = evaluator_trusting(&trusted);
    let result = run_with_activation(&evaluator, sign(&attacker, &payload("ws-synthetic-1")));
    assert_error(&result, "activation_invalid");
}

#[test]
fn a_tampered_activation_payload_is_rejected() {
    let signer = signer();
    let evaluator = evaluator_trusting(&signer);
    let mut signed = sign(&signer, &payload("ws-synthetic-1"));
    signed["payload"]["controls"] = json!([{"extension_id": "command.mcp-synthetic", "state": "enabled"},
        {"extension_id": "command.mcp-other", "state": "enabled"}]);
    assert_error(
        &run_with_activation(&evaluator, signed),
        "activation_invalid",
    );

    let mut signed = sign(&signer, &payload("ws-synthetic-1"));
    signed["payload"]["expires_at"] = "2099-01-01T00:00:00Z".into();
    assert_error(
        &run_with_activation(&evaluator, signed),
        "activation_invalid",
    );

    let mut signed = sign(&signer, &payload("ws-synthetic-1"));
    signed["signature"] = "not base64 !!".into();
    assert_error(
        &run_with_activation(&evaluator, signed),
        "activation_invalid",
    );

    let mut signed = sign(&signer, &payload("ws-synthetic-1"));
    signed["signature"] = STANDARD.encode([0u8; 64]).into();
    assert_error(
        &run_with_activation(&evaluator, signed),
        "activation_invalid",
    );
}

#[test]
fn an_expired_or_not_yet_valid_activation_is_rejected() {
    let signer = signer();
    let evaluator = evaluator_trusting(&signer);
    let mut expired = payload("ws-synthetic-1");
    expired["expires_at"] = "2026-11-01T11:59:59Z".into();
    assert_error(
        &run_with_activation(&evaluator, sign(&signer, &expired)),
        "activation_expired",
    );
    // The expiry instant itself is already expired.
    let mut at_expiry = payload("ws-synthetic-1");
    at_expiry["expires_at"] = "2026-11-01T12:00:00Z".into();
    assert_error(
        &run_with_activation(&evaluator, sign(&signer, &at_expiry)),
        "activation_expired",
    );
    let mut early = payload("ws-synthetic-1");
    early["issued_at"] = "2026-11-01T12:00:01Z".into();
    assert_error(
        &run_with_activation(&evaluator, sign(&signer, &early)),
        "activation_expired",
    );
    let mut at_issue = payload("ws-synthetic-1");
    at_issue["issued_at"] = "2026-11-01T12:00:00Z".into();
    assert_success(&run_with_activation(&evaluator, sign(&signer, &at_issue)));
}

#[test]
fn an_activation_for_another_workspace_or_catalog_is_rejected() {
    let signer = signer();
    let evaluator = evaluator_trusting(&signer);
    let other_workspace = sign(&signer, &payload("ws-synthetic-2"));
    assert_error(
        &run_with_activation(&evaluator, other_workspace),
        "activation_mismatch",
    );
    let mut other_catalog = payload("ws-synthetic-1");
    other_catalog["catalog_digest"] = "0".repeat(64).into();
    assert_error(
        &run_with_activation(&evaluator, sign(&signer, &other_catalog)),
        "activation_mismatch",
    );
}

#[test]
fn an_activation_with_no_configured_key_is_rejected_not_ignored() {
    let signer = signer();
    let keyless = evaluator();
    let signed = sign(&signer, &payload("ws-synthetic-1"));
    assert_error(
        &run_with_activation(&keyless, signed),
        "activation_key_unavailable",
    );
    // No activation and no key is the ordinary case.
    assert_success(&run(&keyless, &request_for(&keyless)));
}

#[test]
fn a_malformed_signed_activation_is_rejected() {
    let signer = signer();
    let evaluator = evaluator_trusting(&signer);
    let mut wrong_schema = payload("ws-synthetic-1");
    wrong_schema["schema"] = "guard.cloud-workspace-activation.v2".into();
    assert_error(
        &run_with_activation(&evaluator, sign(&signer, &wrong_schema)),
        "activation_unsupported_version",
    );
    let mut extra = payload("ws-synthetic-1");
    extra["unexpected"] = true.into();
    assert_error(
        &run_with_activation(&evaluator, sign(&signer, &extra)),
        "activation_invalid",
    );
    let mut bad_time = payload("ws-synthetic-1");
    bad_time["expires_at"] = "tomorrow".into();
    assert_error(
        &run_with_activation(&evaluator, sign(&signer, &bad_time)),
        "activation_invalid",
    );
    // A float cannot be canonicalized, so it can never carry a valid signature.
    let mut float = payload("ws-synthetic-1");
    float["controls"][0]["weight"] = serde_json::from_str("1.5").unwrap();
    let unsigned = json!({"payload": float, "signature": "AAAA"});
    assert_error(
        &run_with_activation(&evaluator, unsigned),
        "activation_invalid",
    );
    let mut document = sign(&signer, &payload("ws-synthetic-1"));
    document["extra"] = true.into();
    assert_error(
        &run_with_activation(&evaluator, document),
        "invalid_request",
    );
}

fn activation_with_controls(controls: Value) -> (Signer, SignedActivation) {
    let signer = signer();
    let mut body = payload("ws-synthetic-1");
    body["controls"] = controls;
    let signed: SignedActivation = serde_json::from_value(sign(&signer, &body)).unwrap();
    (signer, signed)
}

fn verify(
    signed: &SignedActivation,
    key: &[u8; 32],
) -> Result<crate::cloud_action_activation::VerifiedActivation, &'static str> {
    let digest = catalog_digest();
    verify_activation(
        Some(signed),
        Some(key),
        &ActivationContext {
            workspace_id: "ws-synthetic-1",
            catalog_digest: &digest,
            now: "2026-11-01T12:00:00Z",
        },
    )
}

#[test]
fn a_disable_beats_an_enable_in_either_order() {
    let enable = json!({"extension_id": "command.mcp-synthetic", "state": "enabled"});
    let disable = json!({"extension_id": "command.mcp-synthetic", "state": "disabled"});
    let other = json!({"extension_id": "command.mcp-other", "state": "enabled"});
    for controls in [
        json!([enable, disable, other]),
        json!([disable, enable, other]),
        json!([enable, enable, disable, other]),
    ] {
        let (signer, signed) = activation_with_controls(controls);
        let verified = verify(&signed, &signer.public).unwrap();
        assert!(!verified.external_enabled("command.mcp-synthetic"));
        assert!(verified.external_enabled("command.mcp-other"));
        assert!(!verified.external_enabled("command.mcp-unlisted"));
    }
    let (signer, signed) = activation_with_controls(json!([enable]));
    assert!(verify(&signed, &signer.public)
        .unwrap()
        .external_enabled("command.mcp-synthetic"));
}

#[test]
fn an_absent_activation_enables_nothing_and_a_signed_lockdown_is_carried() {
    let digest = catalog_digest();
    let none = verify_activation(
        None,
        None,
        &ActivationContext {
            workspace_id: "ws-synthetic-1",
            catalog_digest: &digest,
            now: "2026-11-01T12:00:00Z",
        },
    )
    .unwrap();
    assert!(!none.global_lockdown);
    assert!(!none.external_enabled("command.mcp-synthetic"));
    assert!(none.digest.is_none());

    let signer = signer();
    let mut body = payload("ws-synthetic-1");
    body["global_lockdown"] = true.into();
    let signed: SignedActivation = serde_json::from_value(sign(&signer, &body)).unwrap();
    let verified = verify(&signed, &signer.public).unwrap();
    assert!(verified.global_lockdown);
    assert!(verified.digest.is_some());
}

#[test]
fn an_activation_key_must_be_exactly_32_hex_bytes() {
    let signer = signer();
    let hex_key = hex::encode(signer.public);
    assert_eq!(parse_public_key(&hex_key).unwrap(), signer.public);
    assert_eq!(
        parse_public_key(&format!("{hex_key}\n")).unwrap(),
        signer.public
    );
    for bad in ["", "zz", &hex_key[..62], &format!("{hex_key}00"), "0x1234"] {
        assert_eq!(
            parse_public_key(bad).unwrap_err(),
            "activation_key_invalid",
            "{bad:?}"
        );
    }
}

// ---- canonical form ----

#[test]
fn object_keys_sort_by_utf16_code_units_not_code_points() {
    // U+FF5E is one UTF-16 unit (0xFF5E); U+10000 is the surrogate pair
    // 0xD800 0xDC00. By code point U+FF5E sorts first; by UTF-16 it sorts last.
    let value: Value =
        serde_json::from_str("{\"\u{FF5E}\":1,\"\u{10000}\":2,\"a\":3,\"B\":4}").unwrap();
    let expected = "{\"B\":4,\"a\":3,\"\u{10000}\":2,\"\u{FF5E}\":1}";
    assert_eq!(
        String::from_utf8(canonical_bytes(&value).unwrap()).unwrap(),
        expected
    );
    let reversed: Value =
        serde_json::from_str("{\"B\":4,\"a\":3,\"\u{10000}\":2,\"\u{FF5E}\":1}").unwrap();
    assert_eq!(
        canonical_bytes(&reversed).unwrap(),
        canonical_bytes(&value).unwrap()
    );
    let nested: Value = serde_json::from_str("{\"o\":{\"\u{FF5E}\":1,\"\u{10000}\":2}}").unwrap();
    assert_eq!(
        String::from_utf8(canonical_bytes(&nested).unwrap()).unwrap(),
        "{\"o\":{\"\u{10000}\":2,\"\u{FF5E}\":1}}"
    );
}

#[test]
fn the_same_arguments_in_any_key_order_have_one_identity() {
    let evaluator = evaluator();
    let base = request_for(&evaluator);
    let forward = line_with_raw_arguments(
        &base,
        "{\"channel\":\"C0SYNTH01\",\"\u{FF5E}\":1,\"\u{10000}\":2}",
    );
    let backward = line_with_raw_arguments(
        &base,
        "{\"\u{10000}\":2,\"\u{FF5E}\":1,\"channel\":\"C0SYNTH01\"}",
    );
    let forward = evaluator.evaluate(forward.as_bytes());
    let backward = evaluator.evaluate(backward.as_bytes());
    assert_success(&forward);
    assert_eq!(
        forward["action_identity_sha256"],
        backward["action_identity_sha256"]
    );
}

#[test]
fn canonical_strings_use_minimal_escapes_and_no_normalization() {
    let value = Value::String("a\"b\\c\u{1}\u{8}\u{c}\n\r\t/\u{7f}\u{2028}\u{e9}".into());
    assert_eq!(
        String::from_utf8(canonical_bytes(&value).unwrap()).unwrap(),
        "\"a\\\"b\\\\c\\u0001\\b\\f\\n\\r\\t/\u{7f}\u{2028}\u{e9}\""
    );
    // Visually identical spellings are different actions.
    let evaluator = evaluator();
    let base = request_for(&evaluator);
    let composed =
        line_with_raw_arguments(&base, "{\"channel\":\"C0SYNTH01\",\"text\":\"caf\u{e9}\"}");
    let decomposed = line_with_raw_arguments(
        &base,
        "{\"channel\":\"C0SYNTH01\",\"text\":\"cafe\u{301}\"}",
    );
    let composed = evaluator.evaluate(composed.as_bytes());
    let decomposed = evaluator.evaluate(decomposed.as_bytes());
    assert_ne!(
        composed["action_identity_sha256"],
        decomposed["action_identity_sha256"]
    );
}

#[test]
fn canonical_arguments_reject_non_objects_and_domain_digests_are_separated() {
    assert_eq!(
        canonical_arguments(&json!([])),
        Err(CanonicalError::Malformed)
    );
    assert_eq!(
        canonical_arguments(&json!({"a": [true, null, 1]})).unwrap(),
        b"{\"a\":[true,null,1]}"
    );
    assert_ne!(
        domain_digest("one", &[b"ab"]),
        domain_digest("two", &[b"ab"])
    );
    // Length prefixes keep the part boundaries from sliding.
    assert_ne!(
        domain_digest("d", &[b"ab", b"c"]),
        domain_digest("d", &[b"a", b"bc"])
    );
}

// ---- error shape ----

#[test]
fn every_error_result_blocks_and_never_permits_dispatch() {
    let evaluator = evaluator();
    let base = request_for(&evaluator);
    let signer = signer();
    let mut cases: Vec<(String, &str)> = vec![
        ("{".into(), "malformed"),
        (
            line_with_raw_arguments(&base, r#"{"a":1,"a":2}"#),
            "duplicate_key",
        ),
        (
            line_with_raw_arguments(&base, &format!("{}1{}", "[".repeat(40), "]".repeat(40))),
            "too_deep",
        ),
        (
            line_with_raw_arguments(&base, r#"{"channel":"C0SYNTH01","n":1.5}"#),
            "unsupported_number",
        ),
        (
            line_with_raw_arguments(&base, r#"{"channel":"C0SYNTH01","n":9007199254740992}"#),
            "unsupported_number",
        ),
    ];
    let mutations: [(Edit, &str); 8] = [
        (
            |r| r["action"]["arguments"]["text"] = "a".repeat(70_000).into(),
            "too_large",
        ),
        (|r| r["extra"] = 1.into(), "invalid_request"),
        (
            |r| r["schema"] = "guard.cloud-action-evaluation.v2".into(),
            "unsupported_version",
        ),
        (
            |r| r["binding_set_digest"] = "0".repeat(64).into(),
            "binding_unavailable",
        ),
        (
            |r| r["action"]["action_id"] = "slack.unknown.thing".into(),
            "action_unknown",
        ),
        (
            |r| r["connection"]["provider"] = "example".into(),
            "connection_mismatch",
        ),
        (
            |r| r["activation"] = json!({"payload": {}, "signature": "AAAA"}),
            "activation_key_unavailable",
        ),
        (
            |r| {
                r["policy"]["rules"] = json!([{"rule_id": "r", "action": "allow", "match": {"action_id": "*", "x": 1}}])
            },
            "invalid_request",
        ),
    ];
    for (mutate, code) in mutations {
        let mut request = base.clone();
        mutate(&mut request);
        cases.push((request.to_string(), code));
    }
    cases.push((
        {
            let mut request = base.clone();
            request["activation"] = sign(&signer, &payload("ws-synthetic-1"));
            request.to_string()
        },
        "activation_key_unavailable",
    ));
    for (line, code) in cases {
        assert_error(&evaluator.evaluate(line.as_bytes()), code);
    }
    let limit = error_result(None, "limit");
    assert_error(&limit, "limit");
    assert_eq!(limit["request_id"], Value::Null);
}

#[test]
fn errors_found_after_parsing_echo_the_request_id_and_parse_errors_do_not() {
    let evaluator = evaluator();
    let mut request = request_for(&evaluator);
    request["action"]["action_id"] = "slack.unknown.thing".into();
    assert_eq!(run(&evaluator, &request)["request_id"], "req-0001");
    let duplicate = line_with_raw_arguments(&request_for(&evaluator), r#"{"a":1,"a":2}"#);
    assert_eq!(
        evaluator.evaluate(duplicate.as_bytes())["request_id"],
        Value::Null
    );
}

#[test]
fn strings_serde_json_treats_as_internal_tokens_are_rejected_not_reinterpreted() {
    let escaped_prefix = "\\u0024serde_json::private::Number";
    for spelling in [
        r#"{"$serde_json::private::Number":"1"}"#.to_string(),
        r#"{"$serde_json::private::RawValue":"{\"a\":1,\"a\":2}"}"#.to_string(),
        format!("{{\"{escaped_prefix}\":\"1\"}}"),
        r#"{"k":"$serde_json::private::Number"}"#.to_string(),
        r#"["$serde_json::private::anything"]"#.to_string(),
    ] {
        let document = format!("{{\"x\":{spelling}}}");
        assert_eq!(
            parse_strict(document.as_bytes()),
            Err(CanonicalError::Malformed),
            "{document}"
        );
    }
    // Ordinary strings that merely resemble the prefix are untouched.
    let fine = r#"{"a":"$serde_json::private","b":"serde_json::private::Number","c":"\"$serde_json::private::\""}"#;
    assert!(parse_strict(fine.as_bytes()).is_ok());

    let evaluator = evaluator();
    let base = request_for(&evaluator);
    let smuggled = line_with_raw_arguments(
        &base,
        r#"{"channel":"C0SYNTH01","x":{"$serde_json::private::RawValue":"{\"a\":1,\"a\":2}"}}"#,
    );
    assert_error(&evaluator.evaluate(smuggled.as_bytes()), "malformed");
    let number = line_with_raw_arguments(
        &base,
        r#"{"channel":"C0SYNTH01","x":{"$serde_json::private::Number":"1"}}"#,
    );
    assert_error(&evaluator.evaluate(number.as_bytes()), "malformed");
}

#[test]
fn a_reserved_token_spelled_entirely_in_escapes_is_still_rejected() {
    let token = "$serde_json::private::RawValue";
    let escaped: String = token
        .chars()
        .map(|ch| format!("\\u{:04x}", ch as u32))
        .collect();
    assert!(escaped.len() > token.len() * 6 - 1);
    let document = format!(
        r#"{{"x":{{"{escaped}":"{{\"channel\":\"C0SYNTH01\",\"channel\":\"C0OTHER\"}}"}}}}"#
    );
    assert_eq!(
        parse_strict(document.as_bytes()),
        Err(CanonicalError::Malformed),
        "{document}"
    );

    let evaluator = evaluator();
    let smuggled = line_with_raw_arguments(
        &request_for(&evaluator),
        &format!(r#"{{"{escaped}":"{{\"channel\":\"C0SYNTH01\",\"channel\":\"C0OTHER\"}}"}}"#),
    );
    assert_error(&evaluator.evaluate(smuggled.as_bytes()), "malformed");
}

#[test]
fn an_error_result_never_echoes_an_unprintable_request_id() {
    let evaluator = evaluator();
    let mut request = request_for(&evaluator);
    request["request_id"] = "a b\n".into();
    let result = run(&evaluator, &request);
    assert!(result.get("error").is_some(), "{result}");
    assert_eq!(result["request_id"], Value::Null, "{result}");
}

#[test]
fn a_signed_global_lockdown_blocks_every_action_and_no_consent_lowers_it() {
    let signer = signer();
    let evaluator = evaluator_trusting(&signer);
    let mut locked = payload("ws-synthetic-1");
    locked["global_lockdown"] = true.into();
    let activation = sign(&signer, &locked);

    let mut request = request_for(&evaluator);
    let identity = identity_of(&evaluator, &request);
    request["activation"] = activation.clone();
    request["saved_consents"] = json!([consent("always-1", "always", &identity)]);
    request["policy"]["rules"] = json!([rule("allow-all", "allow", "*")]);
    let result = run(&evaluator, &request);
    assert_success(&result);
    assert_eq!(result["action"], "block", "{result}");
    assert_eq!(result["dispatch_permitted"], false);
    assert_eq!(result["consent_applied"], "none");
    assert!(
        result["reason_codes"]
            .as_array()
            .unwrap()
            .contains(&"global_lockdown".into()),
        "{result}"
    );

    let unlocked = run_with_activation(&evaluator, sign(&signer, &payload("ws-synthetic-1")));
    assert_success(&unlocked);
    assert_ne!(unlocked["action"], "block", "{unlocked}");
}
