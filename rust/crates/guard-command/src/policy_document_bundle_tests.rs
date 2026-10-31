//! Device scoping decided here, with the rules a bundle publishes as input.

use std::time::{Duration, Instant};

use serde_json::{json, Value};

fn run(input: &Value) -> Value {
    crate::policy_document::evaluate(
        "compile_bundle",
        input,
        Instant::now() + Duration::from_secs(30),
    )
    .unwrap()
}

fn rule(id: &str, matcher: Value) -> Value {
    json!({
        "id": id,
        "enabled": true,
        "effect": "allow",
        "match": matcher,
        "lifetime": {"mode": "permanent", "expiresAt": null},
        "provenance": {"source": "cloud", "createdAt": "2026-01-01T00:00:00Z"},
    })
}

fn request(rules: Value) -> Value {
    json!({
        "bundle": {"payload": {
            "apiVersion": "guard.hashgraphonline.com/v1alpha1",
            "kind": "GuardPolicy",
            "metadata": {"id": "managed-policy", "name": "Managed policy", "revision": 0},
            "spec": {"defaults": {"mode": "prompt"}, "rules": rules},
        }},
        "device_id": "device-1",
        "device_name": "Workstation",
    })
}

fn compiled(rules: Value) -> Vec<String> {
    let output = run(&request(rules));
    output["ok"]
        .as_array()
        .unwrap_or_else(|| panic!("compilation refused: {output}"))
        .iter()
        .map(|row| row["rule_id"].as_str().unwrap().to_owned())
        .collect()
}

fn refusal(input: &Value) -> Value {
    run(input)["error"].clone()
}

#[test]
fn a_rule_reaches_this_device_only_when_its_device_list_names_it() {
    assert_eq!(
        compiled(json!([
            rule("every-device", json!({})),
            rule("by-id", json!({"devices": ["device-0", "device-1"]})),
            rule("by-name", json!({"devices": ["Workstation"]})),
            rule("another-device", json!({"devices": ["device-2"]})),
            rule("no-device-named", json!({"devices": []})),
        ])),
        ["every-device", "by-id", "by-name", "no-device-named"],
    );
}

#[test]
fn the_device_list_leaves_the_rule_once_it_has_been_honoured() {
    // ``devices`` is not a selector the local compiler supports, so a rule
    // that still carried one would be refused instead of applied.
    assert_eq!(
        compiled(json!([rule(
            "by-id",
            json!({"devices": ["device-1"], "harnesses": ["claude"]})
        )])),
        ["by-id"],
    );
}

#[test]
fn an_extension_targeted_rule_is_left_to_the_managed_controls_authority() {
    let mut targeted = rule("extension", json!({}));
    targeted["x-hol-extension-targets"] = json!([{"extensionId": "ext-1"}]);
    assert_eq!(
        compiled(json!([targeted, rule("generic", json!({}))])),
        ["generic"],
    );
}

#[test]
fn a_rule_that_is_not_an_object_is_passed_over() {
    assert_eq!(
        compiled(json!(["not-a-rule", null, rule("generic", json!({}))])),
        ["generic"],
    );
}

#[test]
fn a_device_list_that_is_not_a_list_selects_nothing_and_bounds_nothing() {
    assert_eq!(
        compiled(json!([rule("malformed", json!({"devices": "device-2"}))])),
        ["malformed"],
    );
}

#[test]
fn a_bundle_without_compilable_rules_names_what_is_missing() {
    for (payload, code) in [
        (json!({"bundle": {}}), "missing_policy_bundle_payload"),
        (
            json!({"bundle": {"payload": []}}),
            "missing_policy_bundle_payload",
        ),
        (json!({"bundle": {"payload": {}}}), "invalid_policy_spec"),
        (
            json!({"bundle": {"payload": {"spec": {}}}}),
            "invalid_policy_rules",
        ),
        (
            json!({"bundle": {"payload": {"spec": {"rules": {}}}}}),
            "invalid_policy_rules",
        ),
    ] {
        let mut input = payload;
        input["device_id"] = json!("device-1");
        input["device_name"] = json!("Workstation");
        assert_eq!(
            refusal(&input),
            json!({
                "type": "PolicyCompilationError",
                "message": format!("{code}: policy-bundle"),
                "code": code,
                "rule_id": "policy-bundle",
            }),
            "{code}",
        );
    }
}

#[test]
fn a_request_that_names_no_device_is_refused_before_any_rule_is_read() {
    assert_eq!(
        refusal(&json!({"bundle": {"payload": {}}, "device_name": "Workstation"})),
        json!({"type": "TypeError", "message": "policy_bundle_device_identity"}),
    );
}

#[test]
fn an_evaluate_policy_reaches_the_device_without_changing_its_decisions() {
    let rules = json!([rule("every-device", json!({}))]);
    let mut evaluating = request(rules.clone());
    evaluating["bundle"]["payload"]["spec"]["defaults"]["mode"] = json!("observe");
    assert_eq!(run(&evaluating), json!({"ok": []}));
    let mut enforcing = request(rules);
    enforcing["bundle"]["payload"]["spec"]["defaults"]["mode"] = json!("enforce");
    assert_eq!(run(&enforcing)["ok"][0]["rule_id"], "every-device");
}

#[test]
fn an_evaluate_policy_is_still_checked_before_it_is_set_aside() {
    let mut unsupported = rule("unsupported", json!({}));
    unsupported["effect"] = json!("quarantine");
    let mut evaluating = request(json!([unsupported]));
    evaluating["bundle"]["payload"]["spec"]["defaults"]["mode"] = json!("observe");
    assert_eq!(refusal(&evaluating)["code"], "unsupported_policy_effect");
}

#[test]
fn a_bundle_without_defaults_is_refused_rather_than_read_as_enforced() {
    let mut input = request(json!([rule("every-device", json!({}))]));
    input["bundle"]["payload"]["spec"]
        .as_object_mut()
        .unwrap()
        .remove("defaults");
    assert!(refusal(&input).is_object(), "{}", run(&input));
}
