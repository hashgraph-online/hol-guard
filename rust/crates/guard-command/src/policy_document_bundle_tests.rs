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

#[test]
fn a_review_rule_reaches_the_device_as_a_review_decision() {
    let mut review = rule("ask-a-person", json!({}));
    review["effect"] = json!("review");
    let output = run(&request(json!([review])));
    assert_eq!(output["ok"][0]["rule_id"], "ask-a-person", "{output}");
    assert_eq!(output["ok"][0]["decision"]["action"], "review");
    assert_eq!(output["ok"][0]["decision"]["scope"], "global");
}

#[test]
fn a_bundle_rule_outside_allow_block_and_review_is_still_refused() {
    let mut warn = rule("warn-only", json!({}));
    warn["effect"] = json!("warn");
    assert_eq!(
        refusal(&request(json!([warn])))["code"],
        "unsupported_policy_effect"
    );
}

#[test]
fn a_review_rule_on_an_exact_command_is_refused_rather_than_left_unenforced() {
    let mut ask = rule("ask-before-push", json!({"commands": ["git push"]}));
    ask["effect"] = json!("review");
    assert_eq!(
        refusal(&request(json!([ask])))["code"],
        "unsupported_exact_command_review"
    );
}

fn pattern_rule(id: &str, effect: &str, value: &str) -> Value {
    let mut rule = rule(
        id,
        json!({"commands": {"combinator": "all", "conditions": [
            {"field": "command", "operator": "glob", "value": value, "caseSensitive": true}
        ]}}),
    );
    rule["effect"] = json!(effect);
    rule
}

fn patterns(input: &Value) -> Value {
    crate::policy_document::evaluate(
        "command_patterns_bundle",
        input,
        Instant::now() + Duration::from_secs(30),
    )
    .unwrap()
}

#[test]
fn a_pattern_allow_compiles_to_no_row_and_is_read_from_the_bundle() {
    let input = request(json!([
        pattern_rule("pr-view", "allow", "gh pr view * --repo owner/name"),
        rule("every-device", json!({})),
    ]));
    assert_eq!(
        compiled(input["bundle"]["payload"]["spec"]["rules"].clone()),
        ["every-device"]
    );
    let found = patterns(&input)["ok"].clone();
    assert_eq!(found.as_array().map(Vec::len), Some(1), "{found}");
    assert_eq!(found[0]["rule_id"], "pr-view");
    assert_eq!(found[0]["harnesses"], Value::Null);
    assert_eq!(
        found[0]["expression"]["conditions"][0]["value"],
        "gh pr view * --repo owner/name"
    );
}

#[test]
fn a_pattern_may_only_allow() {
    for effect in ["block", "review"] {
        let refused = refusal(&request(json!([pattern_rule("p", effect, "gh pr view *")])));
        assert!(
            refused
                .to_string()
                .contains("command_expression_requires_guard_3_1_runtime"),
            "{effect}: {refused}"
        );
    }
}

#[test]
fn an_unsafe_pattern_refuses_the_bundle() {
    for value in ["git *", "bash -c *", "sudo git push *"] {
        let refused = refusal(&request(json!([pattern_rule("p", "allow", value)])));
        assert!(
            refused.to_string().contains("command_pattern_allow"),
            "{value}: {refused}"
        );
    }
}

#[test]
fn a_pattern_scoped_to_another_device_or_evaluated_allows_nothing() {
    let mut scoped = pattern_rule("p", "allow", "gh pr view *");
    scoped["match"]["devices"] = json!(["device-9"]);
    assert_eq!(patterns(&request(json!([scoped])))["ok"], json!([]));
    let mut input = request(json!([pattern_rule("p", "allow", "gh pr view *")]));
    input["bundle"]["payload"]["spec"]["defaults"]["mode"] = json!("observe");
    assert_eq!(patterns(&input)["ok"], json!([]));
}

#[test]
fn a_pattern_narrowed_by_a_selector_the_hook_cannot_apply_refuses_the_bundle() {
    for (key, value) in [
        ("repositories", json!(["owner/private"])),
        ("domains", json!(["example.test"])),
        ("actors", json!(["someone"])),
        ("artifacts", json!(["skill:x"])),
    ] {
        let mut narrowed = pattern_rule("p", "allow", "gh pr view * --repo owner/name");
        narrowed["match"][key] = value;
        let refused = refusal(&request(json!([narrowed])));
        assert!(
            refused.to_string().contains("unsupported_policy_match"),
            "{key}: {refused}"
        );
    }
    let mut scoped = pattern_rule("p", "allow", "gh pr view * --repo owner/name");
    scoped["match"]["harnesses"] = json!(["codex"]);
    scoped["match"]["workspaces"] = json!(["/work/repo"]);
    scoped["match"]["repositories"] = json!([]);
    scoped["match"]["x-note"] = json!("kept");
    let found = patterns(&request(json!([scoped])))["ok"].clone();
    assert_eq!(found[0]["harnesses"], json!(["codex"]), "{found}");
}
