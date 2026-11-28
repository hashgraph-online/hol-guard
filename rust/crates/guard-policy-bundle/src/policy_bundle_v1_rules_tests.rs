use serde_json::{json, Value};

use super::{rule_is_valid, BROWSER_SCOPE_KEYS};
use crate::policy_bundle_decisions::build;
use crate::policy_bundle_families::has_unknown_constraints;

fn rule(scope: Value) -> Value {
    json!({
        "ruleId": "browser-rule",
        "action": "allow",
        "reason": "routine browser work on a local page",
        "matcherFamilies": ["mcp"],
        "scope": scope,
    })
}

#[test]
fn verb_site_group_and_driver_scopes_are_accepted() {
    let scoped = rule(json!({
        "browserVerb": ["click", "type", "cookie_read", "tab_control"],
        "siteGroup": ["example-org.co.uk"],
        "browserDriver": ["playwright-mcp"],
    }));
    assert!(rule_is_valid(&scoped));
}

#[test]
fn a_verb_outside_the_contract_is_rejected() {
    for verb in ["press", "Click", "cookie-read", ""] {
        let scoped = rule(json!({ "browserVerb": [verb] }));
        assert!(!rule_is_valid(&scoped), "{verb:?} was accepted");
    }
}

#[test]
fn the_new_scopes_must_be_string_lists() {
    for key in ["browserVerb", "siteGroup", "browserDriver"] {
        for value in [json!("click"), json!([1]), json!({ "a": "b" })] {
            let mut scope = serde_json::Map::new();
            scope.insert(key.to_owned(), value.clone());
            assert!(
                !rule_is_valid(&rule(Value::Object(scope))),
                "{key} accepted {value}"
            );
        }
    }
}

#[test]
fn a_rule_scoped_by_the_new_keys_is_not_saved_as_an_unscoped_decision() {
    let device = "device-1";
    let plain = json!({ "rules": [rule(json!({}))] });
    assert!(!build(plain.as_object().unwrap(), device, device).is_empty());
    for key in ["browserVerb", "siteGroup", "browserDriver"] {
        let mut scope = serde_json::Map::new();
        scope.insert(key.to_owned(), json!(["click"]));
        let bundle = json!({ "rules": [rule(Value::Object(scope))] });
        assert!(
            build(bundle.as_object().unwrap(), device, device).is_empty(),
            "a {key} scope widened into an unscoped decision"
        );
        let mut top_level = rule(json!({}));
        top_level[key] = json!(["click"]);
        assert!(!has_unknown_constraints(top_level.as_object().unwrap()));
        let bundle = json!({ "rules": [top_level] });
        assert!(build(bundle.as_object().unwrap(), device, device).is_empty());
    }
}

#[test]
fn the_browser_scope_keys_stay_sorted_and_unique() {
    let mut sorted = BROWSER_SCOPE_KEYS.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted, BROWSER_SCOPE_KEYS.to_vec());
}
