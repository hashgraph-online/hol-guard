use serde_json::{json, Value};

use super::dispatch;

const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn shape(hint: Value) -> Value {
    dispatch(&json!({ "hint": hint })).expect("hint shape")
}

fn allow() -> Value {
    json!({"schema": "guard.extension-allow-hint.v1", "permission_ids": ["command.p"],
           "rule_ids": ["command.r"], "extension_ids": ["command.e"], "catalog_digest": DIGEST,
           "extra": 1})
}

fn coverage() -> Value {
    json!({"schema": "guard.extension-coverage-hint.v1", "catalog_digest": DIGEST,
           "segments": [
               {"index": 2, "executable": "git", "extension_ids": ["command.git"],
                "rule_ids": [], "permission_ids": ["command.git.push"]},
               {"index": 0, "executable": "bad name", "extension_ids": ["command.npm"],
                "rule_ids": ["command.npm.install"], "permission_ids": []}],
           "segment_total": 3})
}

fn connector() -> Value {
    json!({"schema": "guard.connector-setup-hint.v1", "identity_hash": "a".repeat(64),
           "cli_id": "local-cli.gh@2", "surface": "cli", "display_name": "GitHub CLI",
           "deep_link": "/extensions/local-cli/local-cli.gh%402",
           "card_recommendation": {"state": "allowed", "capabilities": ["read-only"], "x": 1}})
}

#[test]
fn an_allow_hint_is_rebuilt_with_its_relied_permissions_defaulted() {
    let answer = shape(allow());
    assert_eq!(
        answer["allow"],
        json!({"schema": "guard.extension-allow-hint.v1", "permission_ids": ["command.p"],
               "rule_ids": ["command.r"], "extension_ids": ["command.e"],
               "relied_permission_ids": [], "catalog_digest": DIGEST})
    );
    assert_eq!(answer["coverage"], Value::Null);
    assert_eq!(answer["connector"], Value::Null);
    let mut relied_null = allow();
    relied_null["relied_permission_ids"] = Value::Null;
    assert_eq!(shape(relied_null)["allow"], Value::Null);
    let mut empty = allow();
    empty["rule_ids"] = json!([]);
    assert_eq!(shape(empty)["allow"], Value::Null);
}

#[test]
fn a_coverage_hint_is_sorted_and_read_through_an_allow_hint() {
    let expected = json!({"schema": "guard.extension-coverage-hint.v1", "catalog_digest": DIGEST,
        "segments": [
            {"index": 0, "executable": null, "extension_ids": ["command.npm"],
             "rule_ids": ["command.npm.install"], "permission_ids": []},
            {"index": 2, "executable": "git", "extension_ids": ["command.git"],
             "rule_ids": [], "permission_ids": ["command.git.push"]}],
        "segment_total": 3});
    assert_eq!(shape(coverage())["coverage"], expected);
    let mut carried = allow();
    carried["coverage"] = coverage();
    let answer = shape(carried);
    assert_eq!(answer["coverage"], expected);
    assert!(answer["allow"].get("coverage").is_none());
}

#[test]
fn a_coverage_hint_with_a_bad_step_or_total_is_dropped() {
    for (key, bad) in [
        ("segment_total", json!(2)),
        ("segment_total", json!(true)),
        ("segment_total", json!(257)),
        ("segments", json!([])),
        ("catalog_digest", json!(DIGEST.to_uppercase())),
    ] {
        let mut hint = coverage();
        hint[key] = bad;
        assert_eq!(shape(hint)["coverage"], Value::Null, "{key}");
    }
    let mut duplicate = coverage();
    duplicate["segments"][1]["index"] = json!(2);
    assert_eq!(shape(duplicate)["coverage"], Value::Null);
    let mut no_extension = coverage();
    no_extension["segments"][0]["extension_ids"] = json!([]);
    assert_eq!(shape(no_extension)["coverage"], Value::Null);
    let mut float_index = coverage();
    float_index["segments"][0]["index"] = json!(2.0);
    assert_eq!(shape(float_index)["coverage"], Value::Null);
}

#[test]
fn a_connector_hint_is_rebuilt_only_when_every_field_holds() {
    assert_eq!(
        shape(connector())["connector"],
        json!({"schema": "guard.connector-setup-hint.v1", "identity_hash": "a".repeat(64),
               "cli_id": "local-cli.gh@2", "surface": "cli", "display_name": "GitHub CLI",
               "deep_link": "/extensions/local-cli/local-cli.gh%402",
               "card_recommendation": {"state": "allowed", "capabilities": ["read-only"]},
               "risk_classes": []})
    );
    for (key, bad) in [
        ("deep_link", json!("/extensions/local-cli/local-cli.gh@2")),
        ("surface", json!("browser")),
        ("risk_classes", Value::Null),
        ("risk_classes", json!(["Bad"])),
        (
            "card_recommendation",
            json!({"state": "blocked", "capabilities": []}),
        ),
        (
            "card_recommendation",
            json!({"state": "allowed", "capabilities": ["read_only"]}),
        ),
        ("display_name", json!(" GitHub")),
    ] {
        let mut hint = connector();
        hint[key] = bad;
        assert_eq!(shape(hint)["connector"], Value::Null, "{key}");
    }
}

#[test]
fn a_call_without_a_hint_is_refused() {
    assert!(dispatch(&json!({})).is_err());
    assert_eq!(
        shape(json!("text")),
        json!({"allow": null, "coverage": null, "connector": null})
    );
}
