use serde_json::{json, Value};

use super::dispatch;

const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn checked(tool: &str, arguments: Value) -> Value {
    dispatch(&json!({ "tool": tool, "arguments": arguments })).expect("checked arguments")
}

fn error(tool: &str, arguments: Value) -> (String, String) {
    let answer = checked(tool, arguments);
    let error = &answer["error"];
    (
        error["code"].as_str().expect("error code").to_owned(),
        error["message"].as_str().expect("error message").to_owned(),
    )
}

fn create() -> Value {
    json!({"policyYaml": "apiVersion: x", "mode": "replace", "candidateDigest": DIGEST,
           "expectedCurrentDigest": null, "idempotencyKey": "key-0001"})
}

#[test]
fn validate_defaults_to_merge_and_never_repeats_the_policy() {
    assert_eq!(
        checked("validate_policy", json!({"policyYaml": "apiVersion: x"})),
        json!({"value": {"mode": "merge"}})
    );
    assert_eq!(
        checked(
            "validate_policy",
            json!({"policyYaml": "apiVersion: x", "mode": null})
        ),
        json!({"value": {"mode": "merge"}})
    );
}

#[test]
fn the_policy_must_be_present_text_within_the_size_limit() {
    let invalid = "invalid_arguments".to_owned();
    assert_eq!(
        error("validate_policy", json!({})),
        (invalid.clone(), "policyYaml must be a string.".to_owned())
    );
    assert_eq!(
        error("validate_policy", json!({"policyYaml": " \u{1c}\n"})),
        (invalid, "policyYaml must not be empty.".to_owned())
    );
    let oversize = "é".repeat(super::MAX_POLICY_BYTES / 2 + 1);
    assert_eq!(
        error("validate_policy", json!({ "policyYaml": oversize })).0,
        "policy_too_large"
    );
}

#[test]
fn unknown_keys_are_refused_first_and_listed_in_sorted_order() {
    let mut arguments = create();
    arguments["zeta"] = json!(1);
    arguments["it's"] = json!(2);
    arguments["policyYaml"] = json!(3);
    assert_eq!(
        error("create_policy", arguments),
        (
            "invalid_arguments".to_owned(),
            "Unknown arguments: [\"it's\", 'zeta']".to_owned()
        )
    );
}

#[test]
fn create_checks_each_field_in_order() {
    assert_eq!(
        checked("create_policy", create()),
        json!({"value": {"mode": "replace", "candidate_digest": DIGEST,
                         "expected_current_digest": null, "idempotency_key": "key-0001"}})
    );
    let mut arguments = create();
    arguments.as_object_mut().expect("arguments").remove("mode");
    assert_eq!(
        error("create_policy", arguments.clone()).1,
        "mode must be 'merge' or 'replace'."
    );
    arguments["mode"] = json!("merge");
    arguments["candidateDigest"] = json!("short");
    assert_eq!(
        error("create_policy", arguments.clone()).1,
        "candidateDigest must be 64 lowercase hex characters."
    );
    arguments["candidateDigest"] = json!(DIGEST);
    arguments["expectedCurrentDigest"] = json!(DIGEST.to_uppercase());
    assert_eq!(
        error("create_policy", arguments.clone()).1,
        "expectedCurrentDigest must be 64 lowercase hex characters."
    );
    arguments["expectedCurrentDigest"] = json!(DIGEST);
    arguments["idempotencyKey"] = json!("short");
    assert_eq!(
        error("create_policy", arguments).1,
        "idempotencyKey must be 8-128 URL-safe characters [A-Za-z0-9._~-]."
    );
}

#[test]
fn a_trailing_newline_never_passes_a_pattern() {
    let mut arguments = create();
    arguments["candidateDigest"] = json!(format!("{DIGEST}\n"));
    assert_eq!(error("create_policy", arguments).0, "invalid_arguments");
    let request = checked(
        "get_policy_creation",
        json!({"requestId": "abcdefgh12345678\n"}),
    );
    assert_eq!(request["error"]["code"], json!("invalid_arguments"));
}

#[test]
fn get_takes_only_an_alphanumeric_request_id() {
    assert_eq!(
        checked(
            "get_policy_creation",
            json!({"requestId": "abcdefgh12345678"})
        ),
        json!({"value": {"request_id": "abcdefgh12345678"}})
    );
    assert_eq!(
        error("get_policy_creation", json!({})).1,
        "requestId must be 16-64 alphanumeric characters."
    );
    assert_eq!(
        error(
            "get_policy_creation",
            json!({"requestId": "abcdefgh12345678", "policyYaml": "x"})
        )
        .1,
        "Unknown arguments: ['policyYaml']"
    );
}

#[test]
fn an_unknown_tool_or_shape_is_refused() {
    assert!(dispatch(&json!({"tool": "apply_policy", "arguments": {}})).is_err());
    assert!(dispatch(&json!({"tool": "validate_policy", "arguments": []})).is_err());
}
