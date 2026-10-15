use super::*;

const FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../tests/fixtures/policy_effective_parity.json"
));

fn call(request: &Value) -> Value {
    let bytes = evaluate(request.to_string().as_bytes()).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn base() -> Value {
    json!({"protection_posture": "protected", "security_level": "balanced", "mode": "prompt"})
}

/// The legacy composer reported a distinct reason for provider actions; the
/// caller treats every policy rejection alike, so both map to one reason.
fn reason(value: &Value) -> &str {
    match value.as_str().unwrap_or_default() {
        "native_policy_snapshot_provider_actions_invalid" => POLICY_INVALID,
        other => other,
    }
}

#[test]
fn python_parity_vectors_match() {
    let cases: Vec<Value> = serde_json::from_str(FIXTURE).unwrap();
    assert!(cases.len() > 80);
    let mut mismatches = Vec::new();
    for case in &cases {
        let request = json!({
            "schema": SCHEMA,
            "op": case["op"],
            "guard_config": case["guard_config"],
            "configs": case["configs"],
        });
        let actual = call(&request);
        let expected = &case["expected"];
        let matched = if expected["ok"] == json!(true) {
            actual["ok"] == json!(true) && actual["policy"] == expected["policy"]
        } else {
            actual["ok"] == json!(false) && reason(&actual["error"]) == reason(&expected["error"])
        };
        if !matched {
            mismatches.push(format!(
                "{}: expected {expected} got {actual}",
                case["name"]
            ));
        }
    }
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
}

#[test]
fn unknown_request_fields_and_schema_are_rejected() {
    let bad = json!({"schema": SCHEMA, "op": "effective", "configs": [base()], "extra": 1});
    assert!(evaluate(bad.to_string().as_bytes()).is_err());
    let wrong = json!({"schema": "other", "op": "effective", "configs": [base()]});
    assert_eq!(call(&wrong)["ok"], json!(false));
    let unknown_op = json!({"schema": SCHEMA, "op": "merge", "configs": [base()]});
    assert_eq!(call(&unknown_op)["ok"], json!(false));
}

#[test]
fn effective_needs_exactly_one_config_and_compose_at_least_one() {
    let two = json!({"schema": SCHEMA, "op": "effective", "configs": [base(), base()]});
    assert_eq!(call(&two)["ok"], json!(false));
    let none = json!({"schema": SCHEMA, "op": "compose", "configs": []});
    assert_eq!(call(&none)["ok"], json!(false));
}

#[test]
fn compose_never_downgrades_an_enforcing_posture() {
    let mut watch = base();
    watch["protection_posture"] = json!("watch");
    watch["mode"] = json!("observe");
    let request = json!({"schema": SCHEMA, "op": "compose", "configs": [watch, base()]});
    let response = call(&request);
    assert_eq!(response["policy"]["protection_posture"], json!("protected"));
    assert_eq!(response["policy"]["mode"], json!("enforce"));
}

#[test]
fn oversized_request_is_rejected_before_parsing() {
    let big = vec![b' '; MAX_REQUEST_BYTES as usize + 1];
    assert_eq!(
        run_command(&big[..]).unwrap_err(),
        "policy_effective_request_too_large"
    );
    assert_eq!(
        run_command(&b"not json"[..]).unwrap_err(),
        "policy_effective_request_invalid"
    );
}
