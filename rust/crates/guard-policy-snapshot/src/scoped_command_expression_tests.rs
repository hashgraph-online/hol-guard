use super::*;
use crate::scoped_authority::{ExactPolicyContextInputs, PolicyIdentityInputs};
use serde_json::{json, Value};

fn row(id: u64) -> Value {
    json!({"decision_id":id,"harness":"codex","scope":"global","action":"block",
        "source_kind":"signed-bundle","updated_at_us":id,"artifact_id":null,
        "artifact_hash":null,"workspace":null,"publisher":null,"expires_at_ms":null,
        "exact_command_sha256":null,"requires_exact_context":false})
}

fn binding(id: u64) -> Value {
    json!({"decision_id":id,"expression":{"combinator":"all","conditions":[
        {"field":"command","operator":"startsWith","value":"printf","caseSensitive":true}
    ]}})
}

fn payload(rows: Vec<Value>, bindings: Vec<Value>) -> Value {
    json!({"schema":"guard-native-policy-authority.v1","generic_precedence":"specificity-recency.v1",
        "rows":rows,"managed":null,"command_expressions":bindings})
}

fn authority(value: &Value) -> NativePolicyAuthority {
    NativePolicyAuthority::from_slice(&serde_json::to_vec(value).unwrap()).unwrap()
}

fn request() -> ScopedPolicyRequest {
    ScopedPolicyRequest::from_native_identity(PolicyIdentityInputs {
        harness: "codex",
        artifact_id: Some("codex:project:Shell"),
        artifact_hash: None,
        workspace: Some("/synthetic/project"),
        publisher: Some("synthetic-owner"),
        exact_command_sha256: Some(&"d".repeat(64)),
        exact: ExactPolicyContextInputs::default(),
    })
    .unwrap()
}

#[test]
fn absent_extension_preserves_legacy_canonical_authority_bytes() {
    let mut value = payload(vec![row(1)], vec![]);
    value.as_object_mut().unwrap().remove("command_expressions");
    let legacy = authority(&value);
    assert!(legacy.command_expressions().is_empty());
    assert_eq!(
        serde_json::from_slice::<Value>(&legacy.canonical_bytes().unwrap()).unwrap(),
        value
    );
    assert_eq!(
        legacy
            .select_generic(&request(), 100)
            .unwrap()
            .unwrap()
            .decision_id(),
        1
    );
}

#[test]
fn expression_rows_never_match_via_generic_selector_alone() {
    let policy = authority(&payload(vec![row(1)], vec![binding(1)]));
    assert!(policy.select_generic(&request(), 100).unwrap().is_none());
    let matched = policy
        .matching_command_rows(
            &request(),
            &NormalizedCommand::new("printf synthetic").unwrap(),
            100,
        )
        .unwrap();
    assert_eq!(matched.len(), 1);
    assert_eq!(matched[0].decision_id(), 1);
    assert!(policy
        .matching_command_rows(
            &request(),
            &NormalizedCommand::new("echo synthetic").unwrap(),
            100
        )
        .unwrap()
        .is_empty());
}

#[test]
fn expression_and_every_selector_and_expiry_are_jointly_required() {
    let mut selected = row(1);
    selected["scope"] = json!("workspace");
    selected["artifact_id"] = json!("codex:project:Shell");
    selected["workspace"] = json!("/synthetic/project");
    selected["expires_at_ms"] = json!(201);
    selected["exact_command_sha256"] = json!("d".repeat(64));
    let command = NormalizedCommand::new("printf synthetic").unwrap();
    let value = payload(vec![selected], vec![binding(1)]);
    assert_eq!(
        authority(&value)
            .matching_command_rows(&request(), &command, 200)
            .unwrap()
            .len(),
        1
    );
    assert!(authority(&value)
        .matching_command_rows(&request(), &command, 201)
        .unwrap()
        .is_empty());
    for (key, mismatch) in [
        ("harness", json!("claude-code")),
        ("artifact_id", json!("codex:project:other")),
        ("workspace", json!("/synthetic/other")),
        ("exact_command_sha256", json!("e".repeat(64))),
    ] {
        let mut changed = value.clone();
        changed["rows"][0][key] = mismatch;
        assert!(
            authority(&changed)
                .matching_command_rows(&request(), &command, 200)
                .unwrap()
                .is_empty(),
            "{key}"
        );
    }
    let mut publisher = row(1);
    publisher["scope"] = json!("publisher");
    publisher["publisher"] = json!("other-owner");
    assert!(authority(&payload(vec![publisher], vec![binding(1)]))
        .matching_command_rows(&request(), &command, 100)
        .unwrap()
        .is_empty());
}

#[test]
fn all_matching_expression_restrictions_survive_generic_recency_and_specificity() {
    let mut newer = row(2);
    newer["scope"] = json!("artifact");
    newer["artifact_id"] = json!("codex:project:Shell");
    newer["action"] = json!("allow");
    newer["updated_at_us"] = json!(999);
    let policy = authority(&payload(vec![row(1), newer], vec![binding(1), binding(2)]));
    let command = NormalizedCommand::new("printf synthetic").unwrap();
    let matched = policy
        .matching_command_rows(&request(), &command, 100)
        .unwrap();
    assert_eq!(
        matched
            .iter()
            .map(|row| row.decision_id())
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
    assert!(policy.select_generic(&request(), 100).unwrap().is_none());
}

#[test]
fn associations_refuse_duplicate_orphan_unsigned_and_malformed_values() {
    let mut values = vec![
        payload(vec![row(1)], vec![binding(2)]),
        payload(vec![row(1), row(2)], vec![binding(1), binding(1)]),
    ];
    for source in ["local", "signed-memory"] {
        let mut value = payload(vec![row(1)], vec![binding(1)]);
        value["rows"][0]["source_kind"] = json!(source);
        values.push(value);
    }
    for invalid in [json!(true), json!(1.0), json!("1"), json!(0)] {
        let mut value = payload(vec![row(1)], vec![binding(1)]);
        value["command_expressions"][0]["decision_id"] = invalid;
        values.push(value);
    }
    for invalid in [Value::Null, json!({}), json!("unknown")] {
        let mut value = payload(vec![row(1)], vec![binding(1)]);
        value["command_expressions"] = invalid;
        values.push(value);
    }
    let mut extra = payload(vec![row(1)], vec![binding(1)]);
    extra["command_expressions"][0]["unknown"] = json!(true);
    values.push(extra);
    for value in values {
        assert!(NativePolicyAuthority::from_slice(&serde_json::to_vec(&value).unwrap()).is_err());
    }
}

#[test]
fn unsupported_expression_clause_refuses_complete_authority_and_changes_content_digest() {
    let valid = payload(vec![row(1)], vec![binding(1)]);
    let mut different = valid.clone();
    different["command_expressions"][0]["expression"]["conditions"][0]["value"] = json!("echo");
    assert_ne!(
        authority(&valid).content_digest().unwrap(),
        authority(&different).content_digest().unwrap()
    );
    for (key, invalid) in [
        ("operator", json!("regex")),
        ("caseSensitive", json!(false)),
        ("value", json!(" printf")),
    ] {
        let mut value = valid.clone();
        value["command_expressions"][0]["expression"]["conditions"][0][key] = invalid;
        assert!(NativePolicyAuthority::from_slice(&serde_json::to_vec(&value).unwrap()).is_err());
    }
}
