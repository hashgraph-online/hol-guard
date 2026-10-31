//! The command frames the native loader and parser for a caller that holds no
//! parser of its own, so the answer it writes back has to carry every field
//! the parsed document holds, and a rejection has to stay a rejection.

use super::*;

use std::fs;

use crate::managed_policy::POLICY_SCHEMA_VERSION;
use tempfile::TempDir;

fn respond_to(request: Value) -> Result<Value, String> {
    let bytes = run_command(request.to_string().as_bytes())?;
    Ok(serde_json::from_slice(&bytes).expect("response json"))
}

fn policy_document() -> Value {
    json!({
        "schemaVersion": POLICY_SCHEMA_VERSION,
        "settings": {"mode": "enforce"},
        "lockedSettings": ["mode"],
        "requiredHarnesses": ["claude-code"],
        "update": {"owner": "mdm", "channel": "stable"},
        "daemonStartup": "login",
    })
}

#[test]
fn a_parsed_document_carries_every_contract_field() {
    let response = respond_to(json!({
        "schema": SCHEMA,
        "op": "parse",
        "payload": policy_document(),
    }))
    .expect("response");

    assert_eq!(response["ok"], json!(true));
    let policy = &response["policy"];
    assert_eq!(policy["schema_version"], json!(POLICY_SCHEMA_VERSION));
    assert_eq!(policy["settings"], json!({"mode": "enforce"}));
    assert_eq!(policy["locked_settings"], json!(["mode"]));
    assert_eq!(policy["required_harnesses"], json!(["claude-code"]));
    assert_eq!(policy["network"]["proxy_mode"], json!("system"));
    assert_eq!(policy["network"]["allow_public_registries"], json!(true));
    assert_eq!(policy["update"]["owner"], json!("mdm"));
    assert_eq!(policy["daemon_startup"], json!("login"));
    assert_eq!(policy["integrity_trust"]["release_public_keys"], json!({}));
    assert_eq!(policy["policy_bundle_keyring"], Value::Null);
    let parsed = parse_managed_policy(&policy_document()).expect("policy");
    assert_eq!(policy["content_hash"], json!(parsed.content_hash));
}

#[test]
fn a_rejected_document_reports_the_parser_message() {
    let mut document = policy_document();
    document["unexpected"] = json!(true);

    let response = respond_to(json!({"schema": SCHEMA, "op": "parse", "payload": document}))
        .expect("response");

    assert_eq!(response["ok"], json!(false));
    assert_eq!(
        response["rejected"],
        json!("unknown policy keys: unexpected")
    );
}

#[test]
fn a_null_document_is_rejected_by_the_parser() {
    let response =
        respond_to(json!({"schema": SCHEMA, "op": "parse", "payload": null})).expect("response");

    assert_eq!(response["ok"], json!(false));
    assert!(response["rejected"]
        .as_str()
        .is_some_and(|message| !message.is_empty()));
}

#[test]
fn an_explicit_path_loads_without_touching_the_machine_cache() {
    let root = TempDir::new().expect("tempdir");
    let path = root.path().join("managed-policy.json");
    fs::write(&path, policy_document().to_string()).expect("write");

    let response = respond_to(json!({
        "schema": SCHEMA,
        "op": "load",
        "policy_path": path,
    }))
    .expect("response");

    let state = &response["state"];
    assert_eq!(state["status"], json!("active"));
    assert_eq!(state["source"], json!(path.to_string_lossy()));
    assert_eq!(state["reason_code"], Value::Null);
    assert_eq!(state["policy"]["settings"]["mode"], json!("enforce"));
}

#[test]
fn a_missing_explicit_path_is_absent() {
    let root = TempDir::new().expect("tempdir");
    let path = root.path().join("missing.json");

    let response =
        respond_to(json!({"schema": SCHEMA, "op": "load", "policy_path": path})).expect("response");

    assert_eq!(response["state"]["status"], json!("absent"));
    assert_eq!(
        response["state"]["reason_code"],
        json!("managed_policy_absent")
    );
    assert_eq!(response["state"]["policy"], Value::Null);
}

#[test]
fn an_unreadable_explicit_document_is_invalid_with_its_detail() {
    let root = TempDir::new().expect("tempdir");
    let path = root.path().join("managed-policy.json");
    fs::write(&path, b"{not json").expect("write");

    let response =
        respond_to(json!({"schema": SCHEMA, "op": "load", "policy_path": path})).expect("response");

    assert_eq!(response["state"]["status"], json!("invalid"));
    assert_eq!(
        response["state"]["reason_code"],
        json!("managed_policy_invalid")
    );
    assert!(response["state"]["detail"].is_string());
}

#[test]
fn release_keys_travel_as_hex() {
    let mut policy = parse_managed_policy(&policy_document()).expect("policy");
    policy
        .integrity_trust
        .release_public_keys
        .insert("release-2026".to_owned(), vec![0xab; 32]);

    let encoded = policy_json(&policy);

    assert_eq!(
        encoded["integrity_trust"]["release_public_keys"]["release-2026"],
        json!("ab".repeat(32))
    );
}

#[test]
fn a_request_that_does_not_fit_the_contract_is_refused() {
    for request in [
        json!({"schema": "managed-policy-load.v0", "op": "load"}),
        json!({"schema": SCHEMA, "op": "write"}),
        json!({"schema": SCHEMA, "op": "load", "payload": {}}),
        json!({"schema": SCHEMA, "op": "parse"}),
        json!({"schema": SCHEMA, "op": "parse", "payload": {}, "policy_path": "/x"}),
        json!({"schema": SCHEMA, "op": "load", "machine_root": "/tmp"}),
    ] {
        assert_eq!(
            respond_to(request).expect_err("refused"),
            "managed_policy_request_invalid"
        );
    }
}
