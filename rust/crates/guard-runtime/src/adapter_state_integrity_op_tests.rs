use base64ct::{Base64UrlUnpadded, Encoding};
use guard_contracts::{
    AdapterStateIntegrityRequestV1, AdapterStateIntegrityResultV1,
    ADAPTER_STATE_ACTION_AUTHENTICATE, ADAPTER_STATE_ACTION_FIELD, ADAPTER_STATE_ACTION_VERIFY,
    ADAPTER_STATE_INTEGRITY_REQUEST_SCHEMA, ADAPTER_STATE_INTEGRITY_RESULT_SCHEMA,
};
use serde_json::{json, Value};

use super::evaluate_adapter_state_integrity_request;

const KEY: &[u8] = b"0123456789abcdef0123456789abcdef";
const OTHER_KEY: &[u8] = b"fedcba9876543210fedcba9876543210";
const KEY_ID: &str = "4f1c2b3a5d6e7f8091a2b3c4";

fn key_b64(key: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(key)
}

fn manifest() -> Value {
    json!({
        "backup_path": "/home/dev/.config/copilot/config.json.hol-guard-backup",
        "managed_config_path": "/home/dev/.config/copilot/config.json",
        "scope": "user",
        "workspace_dir": Value::Null,
    })
}

fn request(action: &str, payload: Value) -> AdapterStateIntegrityRequestV1 {
    AdapterStateIntegrityRequestV1 {
        schema: ADAPTER_STATE_INTEGRITY_REQUEST_SCHEMA.to_owned(),
        request_id: "req-1".to_owned(),
        action: action.to_owned(),
        harness: "copilot".to_owned(),
        payload,
        field: None,
        integrity_key_b64: Some(key_b64(KEY)),
        integrity_key_id: Some(KEY_ID.to_owned()),
    }
}

fn answer(request: &AdapterStateIntegrityRequestV1) -> AdapterStateIntegrityResultV1 {
    let encoded = evaluate_adapter_state_integrity_request(request).expect("response");
    serde_json::from_slice(&encoded).expect("result")
}

fn authenticated(payload: Value) -> Value {
    let result = answer(&request(ADAPTER_STATE_ACTION_AUTHENTICATE, payload));
    assert_eq!(result.status, "ok", "{}", result.code);
    result.payload.expect("payload")
}

#[test]
fn authenticate_then_verify_round_trips() {
    let stamped = authenticated(manifest());
    assert_eq!(
        stamped["state_authentication"]["algorithm"],
        json!("hmac-sha256")
    );
    assert_eq!(stamped["state_authentication"]["key_id"], json!(KEY_ID));
    assert_eq!(stamped["state_authentication"]["schema_version"], json!(1));

    let result = answer(&request(ADAPTER_STATE_ACTION_VERIFY, stamped));
    assert_eq!(result.schema, ADAPTER_STATE_INTEGRITY_RESULT_SCHEMA);
    assert_eq!(
        result.payload.expect("payload")["authenticated"],
        json!(true)
    );
}

/// The MAC is the only thing standing between an edited manifest and the file
/// Guard restores over, so an edited path must not verify.
#[test]
fn edited_path_does_not_verify() {
    let mut stamped = authenticated(manifest());
    stamped["managed_config_path"] = json!("/home/dev/.ssh/authorized_keys");

    let result = answer(&request(ADAPTER_STATE_ACTION_VERIFY, stamped));
    assert_eq!(
        result.payload.expect("payload")["authenticated"],
        json!(false)
    );
}

#[test]
fn another_harness_does_not_verify() {
    let stamped = authenticated(manifest());
    let mut probe = request(ADAPTER_STATE_ACTION_VERIFY, stamped);
    probe.harness = "hermes".to_owned();

    assert_eq!(
        answer(&probe).payload.expect("payload")["authenticated"],
        json!(false)
    );
}

#[test]
fn another_key_does_not_verify() {
    let stamped = authenticated(manifest());
    let mut probe = request(ADAPTER_STATE_ACTION_VERIFY, stamped);
    probe.integrity_key_b64 = Some(key_b64(OTHER_KEY));

    assert_eq!(
        answer(&probe).payload.expect("payload")["authenticated"],
        json!(false)
    );
}

#[test]
fn another_key_id_does_not_verify() {
    let stamped = authenticated(manifest());
    let mut probe = request(ADAPTER_STATE_ACTION_VERIFY, stamped);
    probe.integrity_key_id = Some("00000000000000000000000f".to_owned());

    assert_eq!(
        answer(&probe).payload.expect("payload")["authenticated"],
        json!(false)
    );
}

#[test]
fn a_missing_or_malformed_block_does_not_verify() {
    for payload in [
        manifest(),
        json!({"managed_config_path": "/tmp/a", "state_authentication": "yes"}),
        json!({
            "managed_config_path": "/tmp/a",
            "state_authentication": {
                "algorithm": "hmac-sha1",
                "key_id": KEY_ID,
                "mac": "00",
                "schema_version": 1,
            },
        }),
        json!({
            "managed_config_path": "/tmp/a",
            "state_authentication": {
                "algorithm": "hmac-sha256",
                "key_id": KEY_ID,
                "mac": "00",
                "schema_version": 2,
            },
        }),
        json!({
            "managed_config_path": "/tmp/a",
            "state_authentication": {
                "algorithm": "hmac-sha256",
                "key_id": KEY_ID,
                "mac": 17,
                "schema_version": 1,
            },
        }),
    ] {
        let result = answer(&request(ADAPTER_STATE_ACTION_VERIFY, payload));
        assert_eq!(
            result.payload.expect("payload")["authenticated"],
            json!(false)
        );
    }
}

#[test]
fn an_authenticated_field_comes_back_only_when_absolute() {
    let stamped = authenticated(manifest());
    let mut probe = request(ADAPTER_STATE_ACTION_FIELD, stamped);
    probe.field = Some("managed_config_path".to_owned());
    let payload = answer(&probe).payload.expect("payload");
    assert_eq!(payload["authenticated"], json!(true));
    assert_eq!(
        payload["value"],
        json!("/home/dev/.config/copilot/config.json")
    );

    for (field, value) in [
        ("workspace_dir", Value::Null),
        ("scope", json!("user")),
        ("missing", Value::Null),
    ] {
        let stamped = authenticated(json!({
            "managed_config_path": "/home/dev/.config/copilot/config.json",
            "scope": value,
            "workspace_dir": Value::Null,
        }));
        let mut probe = request(ADAPTER_STATE_ACTION_FIELD, stamped);
        probe.field = Some(field.to_owned());
        let payload = answer(&probe).payload.expect("payload");
        assert_eq!(payload["authenticated"], json!(true));
        assert_eq!(payload["value"], Value::Null, "{field}");
    }
}

#[test]
fn a_windows_path_is_absolute_and_a_relative_one_is_not() {
    for (value, expected) in [
        ("C:\\Users\\dev\\config.json", true),
        ("\\\\server\\share\\config.json", true),
        ("config.json", false),
        ("../config.json", false),
        ("", false),
        ("/home/dev/co\0nfig.json", false),
    ] {
        let stamped = authenticated(json!({ "managed_config_path": value }));
        let mut probe = request(ADAPTER_STATE_ACTION_FIELD, stamped);
        probe.field = Some("managed_config_path".to_owned());
        let payload = answer(&probe).payload.expect("payload");
        assert_eq!(payload["value"] != Value::Null, expected, "{value:?}");
    }
}

#[test]
fn an_unauthenticated_field_comes_back_null() {
    let mut probe = request(ADAPTER_STATE_ACTION_FIELD, manifest());
    probe.field = Some("managed_config_path".to_owned());
    let payload = answer(&probe).payload.expect("payload");
    assert_eq!(payload["authenticated"], json!(false));
    assert_eq!(payload["value"], Value::Null);
}

#[test]
fn a_request_the_runtime_cannot_answer_is_refused() {
    let mut wrong_schema = request(ADAPTER_STATE_ACTION_VERIFY, manifest());
    wrong_schema.schema = "guard-adapter-state-integrity-request.v2".to_owned();
    assert_eq!(
        answer(&wrong_schema).code,
        "native_adapter_state_integrity_schema_mismatch"
    );

    let mut wrong_action = request("sign", manifest());
    wrong_action.schema = ADAPTER_STATE_INTEGRITY_REQUEST_SCHEMA.to_owned();
    assert_eq!(
        answer(&wrong_action).code,
        "native_adapter_state_integrity_action_unsupported"
    );

    let mut no_field = request(ADAPTER_STATE_ACTION_FIELD, manifest());
    no_field.field = None;
    assert_eq!(
        answer(&no_field).code,
        "native_adapter_state_integrity_invalid"
    );

    let not_an_object = request(ADAPTER_STATE_ACTION_VERIFY, json!([1, 2, 3]));
    assert_eq!(
        answer(&not_an_object).code,
        "native_adapter_state_integrity_invalid"
    );

    let mut no_key = request(ADAPTER_STATE_ACTION_AUTHENTICATE, manifest());
    no_key.integrity_key_b64 = None;
    assert_eq!(
        answer(&no_key).code,
        "native_adapter_state_integrity_key_unavailable"
    );
}

/// A caller that sees the binding digest must learn nothing about the key it
/// sent, so two requests that differ only by key digest the same.
#[test]
fn the_request_digest_excludes_the_key() {
    let first = request(ADAPTER_STATE_ACTION_VERIFY, manifest());
    let mut second = first.clone();
    second.integrity_key_b64 = Some(key_b64(OTHER_KEY));

    let first = answer(&first);
    assert!(first.request_sha256.starts_with("sha256:"));
    assert_eq!(first.request_sha256, answer(&second).request_sha256);

    let mut different = request(ADAPTER_STATE_ACTION_VERIFY, manifest());
    different.harness = "hermes".to_owned();
    assert_ne!(first.request_sha256, answer(&different).request_sha256);
}
