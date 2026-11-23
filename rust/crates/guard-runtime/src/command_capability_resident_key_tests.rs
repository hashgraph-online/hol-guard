use super::*;
use base64ct::{Base64UrlUnpadded, Encoding};
use guard_contracts::COMMAND_CAPABILITY_REQUEST_SCHEMA;
use serde_json::{json, Value};
use std::collections::BTreeMap;

use crate::command_capability_op::sign_envelope;
use crate::encrypted_secret_store::EncryptedFileSecretStore;
use crate::grok_executable_paths::strip_verbatim;
use crate::policy_integrity_resolver::{
    build_scoped_secret_ref, policy_integrity_secret_material, POLICY_INTEGRITY_KEY_REF,
};

const KEY: &[u8] = b"command-capability-test-key";
const KEY_ID: &str = "key-1";
const DEVICE: &str = "device-1";
const WORKSPACE: &str = "workspace-1";

fn capability(key_b64: &str, key_id: &str) -> Value {
    let unsigned = json!({
        "version": 1,
        "issuer": "guard-cloud",
        "issuedAt": "2026-02-01T00:00:00+00:00",
        "expiresAt": "2026-04-01T00:00:00+00:00",
        "nonce": "nonce-1",
        "deviceId": DEVICE,
        "workspaceId": WORKSPACE,
        "operations": ["guard.app.status"],
    });
    Value::Object(sign_envelope(&unsigned, Some(key_b64), Some(key_id)).expect("signed"))
}

fn request() -> CommandCapabilityRequestV1 {
    let key_b64 = Base64UrlUnpadded::encode_string(KEY);
    CommandCapabilityRequestV1 {
        schema: COMMAND_CAPABILITY_REQUEST_SCHEMA.to_owned(),
        request_id: "request-1".to_owned(),
        capability: capability(&key_b64, KEY_ID),
        integrity_key_b64: Some(key_b64),
        integrity_key_id: Some(KEY_ID.to_owned()),
        device_id: Some(DEVICE.to_owned()),
        workspace_id: Some(WORKSPACE.to_owned()),
        oauth_error: None,
        now: "2026-03-01T00:00:00+00:00".to_owned(),
        job: Value::Null,
        schema_versions: BTreeMap::new(),
        replay_items: Vec::new(),
        replay_identity: Value::Null,
        resident_key: false,
    }
}

fn resident(capability: Value) -> CommandCapabilityRequestV1 {
    let mut request = request();
    request.capability = capability;
    request.integrity_key_b64 = None;
    request.integrity_key_id = None;
    request.resident_key = true;
    request
}

fn answer(request: &CommandCapabilityRequestV1, home: Option<&Path>) -> Value {
    let encoded = evaluate_command_capability_request(request, home).expect("response");
    serde_json::from_slice(&encoded).expect("json")
}

/// Stores a key in the vault the resident reads for `home`, as Python's
/// encrypted-file store writes it, and returns the key and id it derives.
fn store_key(home: &Path) -> (String, String) {
    let home = strip_verbatim(home.canonicalize().expect("home"));
    let key_ref = build_scoped_secret_ref(POLICY_INTEGRITY_KEY_REF, &home);
    let mut secrets = EncryptedFileSecretStore::new(&home);
    secrets
        .set_secret(&key_ref, &Base64UrlUnpadded::encode_string(&[9_u8; 32]))
        .expect("store key");
    let material = policy_integrity_secret_material(&mut secrets, &home).expect("material");
    (
        Base64UrlUnpadded::encode_string(&material.raw_key),
        material.key_id,
    )
}

#[test]
fn the_response_carries_the_request_identity() {
    let response = answer(&request(), None);
    assert_eq!(
        response["schema"],
        Value::from(COMMAND_CAPABILITY_RESULT_SCHEMA)
    );
    assert_eq!(response["request_id"], Value::from("request-1"));
    assert_eq!(response["status"], Value::from("ok"));
    assert_eq!(response["payload"]["capability_valid"], Value::Bool(true));
    assert!(response["request_sha256"]
        .as_str()
        .is_some_and(|digest| digest.starts_with("sha256:")));
}

#[test]
fn a_refused_request_carries_no_payload() {
    let mut request = request();
    request.schema = "other".to_owned();
    let response = answer(&request, None);
    assert_eq!(response["status"], Value::from("error"));
    assert_eq!(
        response["code"],
        Value::from("native_command_capability_schema_mismatch")
    );
    assert_eq!(response.get("payload"), None);
}

#[test]
fn the_resident_verifies_with_the_key_in_its_own_vault() {
    let home = tempfile::tempdir().expect("home");
    let (key_b64, key_id) = store_key(home.path());
    let request = resident(capability(&key_b64, &key_id));
    let response = answer(&request, Some(home.path()));
    assert_eq!(response["status"], Value::from("ok"));
    assert_eq!(response["payload"]["capability_valid"], Value::Bool(true));
    assert_eq!(
        response["request_sha256"],
        Value::from(request_digest(&request).expect("digest"))
    );
}

#[test]
fn a_capability_signed_under_another_key_fails_against_the_vault() {
    let home = tempfile::tempdir().expect("home");
    let (_, key_id) = store_key(home.path());
    let other = Base64UrlUnpadded::encode_string(b"another-key");
    let response = answer(&resident(capability(&other, &key_id)), Some(home.path()));
    assert_eq!(response["payload"]["capability_valid"], Value::Bool(false));
}

#[test]
fn a_resident_with_no_stored_key_or_no_home_has_no_key() {
    let home = tempfile::tempdir().expect("home");
    let key_b64 = Base64UrlUnpadded::encode_string(KEY);
    let request = resident(capability(&key_b64, KEY_ID));
    for home in [Some(home.path()), None] {
        let response = answer(&request, home);
        assert_eq!(response["payload"]["capability_valid"], Value::Bool(false));
        assert_eq!(
            response["payload"]["reason"],
            Value::from("local_signing_key_unavailable")
        );
    }
}

#[test]
fn asking_for_the_resident_key_while_sending_one_is_refused() {
    let mut both = request();
    both.resident_key = true;
    let response = answer(&both, None);
    assert_eq!(response["status"], Value::from("error"));
    assert_eq!(
        response["code"],
        Value::from("native_command_capability_invalid")
    );
    assert_eq!(response.get("payload"), None);
}
