use super::*;

const PURPOSE: &str = "guard-local-once-approval";
const SIGNED_AT: &str = "2026-07-17T12:00:00+00:00";

fn key_hex() -> String {
    hex::encode([b'k'; 32])
}

fn ask(request: Value) -> Result<Value, String> {
    run_command(request.to_string().as_bytes())
        .map(|bytes| serde_json::from_slice(&bytes).expect("answer is JSON"))
}

fn sign(payload: Value, purpose: &str) -> Value {
    ask(json!({
        "schema": SCHEMA,
        "op": "sign",
        "payload": payload,
        "purpose": purpose,
        "key_hex": key_hex(),
        "key_id": "key-1",
        "signed_at": SIGNED_AT,
    }))
    .expect("signed")
}

fn verify_with(payload: Value, integrity: Value, key_hex: Value, key_id: Value) -> Value {
    ask(json!({
        "schema": SCHEMA,
        "op": "verify",
        "payload": payload,
        "purpose": PURPOSE,
        "key_hex": key_hex,
        "key_id": key_id,
        "integrity": integrity,
    }))
    .expect("verified")
}

fn verify(payload: Value, integrity: Value) -> Value {
    verify_with(payload, integrity, json!(key_hex()), json!("key-1"))
}

/// The columns are the ones the Python signer produced for the same input,
/// so rows signed before the move still verify.
#[test]
fn signing_matches_the_python_signer() {
    let signed = sign(json!({"action": "allow", "note": "caf\u{e9}"}), PURPOSE);
    assert_eq!(
        signed,
        json!({
            "integrity_version": 1,
            "payload_hash": "1609003108d4075c664808a87ee346b93776b41437e9ba3c1b029440428cefcd",
            "payload_mac": "ec48278230a35d95276e0dd6af4dadd756db59f25f39ceebab37233c573e8acf",
            "integrity_key_id": "key-1",
            "signed_at": SIGNED_AT,
        })
    );
}

#[test]
fn a_signed_payload_verifies_only_for_its_purpose_and_bytes() {
    let payload = json!({"action": "allow"});
    let signed = sign(payload.clone(), PURPOSE);
    let valid = verify(payload.clone(), signed.clone());
    assert_eq!(valid["status"], "valid");
    assert_eq!(valid["message"], "hmac-sha256");
    assert_eq!(valid["payload_hash"], signed["payload_hash"]);

    let other_purpose = sign(payload.clone(), "cursor-native-shell-allow");
    assert_ne!(other_purpose["payload_mac"], signed["payload_mac"]);
    let crossed = verify(payload, other_purpose);
    assert_eq!(crossed["status"], "tampered");
    assert_eq!(
        crossed["message"],
        "local_authority_integrity_payload_hash_mismatch"
    );

    let changed = verify(json!({"action": "deny"}), signed.clone());
    assert_eq!(changed["status"], "tampered");

    let mut forged = signed;
    forged["payload_mac"] = json!("0".repeat(64));
    let forged = verify(json!({"action": "allow"}), forged);
    assert_eq!(forged["message"], "local_authority_integrity_mac_mismatch");
}

/// A stored column that is absent or empty is missing integrity, before the
/// key is consulted.
#[test]
fn incomplete_integrity_is_missing_integrity() {
    let payload = json!({"action": "allow"});
    let signed = sign(payload.clone(), PURPOSE);
    for (name, value) in [
        ("integrity_key_id", Value::Null),
        ("integrity_key_id", json!("")),
        ("payload_hash", json!("")),
        ("payload_mac", json!(7)),
        ("signed_at", Value::Null),
        ("integrity_version", json!(true)),
        ("integrity_version", json!("1")),
    ] {
        let mut integrity = signed.clone();
        integrity[name] = value;
        let answer = verify_with(payload.clone(), integrity, Value::Null, Value::Null);
        assert_eq!(answer["status"], "missing_integrity", "{name}");
        assert_eq!(
            answer["message"],
            "local_authority_integrity_metadata_missing"
        );
    }
}

#[test]
fn an_unsupported_version_is_tampered() {
    let payload = json!({"action": "allow"});
    let mut integrity = sign(payload.clone(), PURPOSE);
    integrity["integrity_version"] = json!(2);
    let answer = verify(payload, integrity);
    assert_eq!(answer["status"], "tampered");
    assert_eq!(
        answer["message"],
        "local_authority_integrity_version_unsupported"
    );
}

#[test]
fn a_missing_or_different_key_is_an_unknown_key() {
    let payload = json!({"action": "allow"});
    let signed = sign(payload.clone(), PURPOSE);
    for (key_hex, key_id) in [
        (Value::Null, json!("key-1")),
        (json!(key_hex()), Value::Null),
        (json!(key_hex()), json!("key-2")),
    ] {
        let answer = verify_with(payload.clone(), signed.clone(), key_hex, key_id);
        assert_eq!(answer["status"], "unknown_key");
        assert_eq!(answer["key_id"], "key-1");
    }
}

#[test]
fn requests_are_validated() {
    let base = json!({
        "schema": SCHEMA,
        "op": "sign",
        "payload": {"action": "allow"},
        "purpose": PURPOSE,
        "key_hex": key_hex(),
        "key_id": "key-1",
        "signed_at": SIGNED_AT,
    });
    let mut cases = Vec::new();
    for (name, value) in [
        ("schema", json!("local-authority-integrity.v0")),
        ("op", json!("rotate")),
        ("payload", json!(["allow"])),
        ("key_hex", json!("not-hex")),
        ("key_hex", Value::Null),
        ("signed_at", Value::Null),
        ("integrity", json!({})),
        ("extra", json!(true)),
    ] {
        let mut request = base.clone();
        request[name] = value;
        cases.push(request);
    }
    let mut verify_without_integrity = base.clone();
    verify_without_integrity["op"] = json!("verify");
    verify_without_integrity
        .as_object_mut()
        .unwrap()
        .remove("signed_at");
    cases.push(verify_without_integrity);
    for request in cases {
        assert_eq!(
            ask(request.clone()).expect_err("refused"),
            "local_authority_integrity_request_invalid",
            "{request}"
        );
    }
}

/// Runtime-transition inverses carry whole restored files, well past the
/// size of an approval row.
#[test]
fn a_large_transition_inverse_signs_and_verifies() {
    let payload = json!({"files": ["x".repeat(2 * 1024 * 1024)]});
    let signed = sign(payload.clone(), PURPOSE);
    assert_eq!(verify(payload, signed)["status"], "valid");
}
