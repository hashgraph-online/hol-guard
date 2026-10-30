//! Review signature kinds: key admission, signature verdicts, and the base64
//! reading CPython gives a signature field.

use guard_contracts::{PolicyBundleAuthorityRequestV1, POLICY_BUNDLE_AUTHORITY_REQUEST_SCHEMA};
use serde_json::{json, Value};

use crate::policy_bundle_op::evaluate_policy_bundle_authority_request;
use crate::policy_bundle_op_review::lenient_base64_decode;

const PUBLIC_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqPje7eGxgUF66/IETV5d\ncd+JcadQQ9pkJ7/KsqvJEaLclr6CScJqKzwVZL3nBDBegh0xKNnYlZ1lBP1urI9g\nup9/TpRYaD/ptxRY7lxF47SxwvBqq9YwTCD/gK2uK45LFJehRYb6Vt1SixjCRadJ\nWCC+oVquvWEMAu+hz8T/dInWL7usPjbZSwJ/eonmCqOvt+8kFwYyAAdJd7ObcW+q\nf6OzMtxlPkbPA8N6z/wpyCDBVNO0NttN3CN2OtAcbzWPX+M/TXBXn2zEsIMPXtYx\nNxGV+SKYWAqyWtQUcfuMKhdZSFhXUAsf8WXZcYmwi0TB3bTJ1i1K603wEPW71j/f\n3QIDAQAB\n-----END PUBLIC KEY-----\n";
const FINGERPRINT: &str = "2d6b2ac8904b58df21462538b9e6a6d7bd76e4becefd09e3bfd74fa80f831b41";
const SIGNATURE: &str = "CrZxYaFX/agrrPn4emucbtAI5fpT5GjEQIgFH4s93BubtQ5q///IP/1vUAjmeb4j7r3exfzEia02RPgJujEcNpybOXn1px1pIXjCse2wWflL0U6cqrchi2yscgdofCtWUNTTcL+a3l/3CrtCzq3X7f4jLoSZvUGsjhvqMkhXMYvyUNFBYq4kkezZbxa/ZRw7D8P12xeqReEYhgvjaXs9KLPVGZ25rjPWnZhk82XdahuxIHWXQTR0TDIu2DGppvg6rURuQ32/UBus40DC8r5Va0Uw9XZcNC9yBgDRdQudfOOZg+UIl0pzqlovj2VFM5OMNrMC24FgYVxPw9dA1xk4Kw==";
const OTHER_PUBLIC_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAq5XeuPrqkFqsZ8hAz6aA\nKVGJz6xpWoUFfXmpEXtxJPzOBUztuJvUkPG7Sc8eLHYami0oJx/yn8RugpF+9shb\n/0PEkwirZzz9KccxEivKLiXdaYwjh2S+YQfXiIRwh/R1t3c/S7TZL01TSVTz+1Xk\nbHIm47yiRX2pK6BOxHT/SSQ24Rlo/PTvhyJOs+9/o6stO0/KgkZCvflxzQXgx3mx\nSnoIysTc5gAXCdADePXIfW8NdqCrazO5y3RztqUsbs2BptPVTSNRVzh83nMBHZpp\nc1CASSB10Ds2Etb6I/zvX00Z9YeI5tImyFwbEH7E6dx55Om7121l3smPuFzrjXgt\nBwIDAQAB\n-----END PUBLIC KEY-----\n";
const OTHER_FINGERPRINT: &str = "dca75daecb4f5b1995d357a76540244bb996ac39672829d57bd420cdfd396281";

const NOW: f64 = 1_762_000_000.0;

fn call(kind: &str, input: Value) -> Value {
    let request = PolicyBundleAuthorityRequestV1 {
        schema: POLICY_BUNDLE_AUTHORITY_REQUEST_SCHEMA.to_owned(),
        request_id: "req-review".to_owned(),
        kind: kind.to_owned(),
        input,
    };
    let response =
        serde_json::to_value(evaluate_policy_bundle_authority_request(&request)).unwrap();
    assert_eq!(response["status"], "ok", "{response}");
    response["result"].clone()
}

fn error_of(result: &Value) -> &str {
    result["error"]
        .as_str()
        .unwrap_or_else(|| panic!("expected a rejection, got {result}"))
}

fn key(key_id: &str, pem: &str, fingerprint: &str) -> Value {
    json!({
        "keyId": key_id,
        "publicKeyPem": pem,
        "fingerprintSha256": fingerprint,
        "state": "active",
        "purpose": "remote_approval",
        "workspaceId": "ws-1",
    })
}

fn signing_key() -> Value {
    key("key-1", PUBLIC_KEY_PEM, FINGERPRINT)
}

/// The signed envelope the fixture signature covers.
fn envelope() -> Value {
    json!({
        "approvalId": "approval-1",
        "workspaceId": "ws-1",
        "issuerKeyId": "key-1",
        "signatureAlgorithm": "rsa-pss-sha256",
        "verificationKeys": [signing_key()],
        "signature": SIGNATURE,
    })
}

fn verify(payload: &Value, anchored: Value) -> Value {
    verify_scoped(payload, anchored, json!("remote_approval"), json!("ws-1"))
}

fn verify_scoped(payload: &Value, anchored: Value, purpose: Value, workspace: Value) -> Value {
    call(
        "verify_signed_review_payload",
        json!({
            "signature_algorithm": "rsa-pss-sha256",
            "payload_chunks": [serde_json::to_string(payload).unwrap()],
            "anchored_keys": anchored,
            "expected_purpose": purpose,
            "expected_workspace_id": workspace,
            "now": NOW,
        }),
    )
}

#[test]
fn an_anchored_signature_verifies() {
    assert_eq!(
        verify(&envelope(), json!([signing_key()])),
        json!({"verified": true})
    );
}

#[test]
fn a_decision_memory_bundle_needs_no_scope() {
    assert_eq!(
        verify_scoped(
            &envelope(),
            json!([signing_key()]),
            Value::Null,
            Value::Null
        ),
        json!({"verified": true})
    );
}

#[test]
fn the_key_id_may_come_from_the_verifier_or_a_single_advertised_key() {
    let mut payload = envelope();
    let object = payload.as_object_mut().unwrap();
    object.remove("issuerKeyId");
    object.insert("verifier".to_owned(), json!({"keyId": "key-1"}));
    // `issuerKeyId` is part of the signed material, so dropping it breaks the
    // signature; the verdict proves the id was still resolved and anchored.
    assert_eq!(
        error_of(&verify(&payload, json!([signing_key()]))),
        "signature_mismatch"
    );
    payload.as_object_mut().unwrap().remove("verifier");
    assert_eq!(
        error_of(&verify(&payload, json!([signing_key()]))),
        "signature_mismatch"
    );
}

#[test]
fn an_unnamed_key_needs_exactly_one_advertised_key() {
    let mut payload = envelope();
    let object = payload.as_object_mut().unwrap();
    object.remove("issuerKeyId");
    object.insert(
        "verificationKeys".to_owned(),
        json!([
            signing_key(),
            key("key-2", OTHER_PUBLIC_KEY_PEM, OTHER_FINGERPRINT)
        ]),
    );
    assert_eq!(
        error_of(&verify(&payload, json!([signing_key()]))),
        "missing_signing_key_id"
    );
}

#[test]
fn a_tampered_payload_fails_the_signature() {
    let mut payload = envelope();
    payload.as_object_mut().unwrap()["approvalId"] = json!("approval-2");
    assert_eq!(
        error_of(&verify(&payload, json!([signing_key()]))),
        "signature_mismatch"
    );
}

#[test]
fn the_algorithm_and_signature_fields_are_required() {
    let wrong_algorithm = call(
        "verify_signed_review_payload",
        json!({
            "signature_algorithm": "rsa-pss-sha512",
            "payload_chunks": [serde_json::to_string(&envelope()).unwrap()],
            "anchored_keys": [signing_key()],
            "expected_purpose": "remote_approval",
            "expected_workspace_id": "ws-1",
            "now": NOW,
        }),
    );
    assert_eq!(error_of(&wrong_algorithm), "invalid_signature_algorithm");

    let mut blank = envelope();
    blank.as_object_mut().unwrap()["signature"] = json!("   ");
    assert_eq!(
        error_of(&verify(&blank, json!([signing_key()]))),
        "missing_signature"
    );

    let mut undecodable = envelope();
    undecodable.as_object_mut().unwrap()["signature"] = json!("A");
    assert_eq!(
        error_of(&verify(&undecodable, json!([signing_key()]))),
        "invalid_signature"
    );
}

#[test]
fn the_advertised_keyring_must_be_a_non_empty_list_of_keys() {
    let mut missing = envelope();
    missing.as_object_mut().unwrap().remove("verificationKeys");
    assert_eq!(
        error_of(&verify(&missing, json!([signing_key()]))),
        "missing_verification_keys"
    );

    let mut empty = envelope();
    empty.as_object_mut().unwrap()["verificationKeys"] = json!([]);
    assert_eq!(
        error_of(&verify(&empty, json!([signing_key()]))),
        "missing_verification_keys"
    );

    let mut not_an_object = envelope();
    not_an_object.as_object_mut().unwrap()["verificationKeys"] = json!(["key-1"]);
    assert_eq!(
        error_of(&verify(&not_an_object, json!([signing_key()]))),
        "invalid_verification_key"
    );

    let mut malformed = envelope();
    malformed.as_object_mut().unwrap()["verificationKeys"] = json!([{"keyId": "key-1"}]);
    assert_eq!(
        error_of(&verify(&malformed, json!([signing_key()]))),
        "invalid_policy_bundle_verification_key:publicKeyPem"
    );
}

#[test]
fn a_key_is_admitted_only_when_the_anchored_keyring_agrees() {
    assert_eq!(
        error_of(&verify(&envelope(), json!([]))),
        "unknown_signing_key"
    );

    let mut advertises_another = envelope();
    advertises_another.as_object_mut().unwrap()["verificationKeys"] =
        json!([key("key-2", OTHER_PUBLIC_KEY_PEM, OTHER_FINGERPRINT)]);
    assert_eq!(
        error_of(&verify(&advertises_another, json!([signing_key()]))),
        "missing_signing_key"
    );

    let mut impersonates = envelope();
    impersonates.as_object_mut().unwrap()["verificationKeys"] =
        json!([key("key-1", OTHER_PUBLIC_KEY_PEM, OTHER_FINGERPRINT)]);
    assert_eq!(
        error_of(&verify(&impersonates, json!([signing_key()]))),
        "untrusted_signing_key"
    );
}

#[test]
fn the_anchored_key_carries_the_expected_scope_and_window() {
    let mut unscoped = signing_key();
    unscoped.as_object_mut().unwrap()["purpose"] = json!("unscoped");
    assert_eq!(
        error_of(&verify(&envelope(), json!([unscoped]))),
        "signing_key_purpose_mismatch"
    );

    let mut elsewhere = signing_key();
    elsewhere.as_object_mut().unwrap()["workspaceId"] = json!("ws-2");
    assert_eq!(
        error_of(&verify(&envelope(), json!([elsewhere]))),
        "signing_key_workspace_mismatch"
    );

    let mut expired = signing_key();
    expired
        .as_object_mut()
        .unwrap()
        .insert("validUntil".to_owned(), json!("2020-01-01T00:00:00Z"));
    assert_eq!(
        error_of(&verify(&envelope(), json!([expired]))),
        "expired_signing_key"
    );

    let mut revoked = signing_key();
    revoked.as_object_mut().unwrap()["state"] = json!("revoked");
    assert_eq!(
        error_of(&verify(&envelope(), json!([revoked]))),
        "expired_signing_key"
    );
}

#[test]
fn an_unparsable_anchored_key_is_not_a_signature_verdict() {
    let mut junk = signing_key();
    junk.as_object_mut().unwrap()["publicKeyPem"] = json!("not a pem");
    assert_eq!(
        error_of(&verify(&envelope(), json!([junk]))),
        "invalid_signing_key"
    );
}

fn sync(raw: Value, anchored: Value) -> Value {
    call(
        "validate_review_sync_keys",
        json!({
            "raw": raw,
            "anchored_keys": anchored,
            "workspace_id": "ws-1",
            "now": NOW,
        }),
    )
}

#[test]
fn synced_review_keys_are_admitted_when_already_anchored() {
    let result = sync(json!([signing_key()]), json!([signing_key()]));
    let keys = result["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["keyId"], "key-1");
    assert_eq!(keys[0]["fingerprintSha256"], FINGERPRINT);
}

#[test]
fn synced_review_keys_must_load_whole() {
    assert_eq!(
        error_of(&sync(json!({}), json!([signing_key()]))),
        "review_verification_keys_invalid"
    );
    assert_eq!(
        error_of(&sync(json!([]), json!([signing_key()]))),
        "review_verification_keys_invalid"
    );
    assert_eq!(
        error_of(&sync(
            json!([signing_key(), {"keyId": "key-2"}]),
            json!([signing_key()])
        )),
        "review_verification_keys_invalid"
    );
}

#[test]
fn synced_review_keys_carry_scope_and_anchoring() {
    let mut unscoped = signing_key();
    unscoped.as_object_mut().unwrap()["purpose"] = json!("unscoped");
    assert_eq!(
        error_of(&sync(json!([unscoped]), json!([signing_key()]))),
        "signing_key_purpose_mismatch"
    );

    let mut elsewhere = signing_key();
    elsewhere.as_object_mut().unwrap()["workspaceId"] = json!("ws-2");
    assert_eq!(
        error_of(&sync(json!([elsewhere.clone()]), json!([elsewhere]))),
        "signing_key_workspace_mismatch"
    );

    assert_eq!(
        error_of(&sync(json!([signing_key()]), json!([]))),
        "unknown_signing_key"
    );

    let mut expired = signing_key();
    expired
        .as_object_mut()
        .unwrap()
        .insert("validUntil".to_owned(), json!("2020-01-01T00:00:00Z"));
    assert_eq!(
        error_of(&sync(json!([expired]), json!([signing_key()]))),
        "expired_signing_key"
    );
}

/// Measured against CPython 3.12 `base64.b64decode(value)`.
#[test]
fn the_decoder_reads_a_signature_the_way_cpython_does() {
    let hex = |value: &str| lenient_base64_decode(value).map(hex::encode);
    assert_eq!(hex("AAAA").as_deref(), Some("000000"));
    assert_eq!(hex("AA==").as_deref(), Some("00"));
    assert_eq!(hex("AAA=").as_deref(), Some("0000"));
    assert_eq!(hex("AB==").as_deref(), Some("00"));
    assert_eq!(hex("AA\nAA").as_deref(), Some("000000"));
    assert_eq!(hex("!!AAAA").as_deref(), Some("000000"));
    assert_eq!(hex("AAAA=").as_deref(), Some("000000"));
    assert_eq!(hex("AAA==").as_deref(), Some("0000"));
    assert_eq!(hex("AAAA====").as_deref(), Some("000000"));
    assert_eq!(hex("").as_deref(), Some(""));
    assert_eq!(hex("====").as_deref(), Some(""));
    assert_eq!(hex("AA"), None);
    assert_eq!(hex("A"), None);
    assert_eq!(hex("AA=A"), None);
    assert_eq!(hex("=AAA"), None);
    assert_eq!(hex("AAAAAA"), None);
    assert_eq!(hex("A==="), None);
}

#[test]
fn a_line_wrapped_signature_still_verifies() {
    let wrapped: String = SIGNATURE
        .as_bytes()
        .chunks(64)
        .map(|chunk| format!("{}\n", std::str::from_utf8(chunk).unwrap()))
        .collect();
    let mut payload = envelope();
    payload.as_object_mut().unwrap()["signature"] = json!(wrapped);
    assert_eq!(
        verify(&payload, json!([signing_key()])),
        json!({"verified": true})
    );
}
