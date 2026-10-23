//! Wire compatibility through the real resident dispatcher and response encoder.

use crate::resident_ops::evaluate_resident_bytes;
use guard_contracts::{MAX_NATIVE_RESPONSE_BYTES, POLICY_BUNDLE_AUTHORITY_REQUEST_SCHEMA};
use serde_json::json;

#[test]
fn policy_bundle_transport_keeps_the_fixed_wire_response_and_request_digest() {
    let request = br#"{"operation":"policy_bundle_authority","request":{"schema":"guard-policy-bundle-authority-request.v1","request_id":"wire-parity","kind":"is_enforceable","input":{"bundle":{"rolloutState":"enforcing"}}}}"#;
    // The digest covers only the request, using the original canonical JSON
    // contract. Field order and compact response bytes remain transport-owned.
    let expected = concat!(
        r#"{"schema":"guard-policy-bundle-authority-result.v1","request_id":"wire-parity","#,
        r#""request_sha256":"sha256:2f28080fe2c52668c1233d0a70421e1a62542598ce0da4b7bc3f7a05b0081696","#,
        r#""status":"ok","code":"ok","result":{"value":true}}"#,
    );
    assert_eq!(
        evaluate_resident_bytes(request, None).unwrap(),
        expected.as_bytes()
    );
}

#[test]
fn policy_bundle_transport_keeps_the_runtime_response_cap() {
    // An invalid id is echoed in the typed error envelope. The domain's wire
    // request cap permits this input, but runtime response encoding refuses it.
    let request = json!({
        "operation": "policy_bundle_authority",
        "request": {
            "schema": POLICY_BUNDLE_AUTHORITY_REQUEST_SCHEMA,
            "request_id": "x".repeat(MAX_NATIVE_RESPONSE_BYTES),
            "kind": "is_enforceable",
            "input": {"bundle": {}},
        },
    });
    assert_eq!(
        evaluate_resident_bytes(&serde_json::to_vec(&request).unwrap(), None).unwrap_err(),
        "native_response_too_large",
    );
}
