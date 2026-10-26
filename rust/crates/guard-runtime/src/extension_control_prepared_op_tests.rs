use super::*;
use crate::extension_control_op::evaluate_extension_control_request;
use guard_contracts::{
    ExtensionControlQueryV1, ExtensionControlRequestV1, ExtensionControlResultV1,
    EXTENSION_CONTROL_MAX_BYTES, EXTENSION_CONTROL_REQUEST_SCHEMA,
};

fn digest() -> String {
    "a".repeat(64)
}

fn wire_request(query: &str) -> ExtensionControlRequestV1 {
    serde_json::from_str(&format!(
        r#"{{"schema":"{EXTENSION_CONTROL_REQUEST_SCHEMA}","request_id":"extension-control-prepared-1","query":{query}}}"#
    ))
    .unwrap()
}

fn reply(request: &ExtensionControlRequestV1) -> ExtensionControlResultV1 {
    let bytes = evaluate_extension_control_request(request).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

/// The digest of a `request_digest` query written as the daemon's JSON.
fn digest_of(fields: &str) -> String {
    let result = reply(&wire_request(&format!(
        r#"{{"kind":"request_digest",{fields}}}"#
    )));
    assert_eq!(result.status, "ok", "{}", result.code);
    match result.payload {
        Some(ExtensionControlPayloadV1::RequestDigest { digest }) => digest,
        other => panic!("expected request_digest payload, got {other:?}"),
    }
}

fn nonce_of(
    nonce: &str,
    activation: &str,
    before: &str,
    after: &str,
    security: Option<&str>,
) -> String {
    let result = reply(&ExtensionControlRequestV1 {
        schema: EXTENSION_CONTROL_REQUEST_SCHEMA.to_owned(),
        request_id: "extension-control-prepared-2".to_owned(),
        query: ExtensionControlQueryV1::CandidateNonce {
            nonce: nonce.to_owned(),
            activation_digest: activation.to_owned(),
            lifecycle_before: before.to_owned(),
            lifecycle_after: after.to_owned(),
            security_digest: security.map(str::to_owned),
        },
    });
    assert_eq!(result.status, "ok", "{}", result.code);
    match result.payload {
        Some(ExtensionControlPayloadV1::CandidateNonce { nonce }) => nonce,
        other => panic!("expected candidate_nonce payload, got {other:?}"),
    }
}

#[test]
fn the_request_digest_is_the_retired_python_digest_of_the_same_request() {
    let layers = r#"[{"kind":"local-admin","controls":[{"target_kind":"permission","target_id":"x","state":"disabled"}],"global_lockdown":false}]"#;
    assert_eq!(
        digest_of(&format!(
            r#""previous_revision":3,"catalog_digest":"{}","layers":{layers},"actor_id":"actor-1","idempotency_key":"key-1","nonce":"n1""#,
            digest()
        )),
        "f904eb3feb6000c31fe8911ee9c7682e1b0d2de1706b7ad11edb1ed1a8ac9fd5"
    );
    // A field the caller left out is `null`: the request is not known to be
    // well formed yet.
    assert_eq!(
        digest_of(
            r#""previous_revision":null,"catalog_digest":null,"layers":null,"actor_id":null,"idempotency_key":null,"nonce":null"#
        ),
        "5e8bf3fbf51ebd9f4404a2de23072a7f2b6d469088162b175c56e0c47b3189d8"
    );
    // Non-ASCII text is escaped the way `json.dumps` escapes it.
    assert_eq!(
        digest_of(
            r#""previous_revision":0,"catalog_digest":null,"layers":[{"kind":"local-admin","note":"café ☃ 😀"}],"actor_id":"a","idempotency_key":"k","nonce":"n""#
        ),
        "8fe78c4c4f6f75fc65a69b9c29eaef48c315364e6edd39da8b8c61e9786700b6"
    );
    // Values of any shape are hashed as sent.
    assert_eq!(
        digest_of(
            r#""previous_revision":1.5,"catalog_digest":null,"layers":{},"actor_id":true,"idempotency_key":"","nonce":["a",1]"#
        ),
        "af8eb7167e46af2d00a73c247e1f99a8a6b42d8d49fb14ebe91b4dfb91ba5f53"
    );
}

#[test]
fn the_request_digest_spells_numbers_and_orders_keys_as_python_does() {
    // Python reads `-0` as the integer 0, `1e2` as 100.0 and `1e-7` as 1e-07,
    // keeps integers of any size exact, and sorts keys at every depth.
    assert_eq!(
        digest_of(
            r#""previous_revision":123456789012345678901234567890,"catalog_digest":null,"layers":{"z":1e-7,"a":[2.0,-0,0.1,1e2],"m":{"y":null,"b":"é"}},"actor_id":null,"idempotency_key":null,"nonce":null"#
        ),
        "547b601f02b59cb85b8ffed10095c170fc1713b04aa15c792553925d2c205849"
    );
}

#[test]
fn the_request_digest_ignores_key_order_but_not_values() {
    let first = digest_of(
        r#""previous_revision":1,"catalog_digest":"c","layers":{"a":1,"b":2},"actor_id":"x","idempotency_key":"k","nonce":"n""#,
    );
    let reordered = digest_of(
        r#""nonce":"n","idempotency_key":"k","actor_id":"x","layers":{"b":2,"a":1},"catalog_digest":"c","previous_revision":1"#,
    );
    assert_eq!(first, reordered);

    let other_actor = digest_of(
        r#""previous_revision":1,"catalog_digest":"c","layers":{"a":1,"b":2},"actor_id":"y","idempotency_key":"k","nonce":"n""#,
    );
    assert_ne!(first, other_actor);
    let other_layers = digest_of(
        r#""previous_revision":1,"catalog_digest":"c","layers":{"a":1,"b":3},"actor_id":"x","idempotency_key":"k","nonce":"n""#,
    );
    assert_ne!(first, other_layers);
}

#[test]
fn the_candidate_nonce_is_the_retired_python_binding() {
    let (b, c, d, e) = (
        "b".repeat(64),
        "c".repeat(64),
        "d".repeat(64),
        "e".repeat(64),
    );
    assert_eq!(
        nonce_of("nonce-1", &b, &c, &d, Some(&e)),
        "532c763071abd3b73255d4e229f625c9016369f843c89ae4d6ea34d229f62cec"
    );
    // No security record is `null`, not an empty string.
    assert_eq!(
        nonce_of("nonce-1", &b, &c, &d, None),
        "8baf154c94c601e5f1920543d5cb9a009b422602e18aa8c922feaed1d0452fed"
    );
    assert_ne!(
        nonce_of("nonce-1", &b, &c, &d, None),
        nonce_of("nonce-1", &b, &c, &d, Some(""))
    );
    assert_eq!(
        nonce_of("caf\u{e9}", &b, &c, &d, None),
        "c7963331eb3cf3ae7df1ca30de4b8b2daf97970692b473a4669d35d019668ca3"
    );
}

#[test]
fn every_input_changes_the_candidate_nonce() {
    let (b, c, d, e) = (
        "b".repeat(64),
        "c".repeat(64),
        "d".repeat(64),
        "e".repeat(64),
    );
    let base = nonce_of("nonce-1", &b, &c, &d, Some(&e));
    for other in [
        nonce_of("nonce-2", &b, &c, &d, Some(&e)),
        nonce_of("nonce-1", &c, &c, &d, Some(&e)),
        nonce_of("nonce-1", &b, &b, &d, Some(&e)),
        nonce_of("nonce-1", &b, &c, &b, Some(&e)),
        nonce_of("nonce-1", &b, &c, &d, Some(&b)),
        nonce_of("nonce-1", &b, &c, &d, None),
    ] {
        assert_ne!(base, other);
    }
    // The inputs are positional: swapping two of them is another binding.
    assert_ne!(base, nonce_of("nonce-1", &b, &d, &c, Some(&e)));
}

#[test]
fn a_request_over_the_byte_limit_has_no_digest() {
    let oversized = "a".repeat(EXTENSION_CONTROL_MAX_BYTES + 1);
    let request = wire_request(&format!(
        r#"{{"kind":"request_digest","previous_revision":null,"catalog_digest":null,"layers":"{oversized}","actor_id":null,"idempotency_key":null,"nonce":null}}"#
    ));

    assert_eq!(
        evaluate_extension_control_request(&request),
        Err("native_extension_control_too_large".to_owned())
    );
}

#[path = "extension_control_prepared_op_targets_tests.rs"]
mod projection;
