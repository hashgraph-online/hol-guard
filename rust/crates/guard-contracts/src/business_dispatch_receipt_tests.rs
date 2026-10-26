use super::*;
use serde_json::{json, Value};

fn fixtures() -> Vec<Value> {
    let v: Value = serde_json::from_str(include_str!(
        "../../../../contracts/business-policy/dispatch-receipt-v1-fixtures.json"
    ))
    .unwrap();
    v["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["receipt"].clone())
        .collect()
}

#[test]
fn business_dispatch_receipt_golden_vectors_keep_effect_and_retry_separate() {
    for v in fixtures() {
        let receipt =
            parse_native_business_dispatch_receipt(&serde_json::to_vec(&v).unwrap()).unwrap();
        assert_eq!(serde_json::to_value(receipt).unwrap(), v);
        assert_eq!(v["provider_effect"], "not_checked");
        assert_eq!(v["retry_authority"], "none");
    }
}

#[test]
fn business_dispatch_receipt_rejects_effect_retry_and_payload_claims() {
    for (key, value) in [
        ("provider_effect", json!("confirmed")),
        ("retry_authority", json!("allow_once")),
        ("body", json!("private-body-canary")),
        ("token", json!("private-token-canary")),
        ("decision", json!("allow")),
        ("schema", json!("other.v1")),
        ("version", json!(2)),
        ("decision_binding", json!("not-a-digest")),
        ("input_binding", json!("B".repeat(64))),
    ] {
        let mut v = fixtures()[0].clone();
        v[key] = value;
        assert!(
            parse_native_business_dispatch_receipt(&serde_json::to_vec(&v).unwrap()).is_err(),
            "{key}"
        );
    }
}

#[test]
fn business_dispatch_receipt_rejects_inconsistent_acknowledgements() {
    for (index, acknowledgement) in [
        (0, Value::Null),
        (2, json!("c".repeat(64))),
        (0, json!("opaque-provider-id")),
    ] {
        let mut v = fixtures()[index].clone();
        v["acknowledgement_binding"] = acknowledgement;
        assert!(parse_native_business_dispatch_receipt(&serde_json::to_vec(&v).unwrap()).is_err());
    }
}

#[test]
fn business_dispatch_receipt_bounds_original_bytes_before_json_decoding() {
    let encoded = serde_json::to_vec(&fixtures()[0]).unwrap();
    assert!(encoded.len() < NATIVE_BUSINESS_DISPATCH_RECEIPT_MAX_BYTES);
    // This is otherwise valid JSON, including a valid receipt. Even whitespace
    // must count toward the transport budget before the decoder runs.
    let mut oversized = vec![b' '; NATIVE_BUSINESS_DISPATCH_RECEIPT_MAX_BYTES + 1];
    oversized.extend(encoded);
    assert_eq!(
        parse_native_business_dispatch_receipt(&oversized),
        Err("native_business_dispatch_receipt_too_large")
    );
}
