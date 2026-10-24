//! Oracle: `guard_evidence_hash` from `runtime/evidence_hash.py`.

use serde_json::{json, Map, Value};

use crate::aibom_trust_metadata::GuardEvidenceHashApi;
use crate::evidence_hash::{
    canonical_guard_evidence_payload, guard_evidence_hash, NativeGuardEvidenceHash,
};

fn payload(value: Value) -> Map<String, Value> {
    value.as_object().expect("object payload").clone()
}

#[test]
fn the_canonical_payload_sorts_keys_and_escapes_non_ascii() {
    let encoded = canonical_guard_evidence_payload(&payload(json!({"b": 1, "a": "café"})));
    assert_eq!(
        String::from_utf8(encoded).expect("utf-8"),
        r#"{"a":"caf\u00e9","b":1}"#
    );
}

#[test]
fn an_empty_payload_hashes_the_empty_object() {
    assert_eq!(
        guard_evidence_hash(&Map::new()),
        "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
    );
}

#[test]
fn insertion_order_does_not_change_the_digest() {
    let one = guard_evidence_hash(&payload(json!({"a": 1, "b": 2})));
    let other = guard_evidence_hash(&payload(json!({"b": 2, "a": 1})));
    assert_eq!(one, other);
}

#[test]
fn the_seam_answers_with_the_native_digest() {
    let claim = payload(json!({"itemId": "item-1", "scope": "workspace"}));
    assert_eq!(
        NativeGuardEvidenceHash.guard_evidence_hash(&claim),
        guard_evidence_hash(&claim)
    );
}
