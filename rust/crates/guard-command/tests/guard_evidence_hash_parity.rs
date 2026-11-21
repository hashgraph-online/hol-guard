//! The evidence digest agrees with the one Python records for the same payload.
//!
//! `guard_evidence_hash` here and `runtime.evidence_hash.guard_evidence_hash`
//! in Python name the same local trust claim on two different routes: a claim
//! written on one is replayed and compared on the other, so a digest that
//! drifted on either side would read as a claim nobody had made. Both replay
//! this fixture.

use guard_command::evidence_hash::guard_evidence_hash;
use serde_json::Value;

const VECTORS: &str = include_str!("../../../../tests/fixtures/guard-evidence-hash.v1.json");

#[test]
fn recorded_payloads_hash_to_their_recorded_digest() {
    let vectors: Value = serde_json::from_str(VECTORS).expect("vectors parse");
    assert_eq!(
        vectors["schema"].as_str(),
        Some("guard-evidence-hash-parity.v1")
    );
    let cases = vectors["cases"].as_array().expect("cases array");
    assert!(cases.len() >= 13, "the fixture records too few payloads");
    for case in cases {
        let payload = case["payload"].as_object().expect("payload object");
        let expected = case["digest"].as_str().expect("digest");
        assert_eq!(
            guard_evidence_hash(payload),
            expected,
            "{}",
            case["name"].as_str().unwrap_or_default()
        );
    }
}
