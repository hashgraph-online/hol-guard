//! Parity with the retired Python artifact hash over a frozen corpus.
//!
//! The fixture was recorded from the Python implementation before it was
//! removed, so a failure here means saved approvals would stop matching their
//! artifacts.

use serde_json::{Map, Value};

use crate::artifact_hash::artifact_hash;

const PARITY: &str = include_str!("../../../../tests/fixtures/artifact-hash-parity.v1.json");

#[test]
fn matches_the_python_hash_for_every_recorded_case() {
    let corpus: Value = serde_json::from_str(PARITY).expect("parity fixture parses");
    let cases = corpus["cases"].as_array().expect("fixture lists cases");
    assert!(!cases.is_empty(), "fixture must record at least one case");
    for case in cases {
        let name = case["case"].as_str().expect("every case is named");
        let artifact: Map<String, Value> = case["artifact"]
            .as_object()
            .expect("every case carries an artifact")
            .clone();
        let expected = case["expected_sha256"]
            .as_str()
            .expect("every case records the Python answer");
        assert_eq!(
            artifact_hash(&artifact),
            expected,
            "{name}: {}",
            case["covers"].as_str().unwrap_or_default()
        );
    }
}
