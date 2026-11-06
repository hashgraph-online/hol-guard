//! Replays vectors recorded from the retired Python receipt payload builder
//! (`tests/fixtures/cloud_receipt_payload/vectors.json`).

use super::runner_authority_op::dispatch;
use super::store_vectors_support_tests::gunzip_json;

const VECTORS: &[u8] =
    include_bytes!("../../../../tests/fixtures/cloud_receipt_payload/vectors.json.gz");

#[test]
fn recorded_python_receipts_match_the_resident() {
    let document = gunzip_json(VECTORS);
    assert_eq!(document["version"], 1);
    let vectors = document["vectors"].as_array().unwrap();
    assert!(vectors.len() > 600);
    let mut failures = Vec::new();
    for vector in vectors {
        let kind = vector["kind"].as_str().unwrap();
        let result = dispatch(kind, &vector["args"]);
        let matches = match (&result, vector.get("expected_error")) {
            (Err(code), Some(expected)) => expected == code,
            (Ok(actual), None) => *actual == vector["expected"],
            _ => false,
        };
        if !matches {
            failures.push(vector["name"].as_str().unwrap().to_owned());
        }
    }
    assert!(
        failures.is_empty(),
        "{} mismatches: {:?}",
        failures.len(),
        &failures[..failures.len().min(20)]
    );
}
