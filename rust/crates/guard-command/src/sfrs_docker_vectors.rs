//! Parity of the Docker request classifier against recorded Python output.

use crate::sfrs_token_vectors::records;
use crate::sfrs_tool_request::docker_sensitive_reason;

#[test]
fn docker_sensitive_reason_matches_recorded_python() {
    let mut failures = Vec::new();
    let mut sensitive = 0usize;
    for record in records() {
        let text = record["text"].as_str().expect("text");
        let expected = record["docker_reason"].as_str().map(str::to_owned);
        if expected.is_some() {
            sensitive += 1;
        }
        let actual = docker_sensitive_reason(text, false);
        if actual != expected {
            failures.push(format!("{text:?}: {actual:?} vs {expected:?}"));
        }
    }
    assert!(
        sensitive > 10,
        "corpus must exercise sensitive docker reasons"
    );
    assert!(
        failures.is_empty(),
        "{} differ, first: {:#?}",
        failures.len(),
        &failures[..failures.len().min(8)]
    );
}
