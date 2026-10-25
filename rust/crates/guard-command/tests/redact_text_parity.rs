//! Secret redaction agrees with the vectors Python records for its own copy of
//! the same twelve rules.
//!
//! `redact_text` here and `redaction.redact_text` in Python each mask bearer
//! tokens, provider keys, private keys, secret environment assignments and
//! connection strings on the route that side owns, before Guard prints or
//! syncs the text. The two implementations read the same fixture, so a rule
//! that drifts in either copy fails on both sides.
//!
//! Each case assembles its input from fragments so no complete secret-shaped
//! literal sits in the tree, the same discipline `oracle_vectors` follows.

use guard_command::redacted_command_tokens::redact_text;
use serde_json::Value;

const VECTORS: &str = include_str!("../../../../tests/fixtures/redact-text-parity.v1.json");

/// The operator boundary is only visible in these cases: each one records a
/// value ending at a different shell operator, so a count alone would let any
/// of them be dropped and replaced by a duplicate of an existing `secret-env`
/// case. The Python suite requires the same names.
const BOUNDED_VALUE_CASES: [&str; 5] = [
    "a quoted value keeps an operator inside it",
    "a single-quoted value keeps an operator inside it",
    "an assignment ends at a pipe",
    "an assignment ends at a background operator",
    "an escaped operator inside a value still ends it",
];

#[test]
fn every_operator_boundary_keeps_its_own_case() {
    let vectors: Value = serde_json::from_str(VECTORS).expect("vectors parse");
    let cases = vectors["cases"].as_array().expect("cases array");
    for required in BOUNDED_VALUE_CASES {
        let recorded = cases
            .iter()
            .filter(|case| case["name"].as_str() == Some(required))
            .count();
        assert_eq!(recorded, 1, "{required}");
    }
}

#[test]
fn recorded_inputs_redact_to_their_recorded_results() {
    let vectors: Value = serde_json::from_str(VECTORS).expect("vectors parse");
    assert_eq!(vectors["schema"].as_str(), Some("redact-text-parity.v1"));
    let cases = vectors["cases"].as_array().expect("cases array");
    assert!(cases.len() >= 32);

    for case in cases {
        let name = case["name"].as_str().unwrap_or_default();
        let input: String = case["input"]
            .as_array()
            .expect("input fragments")
            .iter()
            .map(|fragment| fragment.as_str().expect("fragment"))
            .collect();
        let expected_classifiers: Vec<&str> = case["classifiers"]
            .as_array()
            .expect("classifiers")
            .iter()
            .map(|classifier| classifier.as_str().expect("classifier"))
            .collect();

        let redacted = redact_text(&input);

        assert_eq!(
            redacted.text,
            case["text"].as_str().expect("text"),
            "{name}"
        );
        assert_eq!(
            redacted.count as u64,
            case["count"].as_u64().expect("count"),
            "{name}"
        );
        assert_eq!(redacted.classifiers, expected_classifiers, "{name}");
        assert!(redacted.original_sha256.is_empty(), "{name}");
    }
}
