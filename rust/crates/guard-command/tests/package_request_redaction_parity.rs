//! Package argv redaction agrees with the vectors Python records for its own
//! copy of the routine.
//!
//! `redact_package_request_token` here and
//! `package_intent_common.redact_package_request_token` in Python each strip
//! credentials out of a package argv token on the route that side owns, and
//! Guard persists whichever text came back. The two implementations read the
//! same fixture, so a branch that drifts in either copy fails on both sides.

use guard_command::package_intent_common::redact_package_request_token;
use serde_json::Value;

const VECTORS: &str = include_str!("../../../../tests/fixtures/package-request-redaction.v1.json");

#[test]
fn recorded_tokens_redact_to_their_recorded_text() {
    let vectors: Value = serde_json::from_str(VECTORS).expect("vectors parse");
    assert_eq!(
        vectors["schema"].as_str(),
        Some("package-request-redaction-parity.v1")
    );
    let cases = vectors["cases"].as_array().expect("cases array");
    assert!(cases.len() >= 14);
    for case in cases {
        let token = case["token"].as_str().expect("token");
        let expected = case["redacted"].as_str().expect("redacted");
        assert_eq!(
            redact_package_request_token(token),
            expected,
            "{}",
            case["name"].as_str().unwrap_or_default()
        );
    }
}
