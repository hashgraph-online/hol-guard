//! The payload gate accepts and refuses exactly what Python's does.
//!
//! A builder validates a payload before it signs it and a verifier validates
//! the same payload before it believes it, so the two routes have to agree on
//! the shape down to the wording of the refusal. These vectors are recorded
//! from the Python oracle and replayed by
//! `tests/test_guard_attestation_payload_parity.py` as well.

use guard_command::attestation_payload::{validate_attestation_payload, AttestationPayloadRules};
use serde_json::Value;

const VECTORS: &str = include_str!("../../../../tests/fixtures/guard-attestation-payload.v1.json");

fn vectors() -> Value {
    let parsed: Value = serde_json::from_str(VECTORS).expect("vectors parse");
    assert_eq!(
        parsed["schema"].as_str(),
        Some("guard-attestation-payload-parity.v1")
    );
    parsed
}

fn rules(case: &Value) -> AttestationPayloadRules {
    let flag = |name: &str| {
        case["rules"][name]
            .as_bool()
            .unwrap_or_else(|| panic!("the case records no {name}"))
    };
    AttestationPayloadRules {
        require_signed_at: flag("require_signed_at"),
        require_nonce: flag("require_nonce"),
        require_subject_bindings: flag("require_subject_bindings"),
    }
}

#[test]
fn recorded_payloads_are_accepted_or_refused_as_python_records() {
    let vectors = vectors();
    let cases = vectors["cases"].as_array().expect("cases array");
    assert!(cases.len() >= 40, "the fixture records too few payloads");
    let mut accepted = 0usize;
    for case in cases {
        let name = case["name"].as_str().expect("name");
        let payload = case["payload"].as_object().expect("payload object");
        let verdict = validate_attestation_payload(payload, rules(case));
        match (case.get("normalized"), case.get("error")) {
            (Some(normalized), None) => {
                let normalized = normalized.as_object().expect("normalized object");
                let produced =
                    verdict.unwrap_or_else(|error| panic!("{name}: refused with {error}"));
                assert_eq!(&produced, normalized, "{name}: normalized differently");
                accepted += 1;
            }
            (None, Some(message)) => {
                let message = message.as_str().expect("error message");
                let error = verdict.err().unwrap_or_else(|| panic!("{name}: accepted"));
                assert_eq!(error.message(), message, "{name}: refused differently");
            }
            _ => panic!("{name}: the case records neither one verdict nor the other"),
        }
    }
    assert!(
        accepted >= 10,
        "the fixture records too few accepted payloads"
    );
}
