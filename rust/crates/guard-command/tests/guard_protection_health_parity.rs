//! Replay recorded protection-health reports through the Rust port.
//!
//! Every case was produced by handing the same signals to Python's
//! `evaluate_protection_health`, so an expected report is the exact text
//! `json.dumps` produced and an expected error is Python's own wording.

use std::collections::BTreeMap;

use guard_command::protection_health::{
    evaluate_protection_health, ProtectionCheckStatus, ProtectionSignal,
};
use serde_json::Value;

const FIXTURE: &str = include_str!("../../../../tests/fixtures/guard-protection-health.v1.json");

fn status(name: &str) -> ProtectionCheckStatus {
    match name {
        "pass" => ProtectionCheckStatus::Pass,
        "unknown" => ProtectionCheckStatus::Unknown,
        "fail" => ProtectionCheckStatus::Fail,
        other => panic!("the fixture records an unknown status {other}"),
    }
}

/// `{"check_id": ["status", "reason_code"], ...}` as the fixture writes it.
fn signals(case: &Value, field: &str) -> BTreeMap<String, ProtectionSignal> {
    case[field]
        .as_object()
        .unwrap_or_else(|| panic!("case is missing {field}"))
        .iter()
        .map(|(key, spec)| {
            let pair = spec.as_array().expect("a [status, reason_code] pair");
            let signal = ProtectionSignal::new(
                status(pair[0].as_str().expect("a status")),
                pair[1].as_str().expect("a reason code"),
            )
            .expect("the fixture records stable reason codes");
            (key.clone(), signal)
        })
        .collect()
}

#[test]
fn recorded_protection_health_reports_replay() {
    let document: Value = serde_json::from_str(FIXTURE).expect("fixture parses");
    assert_eq!(
        document["schema"], "guard-protection-health-parity.v1",
        "fixture schema moved"
    );
    let cases = document["cases"].as_array().expect("cases");
    assert!(cases.len() >= 11, "the fixture lost cases");

    let mut reported = 0usize;
    let mut refused = 0usize;
    for case in cases {
        let name = case["name"].as_str().expect("a case name");
        let result = evaluate_protection_health(
            &signals(case, "signals"),
            &signals(case, "harness_signals"),
        );
        match (result, case.get("expected_error").and_then(Value::as_str)) {
            (Err(error), Some(expected)) => {
                assert_eq!(error.message(), expected, "case {name} refuses differently");
                refused += 1;
            }
            (Ok(report), None) => {
                let expected = case["expected_json"].as_str().expect("a recorded report");
                assert_eq!(
                    serde_json::to_string(&report).expect("the report serializes"),
                    expected,
                    "case {name} reports differently"
                );
                reported += 1;
            }
            (Ok(_), Some(expected)) => panic!("case {name} should have been refused: {expected}"),
            (Err(error), None) => panic!("case {name} was refused: {}", error.message()),
        }
    }
    assert!(
        reported >= 6,
        "the fixture must keep recording real reports"
    );
    assert!(refused >= 3, "the fixture must keep recording refusals");
}

#[test]
fn recorded_reason_codes_are_still_refused() {
    let document: Value = serde_json::from_str(FIXTURE).expect("fixture parses");
    let rejected = document["rejected_reason_codes"]
        .as_array()
        .expect("rejected reason codes");
    assert!(!rejected.is_empty(), "the fixture records no rejections");
    for entry in rejected {
        let reason_code = entry["reason_code"].as_str().expect("a reason code");
        let expected = entry["expected_error"]
            .as_str()
            .expect("Python refused it, so it recorded a message");
        let error = ProtectionSignal::new(ProtectionCheckStatus::Unknown, reason_code)
            .err()
            .unwrap_or_else(|| panic!("{reason_code:?} should be refused"));
        assert_eq!(error.message(), expected);
    }
}
