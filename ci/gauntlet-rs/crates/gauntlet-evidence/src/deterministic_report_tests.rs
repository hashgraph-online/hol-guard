use super::*;
use serde_json::{json, Value};

const SOURCE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const CONFIG: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

fn frozen_report() -> Vec<u8> {
    let fixture: Value = serde_json::from_str(include_str!(
        "../tests/fixtures/python_worker_terminal_synthetic.json"
    ))
    .unwrap();
    fixture["report_raw"].as_str().unwrap().as_bytes().to_vec()
}

#[test]
fn python_frozen_report_is_identity_consistent_but_ineligible() {
    let raw = frozen_report();
    let observed = verify_deterministic_report(&raw, SOURCE, CONFIG, 0).unwrap();
    assert_eq!(observed.raw_sha256, sha256(&raw));
    assert_eq!(observed.producer_status, "passed");
    assert_eq!(observed.cell_count, 1);
    assert!(!observed.execution_eligible);
    assert!(verify_deterministic_report(&raw, &"0".repeat(40), CONFIG, 0).is_err());
    assert!(verify_deterministic_report(&raw, SOURCE, &"0".repeat(64), 0).is_err());
    assert!(verify_deterministic_report(&raw, SOURCE, CONFIG, 1).is_err());
}

#[test]
fn producer_status_and_zero_model_usage_cannot_override_bad_identity() {
    let mut report: Value = serde_json::from_slice(&frozen_report()).unwrap();
    for (field, value) in [
        ("guard_source_sha", json!("0".repeat(40))),
        ("runner_config_digest", json!("0".repeat(64))),
        ("model_tokens", json!(1)),
        ("model_tokens", json!(false)),
        ("model_usage_known", json!(false)),
        ("profile", json!("beta-e2e")),
        ("schema", json!("different")),
        ("cells", json!(null)),
        ("cells", json!([{}, {}, {}, {}, {}, {}, {}])),
    ] {
        let original = report[field].clone();
        report[field] = value;
        assert!(
            verify_deterministic_report(report.to_string().as_bytes(), SOURCE, CONFIG, 0).is_err(),
            "{field} was accepted"
        );
        report[field] = original;
    }
    report["exit_code"] = json!(1);
    report["status"] = json!("passed");
    assert!(verify_deterministic_report(report.to_string().as_bytes(), SOURCE, CONFIG, 1).is_err());
    report["status"] = json!("failed");
    let failed =
        verify_deterministic_report(report.to_string().as_bytes(), SOURCE, CONFIG, 1).unwrap();
    assert_eq!(failed.producer_status, "failed");
    assert!(!failed.execution_eligible);
}

#[test]
fn ambiguous_or_missing_report_data_is_refused() {
    let raw = frozen_report();
    let duplicate = format!(
        "{{\"status\":\"passed\",{}",
        &str::from_utf8(&raw).unwrap()[1..]
    );
    assert!(verify_deterministic_report(duplicate.as_bytes(), SOURCE, CONFIG, 0).is_err());
    assert!(verify_deterministic_report(br#"{}"#, SOURCE, CONFIG, 0).is_err());
    assert!(verify_deterministic_report(&[], SOURCE, CONFIG, 0).is_err());
    assert!(verify_deterministic_report(&raw, SOURCE, CONFIG, 256).is_err());
}
