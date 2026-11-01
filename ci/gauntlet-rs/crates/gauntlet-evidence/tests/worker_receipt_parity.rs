//! Python-shaped terminal bytes prove consistency only, never six-cell success.

use gauntlet_evidence::verify_python_worker_terminal;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const JOB: &str = "0123456789abcdef";
const DEPLOYMENT: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const CONFIG: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

fn fixture() -> (Value, Vec<u8>) {
    let value: Value = serde_json::from_slice(include_bytes!(
        "fixtures/python_worker_terminal_synthetic.json"
    ))
    .unwrap();
    (
        value["receipt"].clone(),
        value["report_raw"].as_str().unwrap().as_bytes().to_vec(),
    )
}

fn verify(receipt: &Value, report: Option<&[u8]>) -> bool {
    verify_python_worker_terminal(
        &serde_json::to_vec(receipt).unwrap(),
        report,
        SHA,
        JOB,
        DEPLOYMENT,
        CONFIG,
    )
    .is_ok()
}

fn replace_report(receipt: &mut Value, report: &Value) -> Vec<u8> {
    let raw = serde_json::to_vec(report).unwrap();
    receipt["report_sha256"] = json!(format!("{:x}", Sha256::digest(&raw)));
    raw
}

#[test]
fn python_shaped_report_bytes_are_consistent_but_not_eligible() {
    let (receipt, report) = fixture();
    let observed = verify_python_worker_terminal(
        &serde_json::to_vec(&receipt).unwrap(),
        Some(&report),
        SHA,
        JOB,
        DEPLOYMENT,
        CONFIG,
    )
    .unwrap();
    assert_eq!(observed.status, "passed");
    assert!(observed.report_consistent);
    assert!(!observed.execution_eligible);
    assert_eq!(
        observed.report_sha256.as_deref(),
        receipt["report_sha256"].as_str()
    );
}

#[test]
fn altered_pins_report_usage_and_producer_status_fail_closed() {
    let (receipt, raw) = fixture();
    let mut wrong = receipt.clone();
    wrong["job_id"] = json!("fedcba9876543210");
    assert!(!verify(&wrong, Some(&raw)));
    assert!(!verify(&receipt, None));
    assert!(!verify(&receipt, Some(b"changed")));

    let mut report: Value = serde_json::from_slice(&raw).unwrap();
    let mut changed = receipt.clone();
    report["model_usage_known"] = json!(false);
    let altered_raw = replace_report(&mut changed, &report);
    assert!(!verify(&changed, Some(&altered_raw)));

    let (_, raw) = fixture();
    let mut report: Value = serde_json::from_slice(&raw).unwrap();
    let mut changed = receipt.clone();
    report["guard_source_sha"] = json!("d".repeat(40));
    let altered_raw = replace_report(&mut changed, &report);
    assert!(!verify(&changed, Some(&altered_raw)));

    let mut changed = receipt.clone();
    changed["status"] = json!("failed");
    assert!(!verify(&changed, Some(&raw)));
    let mut changed = receipt.clone();
    changed["exit_code"] = json!(1);
    assert!(!verify(&changed, Some(&raw)));
    let mut changed = receipt.clone();
    changed["command"] = json!("/bin/sh");
    assert!(!verify(&changed, Some(&raw)));
}

#[test]
fn reportless_invalid_evidence_and_duplicate_json_are_not_passes() {
    let (mut receipt, _) = fixture();
    receipt.as_object_mut().unwrap().remove("cells");
    receipt.as_object_mut().unwrap().remove("elapsed_seconds");
    receipt.as_object_mut().unwrap().remove("report_sha256");
    receipt["status"] = json!("invalid-evidence");
    receipt["exit_code"] = json!(1);
    let observed = verify_python_worker_terminal(
        &serde_json::to_vec(&receipt).unwrap(),
        None,
        SHA,
        JOB,
        DEPLOYMENT,
        CONFIG,
    )
    .unwrap();
    assert!(!observed.report_consistent);
    assert!(!observed.execution_eligible);
    let duplicate = format!("{{\"source_sha\":\"{SHA}\",\"source_sha\":\"{SHA}\"}}");
    assert!(verify_python_worker_terminal(
        duplicate.as_bytes(),
        None,
        SHA,
        JOB,
        DEPLOYMENT,
        CONFIG,
    )
    .is_err());
}
