//! Sixteen pure Python `_evaluate_audited_state` vectors from b4efd817.

use gauntlet_evidence::evaluate_audited_campaign;
use serde_json::Value;
use std::path::Path;

#[test]
fn python_audited_campaign_reducer_parity() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/python_gate_campaign_vectors.json");
    let fixture: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(
        fixture["source_sha"],
        "b4efd8171b06d0e13cbe12a077c376ecdc891fd1"
    );
    for case in fixture["cases"].as_array().unwrap() {
        let actual =
            evaluate_audited_campaign(&case["state"], &case["policy"], &case["observations"])
                .unwrap();
        assert_eq!(actual, case["expected"], "{}", case["name"]);
    }
}

#[test]
fn forged_campaign_passed_flags_do_not_override_accounting() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/python_gate_campaign_vectors.json");
    let fixture: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let case = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "charge_mismatch")
        .unwrap();
    let mut state = case["state"].clone();
    state["passed"] = Value::Bool(true);
    state["ledger"][0]["event"]["passed"] = Value::Bool(true);
    let actual = evaluate_audited_campaign(&state, &case["policy"], &case["observations"]).unwrap();
    assert_eq!(actual["status"], "failed");
    assert_eq!(
        actual["errors"],
        serde_json::json!(["attempt-token-charge-mismatch"])
    );
}
