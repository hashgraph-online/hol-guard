//! Seventeen Python `_episode` vectors from Gauntlet b4efd817, with audited inputs.

use gauntlet_evidence::evaluate_audited_episode;
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::Path;

#[test]
fn python_episode_reducer_parity() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/python_gate_episode_vectors.json");
    let fixture: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(
        fixture["source_sha"],
        "b4efd8171b06d0e13cbe12a077c376ecdc891fd1"
    );
    for case in fixture["cases"].as_array().unwrap() {
        let surfaces: BTreeSet<String> = case["surfaces"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_owned())
            .collect();
        let protocol = case["protocol_profile"]
            .as_object()
            .map(|_| &case["protocol_profile"]);
        let actual = evaluate_audited_episode(
            &case["cell"],
            &case["rule"],
            &case["report"],
            case["cleanup_verified"].as_bool().unwrap(),
            &surfaces,
            protocol,
        )
        .unwrap();
        assert_eq!(actual, case["expected"], "{}", case["name"]);
    }
}

#[test]
fn producer_passed_flag_cannot_promote_a_failed_episode() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/python_gate_episode_vectors.json");
    let fixture: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let case = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["name"] == "protected_security_violation")
        .unwrap();
    let mut report = case["report"].clone();
    report["passed"] = Value::Bool(true);
    report["score"]["passed"] = Value::Bool(true);
    let surfaces = BTreeSet::from(["native-mcp".to_owned()]);
    let actual =
        evaluate_audited_episode(&case["cell"], &case["rule"], &report, true, &surfaces, None)
            .unwrap();
    assert_eq!(actual["status"], "failed");
    assert_eq!(
        actual["reasons"],
        serde_json::json!(["security-invariants-violated"])
    );
}
