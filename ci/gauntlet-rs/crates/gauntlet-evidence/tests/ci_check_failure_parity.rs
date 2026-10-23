use gauntlet_evidence::project_ci_check_failure_ineligible;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::PathBuf;

#[test]
fn fixed_pre_execution_failure_rows_match_pinned_python() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/python_ci_check_failures_v1.json")).unwrap();
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../gauntlet/benchmark");
    let pins = [
        (
            "ci_pipeline.py",
            "ff3ece762f411439385fff86cc9ac017203f93a0ba0e4e63bae16ceceae2529b",
        ),
        (
            "beta_profile.py",
            "aee91027c178e5538270dbd57265251ee776458125b9879e44ef083e89c30e9b",
        ),
        (
            "deterministic.py",
            "e819cf846a62506a3b3523f4b6471d3fb5f85c117578fafc5a1746ef925b06ae",
        ),
    ];
    for (name, pin) in pins {
        assert_eq!(fixture["source_sha256"][name], pin);
        assert_eq!(
            format!(
                "{:x}",
                Sha256::digest(std::fs::read(source.join(name)).unwrap())
            ),
            pin
        );
    }
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 8);
    for case in cases {
        let projection = project_ci_check_failure_ineligible(
            case["profile"].as_str().unwrap(),
            case["reason"].as_str().unwrap(),
            case["code"].as_i64().unwrap() as i32,
        )
        .unwrap();
        assert!(!projection.execution_eligible());
        assert_eq!(projection.python_result(), &case["expected"]);
    }
}

#[test]
fn unsupported_or_unbounded_failure_claims_refuse() {
    for (profile, reason, code) in [
        ("unknown", "pipeline-not-started", 2),
        ("deterministic", "pipeline-not-started", 0),
        ("deterministic", "pipeline-not-started", 1),
        ("deterministic", "", 2),
    ] {
        assert!(project_ci_check_failure_ineligible(profile, reason, code).is_err());
    }
    assert!(project_ci_check_failure_ineligible("beta-e2e", &"x".repeat(4097), 2).is_err());
}
