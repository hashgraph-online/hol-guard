use super::verify_provider_status;
use serde_json::Value;

#[test]
fn python_provider_status_snapshots_and_refusals_match() {
    let frozen: Value = serde_json::from_str(include_str!(
        "../tests/fixtures/python_provider_status_v1.json"
    ))
    .unwrap();
    let baseline: Value =
        serde_json::from_str(include_str!("../../../parity-manifest.v1.json")).unwrap();
    let source = baseline["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["path"] == "ci/gauntlet/benchmark/ci_runner_preflight.py")
        .unwrap();
    assert_eq!(frozen["source_sha256"], source["sha256"]);
    assert_eq!(frozen["schema"], "gauntlet-provider-status-fixtures.v1");
    let cases = frozen["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 18);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let result = verify_provider_status(&case["status"], &case["pins"]);
        if let Some(expected) = case.get("quota") {
            assert_eq!(result.unwrap(), *expected, "{name}");
        } else {
            assert_eq!(
                result.unwrap_err().to_string(),
                case["python_refusal"].as_str().unwrap(),
                "{name}"
            );
        }
    }
}
