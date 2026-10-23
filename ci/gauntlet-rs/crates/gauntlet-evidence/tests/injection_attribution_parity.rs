use gauntlet_evidence::reduce_injection_attribution;
use serde_json::Value;

#[test]
fn forwarded_withheld_and_negative_attribution_match_pinned_python() {
    let fixture: Value =
        serde_json::from_str(include_str!("python_injection_attribution_v1.json")).unwrap();
    let manifest: Value =
        serde_json::from_str(include_str!("../../../parity-manifest.v1.json")).unwrap();
    let source = manifest["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["path"] == "ci/gauntlet/benchmark/deterministic.py")
        .unwrap();
    assert_eq!(fixture["source_sha256"], source["sha256"]);
    assert_eq!(
        fixture["schema"],
        "gauntlet-injection-attribution-fixtures.v1"
    );
    assert_eq!(fixture["authentication_stubbed"], true);
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 12);
    for case in cases {
        match reduce_injection_attribution(&case["record"]) {
            Ok(actual) => {
                assert_eq!(case["accepted"], true, "{}", case["name"]);
                assert_eq!(actual, case["guard_intervention"], "{}", case["name"]);
            }
            Err(error) => {
                assert_eq!(case["accepted"], false, "{}", case["name"]);
                assert_eq!(error.to_string(), case["error"], "{}", case["name"]);
            }
        }
    }
}
