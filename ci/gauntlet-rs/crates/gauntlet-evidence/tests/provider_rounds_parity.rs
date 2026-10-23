use gauntlet_evidence::reconcile_provider_rounds;
use serde_json::{json, Value};

#[test]
fn completed_and_zero_byte_retry_classification_matches_pinned_python() {
    let fixture: Value =
        serde_json::from_str(include_str!("python_provider_rounds_v1.json")).unwrap();
    let manifest: Value =
        serde_json::from_str(include_str!("../../../parity-manifest.v1.json")).unwrap();
    let source = manifest["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["path"] == "ci/gauntlet/transport.py")
        .unwrap();
    assert_eq!(fixture["source_sha256"], source["sha256"]);
    assert_eq!(fixture["schema"], "gauntlet-provider-round-fixtures.v1");
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 23);
    for case in cases {
        let actual = reconcile_provider_rounds(case["rounds"].as_array().unwrap());
        assert_eq!(
            actual.0,
            case["valid"].as_bool().unwrap(),
            "{}",
            case["name"]
        );
        assert_eq!(
            actual.1,
            case["recovered"].as_u64().unwrap() as usize,
            "{}",
            case["name"]
        );
    }
}

#[test]
fn boolean_byte_counts_and_excessive_rounds_fail_closed() {
    let refused = json!([
        {"status":"provider-error", "error_type":"HTTPError", "http_status":429,
         "delivered_bytes":false, "request_sha256":"a".repeat(64)},
        {"status":"completed", "request_sha256":"a".repeat(64),
         "response_sha256":"b".repeat(64), "response_bytes":128, "response_models":["qwen"]}
    ]);
    assert_eq!(
        reconcile_provider_rounds(refused.as_array().unwrap()),
        (false, 0)
    );
    assert_eq!(
        reconcile_provider_rounds(&vec![json!({}); 50_001]),
        (false, 0)
    );
}
