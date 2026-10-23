use gauntlet_evidence::reconcile_host_calls;
use serde_json::{json, Value};

mod host_event_source_compatibility;

#[test]
fn omp_host_and_sdk_bridge_reconciliation_matches_python() {
    let fixture: Value = serde_json::from_str(include_str!("python_host_calls_v1.json")).unwrap();
    let baseline: Value =
        serde_json::from_str(include_str!("../../../parity-manifest.v1.json")).unwrap();
    let delta: Value =
        serde_json::from_str(include_str!("../../../integration-source-delta.v1.json")).unwrap();
    assert_eq!(fixture["schema"], "gauntlet-host-call-fixtures.v1");
    let historical = &fixture["sources"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["path"] == "ci/gauntlet/evidence.py")
        .unwrap()["sha256"];
    let compatible = host_event_source_compatibility::verify("host-calls", historical, 31);
    for source in fixture["sources"].as_array().unwrap() {
        let path = source["path"].as_str().unwrap();
        let current = delta["changed"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["path"] == path)
            .or_else(|| {
                baseline["files"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|row| row["path"] == path)
            })
            .unwrap();
        let expected = if path == "ci/gauntlet/evidence.py" {
            &compatible
        } else {
            &source["sha256"]
        };
        assert_eq!(*expected, current["sha256"], "{path}");
    }
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 31);
    for case in cases {
        let actual = reconcile_host_calls(case["events"].as_array().unwrap()).unwrap();
        assert_eq!(
            actual,
            json!({"calls": case["calls"], "errors": case["errors"]}),
            "{}",
            case["name"]
        );
    }
}

#[test]
fn malformed_or_unbounded_event_arrays_refuse() {
    assert!(reconcile_host_calls(&[Value::Null]).is_err());
    assert!(reconcile_host_calls(&vec![json!({}); 50_001]).is_err());
}
