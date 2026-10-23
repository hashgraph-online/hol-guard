use gauntlet_host_state::{load_operations_bytes, QueueConfig};
use serde_json::{json, Value};

#[test]
fn full_operator_config_matches_pinned_python_merge_and_refusal_reasons() {
    let fixture: Value =
        serde_json::from_str(include_str!("python_operations_config_v1.json")).unwrap();
    let manifest: Value =
        serde_json::from_str(include_str!("../../../parity-manifest.v1.json")).unwrap();
    let source = manifest["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["path"] == "ci/gauntlet/control_plane/config.py")
        .unwrap();
    assert_eq!(fixture["source_sha256"], source["sha256"]);
    assert_eq!(fixture["schema"], "gauntlet-operations-config-fixtures.v1");
    let defaults: Value =
        serde_json::from_str(include_str!("../operations-defaults-v1.json")).unwrap();
    assert_eq!(defaults, fixture["defaults"]);
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 37);
    for case in cases {
        let raw = serde_json::to_vec(&case["overrides"]).unwrap();
        let actual = load_operations_bytes(&raw);
        if case["accepted"] == true {
            let loaded = actual.unwrap_or_else(|error| panic!("{case}: {error}"));
            assert_eq!(loaded, case["value"], "{case}");
            QueueConfig::from_operations(&loaded).unwrap();
        } else {
            assert_eq!(
                actual.unwrap_err().reason,
                case["reason"].as_str().unwrap(),
                "{case}"
            );
        }
    }
}

#[test]
fn malformed_or_oversize_input_refuses_before_config_use() {
    assert!(load_operations_bytes(b"{").is_err());
    assert!(load_operations_bytes(b"[]").is_err());
    assert!(load_operations_bytes(&vec![b' '; 1024 * 1024 + 1]).is_err());
    let mut invalid = serde_json::to_vec(&json!({})).unwrap();
    invalid.push(0);
    assert!(load_operations_bytes(&invalid).is_err());
}
