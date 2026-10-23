use gauntlet_evidence::verify_native_transport_relations;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::Path;

#[test]
fn python_sdk_native_transport_and_operations_match() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/native_transport_v1.json")).unwrap();
    assert_eq!(fixture["schema"], "gauntlet-python-native-transport.v1");
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(4)
        .unwrap()
        .join("ci/gauntlet/benchmark/developer_product_custody.py");
    assert_eq!(
        fixture["source_sha256"],
        format!("{:x}", Sha256::digest(std::fs::read(source).unwrap()))
    );
    let rows = fixture["cases"].as_array().unwrap();
    assert_eq!(rows.len(), 27);
    assert_eq!(rows.iter().filter(|row| row["accepted"] == true).count(), 4);
    for row in rows {
        let name = row["name"].as_str().unwrap();
        let observed = verify_native_transport_relations(
            &row["builtin"],
            &row["plane"],
            &row["record"],
            row["sdk_pid"].as_u64().unwrap(),
            &row["sdk_identity"],
            row["require_sdk"].as_bool().unwrap(),
        );
        if row["accepted"] == true {
            let actual_count = row["builtin"]["transport_observations"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|event| event["kind"] == "actual-hook-response")
                .count();
            assert_eq!(
                observed.unwrap_or_else(|error| panic!("{name}: {error}")),
                json!({"native_review_count": actual_count,
                       "admitted_operations": row["record"]["operations"]["admitted"],
                       "execution_eligible": false}),
                "{name}"
            );
        } else {
            assert_eq!(
                observed.unwrap_err().to_string(),
                row["reason"].as_str().unwrap(),
                "{name}"
            );
        }
    }
}
