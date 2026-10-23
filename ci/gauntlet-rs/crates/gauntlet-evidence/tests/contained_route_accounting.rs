use gauntlet_evidence::verify_contained_route_accounting;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::Path;

#[test]
fn exact_python_contained_route_accounting_matches() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/contained_route_accounting_v1.json")).unwrap();
    assert_eq!(
        fixture["schema"],
        "gauntlet-python-contained-route-accounting.v1"
    );
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(4)
        .unwrap()
        .join("ci/gauntlet/benchmark/private_cell_runtime_custody.py");
    assert_eq!(
        fixture["source_sha256"],
        format!("{:x}", Sha256::digest(std::fs::read(source).unwrap()))
    );
    let rows = fixture["cases"].as_array().unwrap();
    assert_eq!(rows.len(), 13);
    assert_eq!(rows.iter().filter(|row| row["accepted"] == true).count(), 5);
    for row in rows {
        let name = row["name"].as_str().unwrap();
        let observed = verify_contained_route_accounting(&row["builtin"], &row["plane"]);
        if row["accepted"] == true {
            let accepted = observed.unwrap_or_else(|error| panic!("{name}: {error}"));
            let consumed = row["builtin"]["contained_transport_observations"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|event| event["kind"] == "contained-route-consumed")
                .count();
            assert_eq!(accepted["matched_routes"], consumed, "{name}");
            assert_eq!(accepted["execution_eligible"], false, "{name}");
        } else {
            assert_eq!(
                observed.unwrap_err().to_string(),
                row["reason"].as_str().unwrap(),
                "{name}"
            );
        }
    }
}
