use gauntlet_evidence::verify_private_network_topology;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::Path;

#[test]
fn python_loopback_topology_matches() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/private_network_v1.json")).unwrap();
    assert_eq!(fixture["schema"], "gauntlet-python-private-network.v1");
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(4)
        .unwrap()
        .join("ci/gauntlet/benchmark/product_vm_network.py");
    assert_eq!(
        fixture["source_sha256"],
        format!("{:x}", Sha256::digest(std::fs::read(source).unwrap()))
    );
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 20);
    assert_eq!(
        cases.iter().filter(|row| row["accepted"] == true).count(),
        4
    );
    for row in cases {
        let name = row["name"].as_str().unwrap();
        let observed = verify_private_network_topology(
            row["devices"].as_str().unwrap(),
            row["routes4"].as_str().unwrap(),
            row["routes6"].as_str().unwrap(),
            row["addresses6"].as_str().unwrap(),
        );
        if row["accepted"] == true {
            let mut expected = row["result"].clone();
            expected["execution_eligible"] = json!(false);
            assert_eq!(
                observed.unwrap_or_else(|error| panic!("{name}: {error}")),
                expected,
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

#[test]
fn oversized_kernel_observation_refuses() {
    let long = "x".repeat(65537);
    assert_eq!(
        verify_private_network_topology("lo: 0\n", &long, "", "")
            .unwrap_err()
            .to_string(),
        "private network kernel observation byte budget"
    );
}
