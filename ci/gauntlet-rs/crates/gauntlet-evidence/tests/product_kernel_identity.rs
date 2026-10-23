use gauntlet_evidence::verify_product_kernel_identity;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::Path;

#[test]
fn python_product_kernel_identity_matches() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/product_kernel_identity_v1.json")).unwrap();
    assert_eq!(
        fixture["schema"],
        "gauntlet-python-product-kernel-identity.v1"
    );
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(4)
        .unwrap()
        .join("ci/gauntlet/benchmark/product_custody.py");
    assert_eq!(
        fixture["source_sha256"],
        format!("{:x}", Sha256::digest(std::fs::read(source).unwrap()))
    );
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 25);
    assert_eq!(
        cases.iter().filter(|row| row["accepted"] == true).count(),
        4
    );
    for row in cases {
        let name = row["name"].as_str().unwrap();
        let observed = verify_product_kernel_identity(
            &row["identity"],
            &row["controller"],
            row["agent"].as_object().map(|_| &row["agent"]),
            row["product_uid"].as_u64().unwrap(),
        );
        if row["accepted"] == true {
            assert_eq!(
                observed.unwrap_or_else(|error| panic!("{name}: {error}")),
                json!({"identity_consistent": true, "execution_eligible": false}),
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
