use gauntlet_evidence::verify_private_runtime_prompt_relation;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::Path;

fn public_key(raw: &str) -> Vec<u8> {
    raw.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn signed_python_public_prompt_relation_matches() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/private_runtime_prompt_v1.json")).unwrap();
    assert_eq!(
        fixture["schema"],
        "gauntlet-python-private-runtime-prompt.v1"
    );
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(4)
        .unwrap();
    for (field, source) in [
        (
            "source_sha256",
            "ci/gauntlet/benchmark/private_cell_runtime_custody.py",
        ),
        (
            "custody_sha256",
            "ci/gauntlet/benchmark/developer_product_custody.py",
        ),
    ] {
        assert_eq!(
            fixture[field],
            format!(
                "{:x}",
                Sha256::digest(std::fs::read(root.join(source)).unwrap())
            )
        );
    }
    let rows = fixture["cases"].as_array().unwrap();
    assert_eq!(rows.len(), 22);
    assert_eq!(rows.iter().filter(|row| row["accepted"] == true).count(), 3);
    for row in rows {
        let name = row["name"].as_str().unwrap();
        let raw = serde_json::to_vec(&row["runtime"]).unwrap();
        let observed = verify_private_runtime_prompt_relation(
            &raw,
            &public_key(row["public_key_hex"].as_str().unwrap()),
            row["session_id"].as_str().unwrap(),
            row["prompt_digest"].as_str().unwrap(),
        );
        if row["accepted"] == true {
            assert_eq!(
                observed.unwrap_or_else(|error| panic!("{name}: {error}")),
                serde_json::json!({"matched_public_prompts": 1, "execution_eligible": false}),
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
fn ambiguous_outer_runtime_is_refused() {
    let raw = br#"{"record":{},"record":{},"signature":"invalid"}"#;
    let error =
        verify_private_runtime_prompt_relation(raw, &[0; 32], "session", "digest").unwrap_err();
    assert_eq!(error.to_string(), "invalid controller envelope");
}
