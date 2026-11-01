use gauntlet_contracts::schema_kinds;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::Path;

#[test]
fn pinned_schema_files_match_source_inventory() {
    let manifest: Value =
        serde_json::from_str(include_str!("../../../parity-manifest.v1.json")).unwrap();
    assert_eq!(manifest["schema"], "gauntlet-rust-parity-manifest.v1");
    assert_eq!(
        manifest["source_commit"],
        "b4efd8171b06d0e13cbe12a077c376ecdc891fd1"
    );
    let files = manifest["files"].as_array().unwrap();
    assert_eq!(files.len(), 420);
    assert_eq!(manifest["source_file_count"], 420);
    let mut names = BTreeSet::new();
    let mut schemas = BTreeSet::new();
    for file in files {
        let name = file["path"].as_str().unwrap();
        let digest = file["sha256"].as_str().unwrap();
        assert!(names.insert(name));
        assert_eq!(digest.len(), 64);
        if let Some(filename) = name.strip_prefix("ci/gauntlet/benchmark/schemas/") {
            let path = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("schemas")
                .join(filename);
            let raw = std::fs::read(path).unwrap();
            assert_eq!(format!("{:x}", Sha256::digest(raw)), digest, "{name}");
            schemas.insert(filename.strip_suffix(".v1.json").unwrap());
        }
    }
    assert_eq!(schemas, schema_kinds().collect());
}
