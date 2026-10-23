use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

#[test]
fn merged_gauntlet_source_matches_the_explicit_pinned_delta() {
    let baseline: Value =
        serde_json::from_str(include_str!("../../../parity-manifest.v1.json")).unwrap();
    let delta: Value =
        serde_json::from_str(include_str!("../../../integration-source-delta.v1.json")).unwrap();
    assert_eq!(delta["schema"], "gauntlet-rust-integration-source-delta.v1");
    assert_eq!(delta["base_source_commit"], baseline["source_commit"]);
    assert_eq!(
        delta["integration_commit"],
        "b7f1f3273da9a874a8eed1b3aaea712cec5e9380"
    );

    let mut expected: BTreeMap<&str, &str> = baseline["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            (
                entry["path"].as_str().unwrap(),
                entry["sha256"].as_str().unwrap(),
            )
        })
        .collect();
    let changed = delta["changed"].as_array().unwrap();
    let added = delta["added"].as_array().unwrap();
    // Main through 4a654ea8 updates the catalog, metadata probes and CI docs.
    // Every tracked byte is still checked against the reviewed source map.
    assert_eq!(changed.len(), 58);
    assert_eq!(added.len(), 7);
    for entry in changed {
        let path = entry["path"].as_str().unwrap();
        assert_eq!(expected.get(path), entry["base_sha256"].as_str().as_ref());
        expected.insert(path, entry["sha256"].as_str().unwrap());
    }
    for entry in added {
        let path = entry["path"].as_str().unwrap();
        assert!(expected
            .insert(path, entry["sha256"].as_str().unwrap())
            .is_none());
    }
    assert_eq!(
        expected.len(),
        delta["source_file_count"].as_u64().unwrap() as usize
    );

    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(4)
        .unwrap();
    let listed = Command::new("git")
        .args(["ls-files", "ci/gauntlet"])
        .current_dir(root)
        .output()
        .unwrap();
    assert!(listed.status.success());
    let actual = String::from_utf8(listed.stdout).unwrap();
    assert_eq!(
        actual.lines().collect::<Vec<_>>(),
        expected.keys().copied().collect::<Vec<_>>()
    );
    for (path, digest) in expected {
        let bytes = std::fs::read(root.join(path)).unwrap();
        assert_eq!(format!("{:x}", Sha256::digest(bytes)), digest, "{path}");
    }
}
