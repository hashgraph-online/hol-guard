use gauntlet_evidence::plan_controller_install;
use serde_json::Value;
use std::collections::BTreeMap;

fn current_source_map() -> BTreeMap<String, String> {
    let baseline: Value =
        serde_json::from_str(include_str!("../../../parity-manifest.v1.json")).unwrap();
    let delta: Value =
        serde_json::from_str(include_str!("../../../integration-source-delta.v1.json")).unwrap();
    assert_eq!(delta["base_source_commit"], baseline["source_commit"]);
    let mut files: BTreeMap<String, String> = baseline["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            (
                row["path"].as_str().unwrap().to_owned(),
                row["sha256"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    for row in delta["changed"].as_array().unwrap() {
        let path = row["path"].as_str().unwrap();
        assert_eq!(
            files.get(path).map(String::as_str),
            row["base_sha256"].as_str()
        );
        files.insert(path.to_owned(), row["sha256"].as_str().unwrap().to_owned());
    }
    for row in delta["added"].as_array().unwrap() {
        assert!(files
            .insert(
                row["path"].as_str().unwrap().to_owned(),
                row["sha256"].as_str().unwrap().to_owned(),
            )
            .is_none());
    }
    assert_eq!(files.len(), 427);
    files
}

#[test]
fn current_source_map_matches_python_bootstrap_tree_plan() {
    // Frozen independently from bootstrap.py's selection and bootstrap_guest.py's
    // 0755/0444 Root install modes, then Python canonical SHA-256 over the same
    // path/mode/uid/file-hash shape used by TreeKind::Controller. Recomputed
    // from bootstrap.py's actual selection after merging main at 4a654ea8.
    let plan = plan_controller_install(&current_source_map()).unwrap();
    assert_eq!(plan.installed_files.len(), 396);
    assert_eq!(plan.entries, 407);
    assert_eq!(
        plan.tree_digest,
        "28fd562fa80d0ed626d9732da75590273a0a9b2c8b815df8fcabb228d1de2c8b"
    );
    assert!(plan
        .installed_files
        .contains_key("ci/gauntlet/benchmark/__main__.py"));
    assert!(!plan
        .installed_files
        .contains_key("ci/gauntlet/control_plane/bootstrap.py"));
}

#[test]
fn source_drift_and_unlisted_installed_files_cannot_keep_the_expected_tree_digest() {
    let source = current_source_map();
    let expected = plan_controller_install(&source).unwrap();
    let mut changed = source.clone();
    changed.insert(
        "ci/gauntlet/benchmark/__main__.py".to_owned(),
        "0".repeat(64),
    );
    assert_ne!(
        plan_controller_install(&changed).unwrap().tree_digest,
        expected.tree_digest
    );
    let mut extra = source.clone();
    extra.insert("ci/gauntlet/extra.py".to_owned(), "0".repeat(64));
    assert_ne!(
        plan_controller_install(&extra).unwrap().tree_digest,
        expected.tree_digest
    );
    // Python deliberately omits this control-plane file. A fresh installer
    // cannot place it; whole-tree verification still rejects it if present.
    let mut excluded = source.clone();
    excluded.insert(
        "ci/gauntlet/control_plane/unlisted.py".to_owned(),
        "0".repeat(64),
    );
    assert_eq!(
        plan_controller_install(&excluded).unwrap().tree_digest,
        expected.tree_digest
    );
    let mut missing = source.clone();
    missing.remove("ci/gauntlet/benchmark/__main__.py");
    assert!(plan_controller_install(&missing).is_err());
    let mut conflict = source.clone();
    conflict.insert(
        "ci/gauntlet/benchmark/__main__.py/child".to_owned(),
        "0".repeat(64),
    );
    assert!(plan_controller_install(&conflict).is_err());
    let mut unsafe_path = source;
    unsafe_path.insert("ci/gauntlet/../outside".to_owned(), "0".repeat(64));
    assert!(plan_controller_install(&unsafe_path).is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn optional_root_owned_fresh_install_fixture_matches_the_source_plan() {
    let Some(root) = std::env::var_os("GAUNTLET_CONTROLLER_INSTALL_FIXTURE") else {
        return;
    };
    let expected = plan_controller_install(&current_source_map()).unwrap();
    let observed = gauntlet_evidence::verify_controller_tree(
        std::path::Path::new(&root),
        &expected.tree_digest,
    )
    .unwrap();
    assert_eq!(observed.entries(), expected.entries);
}
