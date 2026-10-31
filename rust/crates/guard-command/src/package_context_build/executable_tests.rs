//! PATH drift for the package-manager executable component: only a change in
//! the binary a bare manager name resolves to may change it.

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use serde_json::{json, Map, Value};

use super::{build_package_execution_context, BuildInput};

fn write_manager(directory: &Path, body: &str) {
    std::fs::create_dir_all(directory).unwrap();
    let path = directory.join("bun");
    std::fs::write(&path, body).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

fn executable_digest(root: &Path, search_path: &[&Path]) -> String {
    let workspace = root.join("workspace");
    std::fs::create_dir_all(&workspace).unwrap();
    let home = root.join("home");
    std::fs::create_dir_all(&home).unwrap();
    let joined = search_path
        .iter()
        .map(|directory| directory.to_str().unwrap())
        .collect::<Vec<_>>()
        .join(":");
    let environment = BTreeMap::from([
        ("HOME".to_owned(), home.to_str().unwrap().to_owned()),
        ("PATH".to_owned(), joined.clone()),
    ]);
    let metadata: Map<String, Value> = serde_json::from_value(json!({
        "package_manager": "bun",
        "intent_kind": "install",
        "flags": ["-g"],
    }))
    .unwrap();
    let built = build_package_execution_context(&BuildInput {
        workspace_dir: workspace.to_str().unwrap(),
        metadata: &metadata,
        executable: Some("bun"),
        executable_args: &["install".to_owned(), "-g".to_owned()],
        environment: &environment,
        process_cwd: workspace.to_str().unwrap(),
        process_home: home.to_str().unwrap(),
        process_home_env: home.to_str(),
        process_path: Some(&joined),
    })
    .unwrap();
    built
        .components
        .into_iter()
        .find(|component| component.name == "package_manager_executable")
        .unwrap()
        .digest
}

#[test]
fn unrelated_path_prefix_keeps_the_executable_digest() {
    let root = tempfile::tempdir().unwrap();
    let manager_bin = root.path().join("manager-bin");
    let shim_bin = root.path().join("agent-shim-1234");
    write_manager(&manager_bin, "#!/bin/sh\n# bun-v1\n");
    std::fs::create_dir_all(&shim_bin).unwrap();

    let baseline = executable_digest(root.path(), &[&manager_bin]);
    let prefixed = executable_digest(root.path(), &[&shim_bin, &manager_bin]);

    assert_eq!(baseline, prefixed);
    write_manager(&manager_bin, "#!/bin/sh\n# bun-v2\n");
    assert_ne!(baseline, executable_digest(root.path(), &[&manager_bin]));
}

#[test]
fn shadowing_manager_earlier_in_path_changes_the_executable_digest() {
    let root = tempfile::tempdir().unwrap();
    let manager_bin = root.path().join("manager-bin");
    let shadow_bin = root.path().join("shadow-bin");
    write_manager(&manager_bin, "#!/bin/sh\n# bun-v1\n");
    write_manager(&shadow_bin, "#!/bin/sh\n# bun-v1\n");

    let baseline = executable_digest(root.path(), &[&manager_bin]);
    let shadowed = executable_digest(root.path(), &[&shadow_bin, &manager_bin]);

    assert_ne!(baseline, shadowed);
}
