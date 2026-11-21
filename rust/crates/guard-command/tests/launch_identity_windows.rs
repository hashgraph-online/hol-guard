#![cfg(windows)]

//! Runtime launch identities on Windows: a launcher found through PATH and
//! PATHEXT resolves to a verified, content-bound executable the MCP proxy can
//! launch, a changed file stops matching, and unresolved commands fail closed.

use std::path::{Path, PathBuf};

use guard_command::launch_identity::{
    build_runtime_launch_identity, resolved_runtime_launch_executable,
    runtime_launch_identity_is_reusable, runtime_launch_identity_matches,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const LAUNCHER: &str = "@echo off\r\npython \"%~dp0server.py\"\r\n";

fn identity(command: &str, search_path: &Path, cwd: &Path) -> Value {
    build_runtime_launch_identity(
        &json!(command),
        &[json!("--stdio")],
        true,
        false,
        search_path.to_str(),
        Some(cwd),
        None,
        None,
    )
}

fn matches(expected: &Value, command: &str, search_path: &Path, cwd: &Path) -> bool {
    runtime_launch_identity_matches(
        expected,
        &json!(command),
        &[json!("--stdio")],
        true,
        false,
        search_path.to_str(),
        Some(cwd),
        None,
    )
}

fn fixture(name: &str) -> (PathBuf, PathBuf) {
    let root = std::env::temp_dir().join(format!("{name}_{}", std::process::id()));
    let bin = root.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::write(bin.join("fake-mcp.cmd"), LAUNCHER).unwrap();
    std::fs::write(bin.join("server.js"), "console.log(1)\n").unwrap();
    (root, bin)
}

#[test]
fn a_path_launcher_projects_to_its_verified_executable() {
    let (root, bin) = fixture("launch_identity_verified");
    let launch = identity("fake-mcp", &bin, &root);
    let executable = &launch["executable"];
    assert_eq!(executable["status"], json!("verified"), "{launch:?}");
    assert_eq!(executable["file_format"], json!("script"));
    let digest = hex::encode(Sha256::digest(LAUNCHER.as_bytes()));
    assert_eq!(executable["sha256"], json!(digest));
    let path = resolved_runtime_launch_executable(&launch).expect("verified executable");
    assert_eq!(executable["path"], json!(path));
    assert!(Path::new(&path).is_absolute(), "{path}");
    assert!(!path.starts_with(r"\\?\"), "{path}");
    assert!(
        path.to_ascii_lowercase().ends_with(r"\bin\fake-mcp.cmd"),
        "{path}"
    );
    // The entrypoint stays unproven, so no saved approval can reuse it.
    assert!(!runtime_launch_identity_is_reusable(&launch));
    assert!(matches(&launch, "fake-mcp", &bin, &root));

    // An explicit relative path resolves against the launch cwd.
    let explicit = identity(r".\bin\fake-mcp", &bin, &root);
    assert_eq!(resolved_runtime_launch_executable(&explicit), Some(path));

    std::fs::write(bin.join("fake-mcp.cmd"), "@echo off\r\nexit /b 1\r\n").unwrap();
    assert!(!matches(&launch, "fake-mcp", &bin, &root));
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn unresolved_and_non_executable_commands_fail_closed() {
    let (root, bin) = fixture("launch_identity_unresolved");
    for command in ["guard-missing-launcher", "server.js", r".\bin\server.js"] {
        let launch = identity(command, &bin, &root);
        assert_ne!(
            launch["executable"]["status"],
            json!("verified"),
            "{command}"
        );
        assert!(launch["executable"]["reuse_nonce"].is_string(), "{command}");
        assert_eq!(
            resolved_runtime_launch_executable(&launch),
            None,
            "{command}"
        );
        assert!(!matches(&launch, command, &bin, &root), "{command}");
    }
    let _ = std::fs::remove_dir_all(&root);
}
