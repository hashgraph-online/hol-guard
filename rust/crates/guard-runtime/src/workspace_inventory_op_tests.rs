//! Parity vectors recorded from the legacy Python
//! `local_supply_chain._workspace_files`, `_workspace_audit_inventory`,
//! `_workspace_diff_audit_inventory` and `_audit_lockfile_warnings` before they
//! were deleted. Each vector carries the workspace files and the payload the
//! Python path produced.

use super::*;
use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;

const VECTORS: &str = include_str!("../testdata/workspace_inventory_vectors.json");

struct Scratch(PathBuf);

impl Scratch {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "workspace-inventory-{label}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Self(fs::canonicalize(path).unwrap())
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn write_files(root: &Path, files: &Value) {
    for (relative, content) in files.as_object().unwrap() {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        match content {
            Value::String(text) => fs::write(&path, text).unwrap(),
            Value::Object(spec) => {
                if let Some(target) = spec.get("symlink").and_then(Value::as_str) {
                    #[cfg(unix)]
                    std::os::unix::fs::symlink(target, &path).unwrap();
                    #[cfg(not(unix))]
                    let _ = target;
                } else {
                    let hex = spec["hex"].as_str().unwrap();
                    let bytes: Vec<u8> = (0..hex.len())
                        .step_by(2)
                        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap())
                        .collect();
                    fs::write(&path, bytes).unwrap();
                }
            }
            _ => panic!("bad file spec"),
        }
    }
}

fn request(
    workspace: &Path,
    before: Option<&Path>,
    sboms: &[String],
    mode: &str,
) -> WorkspaceInventoryRequestV1 {
    WorkspaceInventoryRequestV1 {
        schema: PACKAGE_AUTHORITY_REQUEST_SCHEMA.to_owned(),
        request_id: "vector".to_owned(),
        guard_home: "/tmp/guard-home".to_owned(),
        workspace_dir: workspace.display().to_string(),
        before_workspace_dir: before.map(|path| path.display().to_string()),
        sbom_paths: sboms.to_vec(),
        files_only: mode == "files",
        include_lockfile_warnings: mode != "files",
    }
}

fn run(request: &WorkspaceInventoryRequestV1) -> Result<Value, String> {
    evaluate_workspace_inventory(request)
        .map(|bytes| serde_json::from_slice::<Value>(&bytes).unwrap()["payload"].clone())
}

#[test]
fn recorded_python_vectors_match() {
    let vectors: Vec<Value> = serde_json::from_str(VECTORS).unwrap();
    assert!(vectors.len() >= 20);
    for vector in &vectors {
        let name = vector["name"].as_str().unwrap();
        let scratch = Scratch::new(name);
        let workspace = scratch.0.join("ws");
        fs::create_dir_all(&workspace).unwrap();
        write_files(&workspace, &vector["files"]);
        let before = vector["before_files"].as_object().map(|_| {
            let path = scratch.0.join("before");
            fs::create_dir_all(&path).unwrap();
            write_files(&path, &vector["before_files"]);
            path
        });
        let sboms: Vec<String> = vector["sbom_paths"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .unwrap()
                    .replace("{TMP}", &scratch.0.display().to_string())
            })
            .collect();
        let payload = run(&request(
            &workspace,
            before.as_deref(),
            &sboms,
            vector["mode"].as_str().unwrap(),
        ))
        .unwrap();
        assert_eq!(payload, vector["expected"], "{name}");
    }
}

#[test]
fn rejects_malformed_requests() {
    let scratch = Scratch::new("malformed");
    let valid = request(&scratch.0, None, &[], "inventory");
    let mut bad_schema = valid.clone();
    bad_schema.schema = "other".into();
    assert_eq!(
        run(&bad_schema).unwrap_err(),
        "native_workspace_inventory_schema_mismatch"
    );
    for mutate in [
        |request: &mut WorkspaceInventoryRequestV1| request.request_id.clear(),
        |request: &mut WorkspaceInventoryRequestV1| request.guard_home.clear(),
        |request: &mut WorkspaceInventoryRequestV1| request.workspace_dir.clear(),
    ] {
        let mut bad = valid.clone();
        mutate(&mut bad);
        assert_eq!(run(&bad).unwrap_err(), "native_workspace_inventory_invalid");
    }
}

#[test]
fn unreadable_diff_file_fails_the_request() {
    let scratch = Scratch::new("unreadable");
    let after = scratch.0.join("after");
    let before = scratch.0.join("before");
    write_files(&after, &json!({"package.json": "{}"}));
    write_files(&before, &json!({"package.json": {"hex": "ffff"}}));
    assert_eq!(
        run(&request(&after, Some(&before), &[], "inventory")).unwrap_err(),
        "native_workspace_inventory_invalid"
    );
}

#[test]
fn oversized_sbom_is_skipped() {
    let scratch = Scratch::new("oversized");
    let workspace = scratch.0.join("ws");
    fs::create_dir_all(&workspace).unwrap();
    let oversized = vec![b'x'; (10 * 1024 * 1024) + 1];
    fs::write(workspace.join("big-sbom.json"), oversized).unwrap();
    let payload = run(&request(
        &workspace,
        None,
        &["big-sbom.json".to_owned()],
        "inventory",
    ))
    .unwrap();
    assert_eq!(payload["sbom_paths"], json!(["big-sbom.json"]));
    assert_eq!(payload["inventory"], json!([]));
}
