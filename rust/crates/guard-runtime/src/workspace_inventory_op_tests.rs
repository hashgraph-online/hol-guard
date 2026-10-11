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
        targets_only: false,
        package_spec: None,
        inventory_offset: 0,
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
        let mut payload = run(&request(
            &workspace,
            before.as_deref(),
            &sboms,
            vector["mode"].as_str().unwrap(),
        ))
        .unwrap();
        let object = payload.as_object_mut().unwrap();
        assert_eq!(object.remove("scan_targets").unwrap(), json!([]), "{name}");
        assert!(object.remove("package_target").unwrap().is_null());
        assert_eq!(object.remove("next_offset"), Some(Value::Null), "{name}");
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

#[test]
fn explicit_package_spec_yields_a_target() {
    let scratch = Scratch::new("explicit-spec");
    let mut explain = request(&scratch.0, None, &[], "files");
    explain.package_spec = Some(guard_contracts::WorkspacePackageSpecV1 {
        ecosystem: "npm".into(),
        spec: "left-pad@1.3.0".into(),
    });
    let payload = run(&explain).unwrap();
    assert_eq!(payload["package_target"]["package_name"], "left-pad");
    assert_eq!(payload["package_target"]["requested_specifier"], "1.3.0");
    assert_eq!(payload["scan_targets"], serde_json::json!([]));
}

#[test]
fn targets_only_returns_one_target_per_inventory_item() {
    let vectors: Vec<Value> = serde_json::from_str(VECTORS).unwrap();
    let vector = vectors
        .iter()
        .find(|vector| vector["mode"] == "inventory" && vector["before_files"].is_null())
        .unwrap();
    let scratch = Scratch::new("targets-only");
    write_files(&scratch.0, &vector["files"]);
    let mut only = request(&scratch.0, None, &[], "inventory");
    only.targets_only = true;
    let payload = run(&only).unwrap();
    assert_eq!(payload["inventory"], json!([]));
    assert_eq!(
        payload["scan_targets"].as_array().unwrap().len(),
        vector["expected"]["inventory"].as_array().unwrap().len()
    );
}

#[test]
fn large_target_list_is_returned_in_pages() {
    let scratch = Scratch::new("paged-targets");
    let workspace = scratch.0.join("ws");
    fs::create_dir_all(&workspace).unwrap();
    let mut components = String::from(r#"{"bomFormat":"CycloneDX","components":["#);
    for index in 0..12_000 {
        if index > 0 {
            components.push(',');
        }
        components.push_str(&format!(
            r#"{{"name":"package-with-a-long-name-{index:05}","version":"1.0.0","purl":"pkg:npm/package-with-a-long-name-{index:05}@1.0.0"}}"#
        ));
    }
    components.push_str("]}");
    fs::write(workspace.join("sbom.cdx.json"), components).unwrap();
    let mut request = request(&workspace, None, &["sbom.cdx.json".to_owned()], "inventory");
    request.targets_only = true;
    let mut names: Vec<String> = Vec::new();
    let mut pages = 0;
    loop {
        let bytes = evaluate_workspace_inventory(&request).unwrap();
        assert!(bytes.len() < guard_contracts::MAX_NATIVE_RESPONSE_BYTES);
        let payload = serde_json::from_slice::<Value>(&bytes).unwrap()["payload"].clone();
        pages += 1;
        assert_eq!(payload["inventory"], json!([]));
        for target in payload["scan_targets"].as_array().unwrap() {
            names.push(target["package_name"].as_str().unwrap().to_owned());
        }
        match payload["next_offset"].as_u64() {
            Some(next) => request.inventory_offset = next as usize,
            None => break,
        }
        assert!(pages < 64);
    }
    assert!(pages > 1);
    assert_eq!(names.len(), 12_000);
    assert_eq!(names[11_999], "package-with-a-long-name-11999");
}

#[test]
fn relative_workspace_dirs_are_rejected() {
    let mut relative_workspace =
        request(Path::new("/tmp/unused-workspace"), None, &[], "inventory");
    relative_workspace.workspace_dir = "relative/workspace".into();
    assert_eq!(
        run(&relative_workspace).unwrap_err(),
        "native_workspace_inventory_invalid"
    );
    let scratch = Scratch::new("relative-before");
    let mut relative_before = request(&scratch.0, None, &[], "inventory");
    relative_before.before_workspace_dir = Some("relative/before".into());
    assert_eq!(
        run(&relative_before).unwrap_err(),
        "native_workspace_inventory_invalid"
    );
}

#[test]
fn large_inventory_is_returned_in_pages() {
    let scratch = Scratch::new("paged");
    let workspace = scratch.0.join("ws");
    fs::create_dir_all(&workspace).unwrap();
    let mut components = String::from(r#"{"bomFormat":"CycloneDX","components":["#);
    for index in 0..12_000 {
        if index > 0 {
            components.push(',');
        }
        components.push_str(&format!(
            r#"{{"name":"package-with-a-long-name-{index:05}","version":"1.0.0"}}"#
        ));
    }
    components.push_str("]}");
    fs::write(workspace.join("sbom.cdx.json"), components).unwrap();
    let mut names: Vec<String> = Vec::new();
    let mut pages = 0;
    let mut request = request(&workspace, None, &["sbom.cdx.json".to_owned()], "inventory");
    loop {
        let bytes = evaluate_workspace_inventory(&request).unwrap();
        assert!(bytes.len() < guard_contracts::MAX_NATIVE_RESPONSE_BYTES);
        let payload = serde_json::from_slice::<Value>(&bytes).unwrap()["payload"].clone();
        pages += 1;
        for entry in payload["inventory"].as_array().unwrap() {
            names.push(entry["name"].as_str().unwrap().to_owned());
        }
        match payload["next_offset"].as_u64() {
            Some(next) => {
                assert!(next as usize > request.inventory_offset);
                request.inventory_offset = next as usize;
            }
            None => break,
        }
        assert!(pages < 64);
    }
    assert!(pages > 1);
    assert_eq!(names.len(), 12_000);
    assert_eq!(names[0], "package-with-a-long-name-00000");
    assert_eq!(names[11_999], "package-with-a-long-name-11999");
}

#[test]
fn inventory_row_larger_than_the_resident_reply_is_rejected() {
    let scratch = Scratch::new("row-too-large");
    let workspace = scratch.0.join("ws");
    fs::create_dir_all(&workspace).unwrap();
    let name = "n".repeat(crate::MAX_NATIVE_RESPONSE_BYTES);
    let sbom =
        format!(r#"{{"bomFormat":"CycloneDX","components":[{{"name":"{name}","version":"1"}}]}}"#);
    fs::write(workspace.join("sbom.cdx.json"), sbom).unwrap();
    assert_eq!(
        run(&request(
            &workspace,
            None,
            &["sbom.cdx.json".to_owned()],
            "inventory",
        ))
        .unwrap_err(),
        "workspace_inventory_exceeds_resident_response"
    );
}
