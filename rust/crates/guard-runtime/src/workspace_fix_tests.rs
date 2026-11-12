use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use super::*;

fn manifest(version: &str) -> String {
    format!(
        "{{\n  \"name\": \"app\",\n  \"dependencies\": {{\n    \"left-pad\": \"{version}\"\n  }}\n}}\n"
    )
}

fn project() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(dir.path()).unwrap();
    fs::write(root.join("package.json"), manifest("^1.0.0")).unwrap();
    (dir, root)
}

fn call(request: &Value) -> Value {
    run_command(request.to_string().as_bytes()).unwrap()
}

fn plan_request(root: &Path) -> Value {
    json!({"op": "plan", "root": root, "package": "left-pad", "fix_version": "1.3.0"})
}

fn plan_result(root: &Path) -> Value {
    let response = call(&plan_request(root));
    assert_eq!(response["ok"], true, "{response}");
    response["result"].clone()
}

fn apply_request(root: &Path, proposal: &Value) -> Value {
    json!({
        "op": "apply",
        "root": root,
        "manifest_path": proposal["manifest_path"],
        "base_sha256": proposal["base_sha256"],
        "new_sha256": proposal["new_sha256"],
        "edits": proposal["edits"],
    })
}

fn write_manifest(root: &Path, dir: &str, text: &str) {
    fs::create_dir_all(root.join(dir)).unwrap();
    fs::write(root.join(dir).join("package.json"), text).unwrap();
}

#[test]
fn plans_an_edit_with_diff_and_hashes() {
    let (_dir, root) = project();
    let result = plan_result(&root);
    let proposal = &result["proposals"][0];
    assert_eq!(proposal["manifest_path"], "package.json");
    assert_eq!(proposal["edits"][0]["to_spec"], "^1.3.0");
    assert!(proposal["diff"]
        .as_str()
        .unwrap()
        .contains("-    \"left-pad\": \"^1.0.0\""));
    assert_eq!(
        proposal["base_sha256"],
        sha256_hex(manifest("^1.0.0").as_bytes())
    );
    assert_eq!(
        proposal["new_sha256"],
        sha256_hex(manifest("^1.3.0").as_bytes())
    );
    assert_eq!(result["truncated"], false);
    assert_eq!(result["skipped"], json!([]));
}

#[test]
fn only_inventory_manifests_are_planned() {
    let (_dir, root) = project();
    for dir in ["node_modules/left-pad", "packages/app", "a/b/c/d/e"] {
        write_manifest(&root, dir, &manifest("1.0.0"));
    }
    let result = plan_result(&root);
    let paths: Vec<&str> = result["proposals"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["manifest_path"].as_str().unwrap())
        .collect();
    assert_eq!(paths, ["package.json", "packages/app/package.json"]);
}

#[test]
fn skipped_manifests_explain_why_and_declared_ones_come_first() {
    let (_dir, root) = project();
    write_manifest(&root, "a", "{ not json");
    write_manifest(&root, "b", &manifest("workspace:*"));
    write_manifest(&root, "c", "{\"name\": \"none\"}");
    let result = plan_result(&root);
    assert_eq!(
        result["skipped"],
        json!([
            {"manifest_path": "b/package.json", "reason": "spec_workspace_protocol"},
            {"manifest_path": "a/package.json", "reason": "manifest_invalid_json"},
        ])
    );
}

#[cfg(unix)]
#[test]
fn a_symlinked_manifest_is_skipped_and_never_read() {
    let (_dir, root) = project();
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("package.json"), manifest("1.0.0")).unwrap();
    fs::create_dir_all(root.join("linked")).unwrap();
    std::os::unix::fs::symlink(
        outside.path().join("package.json"),
        root.join("linked/package.json"),
    )
    .unwrap();
    let result = plan_result(&root);
    assert_eq!(result["proposals"].as_array().unwrap().len(), 1);
    assert_eq!(
        result["skipped"],
        json!([{"manifest_path": "linked/package.json", "reason": "manifest_is_symlink"}])
    );
}

#[test]
fn proposals_beyond_the_limit_are_reported_skipped() {
    let (_dir, root) = project();
    for index in 0..3 {
        write_manifest(&root, &format!("p{index}"), &manifest("1.0.0"));
    }
    let mut request = plan_request(&root);
    request["max_proposals"] = json!(2);
    let result = call(&request)["result"].clone();
    assert_eq!(result["proposals"].as_array().unwrap().len(), 2);
    assert_eq!(result["skipped"].as_array().unwrap().len(), 2);
    assert_eq!(result["skipped"][0]["reason"], "too_many_manifests");
}

#[test]
fn a_diff_over_the_cap_is_refused() {
    let (_dir, root) = project();
    let mut request = plan_request(&root);
    request["max_diff_bytes"] = json!(10);
    let result = call(&request)["result"].clone();
    assert_eq!(result["proposals"], json!([]));
    assert_eq!(result["skipped"][0]["reason"], "diff_too_large");
}

#[test]
fn more_manifests_than_the_scan_limit_flag_truncated() {
    let (_dir, root) = project();
    for index in 0..=MAX_MANIFESTS {
        write_manifest(&root, &format!("p{index:03}"), "{}");
    }
    assert_eq!(plan_result(&root)["truncated"], true);
}

#[test]
fn the_scan_limit_drops_the_deepest_manifests_not_the_root() {
    let (_dir, root) = project();
    for index in 0..=MAX_MANIFESTS {
        write_manifest(&root, &format!("p{index:03}/nested"), "{}");
    }
    let result = plan_result(&root);
    assert_eq!(result["truncated"], true);
    assert_eq!(result["proposals"][0]["manifest_path"], "package.json");
}

#[cfg(unix)]
#[test]
fn apply_writes_the_reviewed_edit_and_lists_lockfiles() {
    let (_dir, root) = project();
    fs::write(root.join("package-lock.json"), "{}").unwrap();
    let proposal = plan_result(&root)["proposals"][0].clone();
    let response = call(&apply_request(&root, &proposal));
    assert_eq!(response["ok"], true, "{response}");
    assert_eq!(response["result"]["status"], "applied");
    assert_eq!(
        response["result"]["lockfiles"],
        json!(["package-lock.json"])
    );
    assert_eq!(
        fs::read_to_string(root.join("package.json")).unwrap(),
        manifest("^1.3.0")
    );
}

#[cfg(unix)]
#[test]
fn apply_goes_stale_when_the_manifest_changed_and_keeps_the_users_edit() {
    let (_dir, root) = project();
    let proposal = plan_result(&root)["proposals"][0].clone();
    let user = manifest("^1.0.0").replace("app", "renamed");
    fs::write(root.join("package.json"), &user).unwrap();
    let response = call(&apply_request(&root, &proposal));
    assert_eq!(response["result"]["status"], "stale");
    assert_eq!(response["result"]["reason"], "manifest_changed");
    assert_eq!(fs::read_to_string(root.join("package.json")).unwrap(), user);
}

#[cfg(unix)]
#[test]
fn apply_refuses_edits_that_do_not_produce_the_reviewed_hash() {
    let (_dir, root) = project();
    let mut proposal = plan_result(&root)["proposals"][0].clone();
    proposal["edits"][0]["to_spec"] = json!("^9.9.9");
    let response = call(&apply_request(&root, &proposal));
    assert_eq!(response["result"]["reason"], "proposal_mismatch");
    assert_eq!(
        fs::read_to_string(root.join("package.json")).unwrap(),
        manifest("^1.0.0")
    );
}

#[test]
fn bad_requests_report_a_code() {
    let (_dir, root) = project();
    assert!(run_command(b"{\"op\": \"nope\"}").is_err());
    assert!(run_command(b"{").is_err());
    let relative =
        call(&json!({"op": "plan", "root": "rel", "package": "x", "fix_version": "1.0.0"}));
    assert_eq!(relative["error"], "workspace_fix_root_not_absolute");
    let gone = root.join("gone");
    let missing =
        call(&json!({"op": "plan", "root": gone, "package": "x", "fix_version": "1.0.0"}));
    assert_eq!(missing["error"], "workspace_fix_root_missing");
    let proposal = plan_result(&root)["proposals"][0].clone();
    let mut request = apply_request(&root, &proposal);
    request["manifest_path"] = json!("../package.json");
    assert_eq!(call(&request)["error"], "manifest_path_invalid");
}
