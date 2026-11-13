//! A hook's working directory outside the home: a checkout on an external
//! volume or a second disk. The harness names it, so a directory the caller
//! owns is trusted; system directories and missing paths stay refused.

use serde_json::{json, Value};
use std::path::Path;
use tempfile::TempDir;

use super::{
    evaluate_directory_trust_request, DirectoryTrustRequestV1, DIRECTORY_TRUST_REQUEST_SCHEMA,
};
use crate::guard_paths::python_realpath_lax;

fn text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// Settles each value under both hook rules and under the plain workspace
/// parameter, against a home that does not contain any of them.
fn settle(home: &Path, values: &[String]) -> Vec<Value> {
    let guard_home = home.join(".hol-guard");
    std::fs::create_dir_all(&guard_home).expect("a guard home");
    let candidates: Vec<Value> = values
        .iter()
        .flat_map(|value| {
            [
                json!({"parameter": "workspace-payload", "rule": "hook-workspace", "value": value}),
                json!({"parameter": "exec-workdir", "rule": "exec-workdir", "value": value}),
                json!({"parameter": "workspace", "value": value}),
            ]
        })
        .collect();
    let request: DirectoryTrustRequestV1 = serde_json::from_value(json!({
        "schema": DIRECTORY_TRUST_REQUEST_SCHEMA,
        "request_id": "req-hook-workspace-outside-home",
        "guard_home": text(&guard_home),
        "home_dir": text(home),
        "temp_dir": text(&std::env::temp_dir()),
        "candidates": candidates,
    }))
    .expect("the request parses");
    let body = evaluate_directory_trust_request(&request).expect("the operation answers");
    let body: Value = serde_json::from_slice(&body).expect("the answer is JSON");
    body["results"].as_array().expect("results").clone()
}

/// A directory outside both the home and every temporary root: the crate's
/// own source tree, which the user running the tests owns.
fn outside_checkout() -> TempDir {
    tempfile::Builder::new()
        .prefix(".hook-workspace-probe-")
        .tempdir_in(env!("CARGO_MANIFEST_DIR"))
        .expect("a directory beside the crate sources")
}

#[test]
fn a_checkout_the_caller_owns_outside_the_home_is_the_hooks_workspace() {
    let home = TempDir::new().expect("a temporary home");
    let checkout = outside_checkout();
    std::fs::create_dir(checkout.path().join("src")).expect("a subdirectory");
    let values = [text(checkout.path()), text(&checkout.path().join("src"))];
    let results = settle(home.path(), &values);
    assert_eq!(results.len(), 6);
    for (index, value) in values.iter().enumerate() {
        let expected = text(&python_realpath_lax(Path::new(value)).expect("it resolves"));
        let [payload, workdir, plain] = &results[index * 3..index * 3 + 3] else {
            unreachable!("three verdicts per value");
        };
        assert_eq!(payload["trusted"], json!(true), "{value}");
        assert_eq!(payload["path"], json!(expected));
        assert_eq!(workdir["trusted"], json!(true), "{value}");
        assert_eq!(workdir["path"], json!(expected));
        // A directory a dashboard or CLI request names keeps the home's
        // roots: only the harness's own working directory is widened.
        assert_eq!(plain["trusted"], json!(false), "{value}");
        assert_eq!(plain["reason"], json!("unexpected_root"));
    }
}

#[test]
fn system_directories_missing_paths_and_files_stay_refused() {
    let home = TempDir::new().expect("a temporary home");
    let checkout = outside_checkout();
    let file = checkout.path().join("notes.txt");
    std::fs::write(&file, "x").expect("a file");
    let mut values = vec![
        "/".to_owned(),
        text(&checkout.path().join("missing")),
        text(&file),
    ];
    // Under root every system directory is the caller's own.
    if !nix::unistd::getuid().is_root() {
        values.extend(["/usr/lib".to_owned(), "/etc".to_owned()]);
    }
    let results = settle(home.path(), &values);
    assert_eq!(results.len(), values.len() * 3);
    for (index, result) in results.iter().enumerate() {
        let value = &values[index / 3];
        assert_eq!(result["trusted"], json!(false), "{value}: {result}");
        assert!(result.get("path").is_none(), "{value}");
    }
}
