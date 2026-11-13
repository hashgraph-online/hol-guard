//! A hook's working directory outside the home: a checkout on an external
//! volume or a second disk. The harness names it, so a directory the caller
//! owns is trusted; an agent-chosen exec workdir, system directories and
//! missing paths stay refused.

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

const TEMPORARY_ROOTS: &[&str] = &[
    "/tmp",
    "/var/tmp",
    "/private/tmp",
    "/private/var/tmp",
    "/var/folders",
    "/private/var/folders",
];

/// A directory outside both the home and every temporary root: the crate's
/// own source tree, which the user running the tests owns. `None` when the
/// sources sit under a temporary root, which the plain workspace rule
/// already trusts, or cannot be written to, or when the tests run as root,
/// where ownership proves nothing and the fallback is off.
fn outside_checkout() -> Option<TempDir> {
    let sources = python_realpath_lax(Path::new(env!("CARGO_MANIFEST_DIR"))).ok()?;
    let temp = python_realpath_lax(&std::env::temp_dir()).ok()?;
    let under_temporary_root =
        sources.starts_with(&temp) || TEMPORARY_ROOTS.iter().any(|root| sources.starts_with(root));
    if under_temporary_root || nix::unistd::geteuid().is_root() {
        eprintln!(
            "skipped: the crate sources are not an owned directory outside the temporary roots"
        );
        return None;
    }
    match tempfile::Builder::new()
        .prefix(".hook-workspace-probe-")
        .tempdir_in(&sources)
    {
        Ok(directory) => Some(directory),
        Err(error) => {
            eprintln!("skipped: the crate sources are not writable: {error}");
            None
        }
    }
}

#[test]
fn a_checkout_the_caller_owns_outside_the_home_is_the_hooks_workspace() {
    let home = TempDir::new().expect("a temporary home");
    let Some(checkout) = outside_checkout() else {
        return;
    };
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
        // The directory the model asked a command to run in, and the one a
        // dashboard or CLI request names, keep the home's roots: only the
        // harness's own working directory is widened.
        for verdict in [workdir, plain] {
            assert_eq!(verdict["trusted"], json!(false), "{value}: {verdict}");
            assert_eq!(verdict["reason"], json!("unexpected_root"));
        }
    }
}

#[test]
fn system_directories_missing_paths_and_files_stay_refused() {
    let home = TempDir::new().expect("a temporary home");
    let Some(checkout) = outside_checkout() else {
        return;
    };
    let file = checkout.path().join("notes.txt");
    std::fs::write(&file, "x").expect("a file");
    let values = vec![
        "/".to_owned(),
        "/usr/lib".to_owned(),
        "/etc".to_owned(),
        text(&checkout.path().join("missing")),
        text(&file),
    ];
    let results = settle(home.path(), &values);
    assert_eq!(results.len(), values.len() * 3);
    for (index, result) in results.iter().enumerate() {
        let value = &values[index / 3];
        assert_eq!(result["trusted"], json!(false), "{value}: {result}");
        assert!(result.get("path").is_none(), "{value}");
    }
}
