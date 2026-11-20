//! A hook's working directory outside the profile directory on Windows: a
//! checkout on a second drive. Windows has no uid, so the owner SID decides.
//! A directory the caller owns is trusted when the harness names it; an
//! agent-chosen exec workdir, system directories and missing paths stay
//! refused.

use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use tempfile::TempDir;

use super::{
    evaluate_directory_trust_request, DirectoryTrustRequestV1, DIRECTORY_TRUST_REQUEST_SCHEMA,
};
use crate::guard_paths::python_realpath_lax;

fn text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

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
        "request_id": "req-hook-workspace-outside-profile",
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

/// A directory under the crate's own sources, which the account running the
/// tests created. `None` when the sources sit under the temporary directory,
/// which the plain workspace rule already trusts, or cannot be written to.
fn outside_checkout() -> Option<(TempDir, PathBuf)> {
    let sources = python_realpath_lax(Path::new(env!("CARGO_MANIFEST_DIR"))).ok()?;
    let temp = python_realpath_lax(&std::env::temp_dir()).ok()?;
    if sources.starts_with(&temp) {
        eprintln!("skipped: the crate sources sit under the temporary directory");
        return None;
    }
    match tempfile::Builder::new()
        .prefix(".hook-workspace-probe-")
        .tempdir_in(&sources)
    {
        Ok(directory) => {
            // The administrators SID can own a newly created temporary
            // directory; explicitly give the fixture to the process user.
            let owned = directory.path().join("owned");
            assert!(
                guard_runtime_windows_process::create_owner_only_directory(&owned)
                    .expect("create caller-owned fixture"),
                "fixture must be newly created"
            );
            Some((directory, owned))
        }
        Err(error) => {
            eprintln!("skipped: the crate sources are not writable: {error}");
            None
        }
    }
}

#[test]
fn a_checkout_the_caller_owns_outside_the_profile_is_the_hooks_workspace() {
    let home = TempDir::new().expect("a temporary home");
    let Some((_fixture, checkout)) = outside_checkout() else {
        return;
    };
    // A folder created under an elevated token is owned by Administrators,
    // which the exact-owner check refuses; give the subfolder to the caller.
    assert!(
        guard_runtime_windows_process::create_owner_only_directory(&checkout.join("src"))
            .expect("a caller-owned subdirectory"),
        "the subdirectory must be newly created"
    );
    let values = [
        text(checkout.as_path()),
        text(&checkout.as_path().join("src")),
    ];
    let results = settle(home.path(), &values);
    assert_eq!(results.len(), 6);
    for (index, value) in values.iter().enumerate() {
        let expected = text(&python_realpath_lax(Path::new(value)).expect("it resolves"));
        let [payload, workdir, plain] = &results[index * 3..index * 3 + 3] else {
            unreachable!("three verdicts per value");
        };
        assert_eq!(payload["trusted"], json!(true), "{value}: {payload}");
        assert_eq!(payload["path"], json!(expected));
        for verdict in [workdir, plain] {
            assert_eq!(verdict["trusted"], json!(false), "{value}: {verdict}");
            assert_eq!(verdict["reason"], json!("unexpected_root"));
        }
    }
}

#[test]
fn system_directories_missing_paths_and_files_stay_refused() {
    let home = TempDir::new().expect("a temporary home");
    let Some((_fixture, checkout)) = outside_checkout() else {
        return;
    };
    let file = checkout.as_path().join("notes.txt");
    std::fs::write(&file, "x").expect("a file");
    let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_owned());
    let program_data =
        std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".to_owned());
    let users_root = std::env::var_os("USERPROFILE")
        .and_then(|profile| PathBuf::from(profile).parent().map(text))
        .unwrap_or_else(|| r"C:\Users".to_owned());
    let values = vec![
        r"C:\".to_owned(),
        program_data,
        users_root,
        system_root.clone(),
        format!(r"{system_root}\System32"),
        text(&checkout.as_path().join("missing")),
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
