//! Parity vectors recorded from the retired Python `_safe_relative` of the
//! contained workspace-write path: each case carries the accept or reject
//! decision the Python produced over a fixed workspace layout.

use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use serde_json::Value;

use super::_semantic_safe_relative;

const VECTORS: &str = include_str!("../tests/fixtures/workspace_write_safe_relative_vectors.json");

/// Names the Rust side rejects although the Python accepted them: the shared
/// protected-name and secret-path lists, the non-directory parent and the
/// case-folding alias check (a case-insensitive filesystem) are stricter,
/// never looser.
const STRICTER: &[&str] = &[
    "credentials.json",
    "config/secrets.json",
    "id_rsa",
    "link_file/x",
    "Src/A.PY",
];

fn build_layout(root: &Path, layout: &Value) {
    for dir in layout["dirs"].as_array().expect("dirs") {
        fs::create_dir_all(root.join(dir.as_str().expect("dir"))).expect("dir");
    }
    for file in layout["files"].as_array().expect("files") {
        let path = root.join(file.as_str().expect("file"));
        fs::create_dir_all(path.parent().expect("parent")).expect("parent");
        fs::write(&path, b"x").expect("file");
    }
    for (link, original) in layout["hardlinks"].as_object().expect("hardlinks") {
        let original = root.join(original.as_str().expect("original"));
        fs::write(&original, b"x").expect("original");
        fs::hard_link(&original, root.join(link)).expect("hardlink");
    }
    for (link, target) in layout["symlinks"].as_object().expect("symlinks") {
        symlink(root.join(target.as_str().expect("target")), root.join(link)).expect("symlink");
    }
}

#[test]
fn safe_relative_matches_the_retired_python() {
    let vectors: Value = serde_json::from_str(VECTORS).expect("vectors");
    let root: PathBuf = std::env::temp_dir().join(format!("hg-safe-rel-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).expect("root");
    let workspace = fs::canonicalize(&root).expect("workspace");
    build_layout(&workspace, &vectors["layout"]);
    let cases = vectors["cases"].as_array().expect("cases");
    let mut mismatches = Vec::new();
    for case in cases {
        let value = case["value"].as_str().expect("value");
        let must_exist = case["must_exist"].as_bool().expect("must_exist");
        let expected = case["ok"].as_bool().expect("ok");
        let actual = _semantic_safe_relative(&workspace, value, must_exist);
        if actual.is_ok() && !expected {
            mismatches.push(format!(
                "{value:?} must_exist={must_exist}: python rejected, rust accepted"
            ));
        } else if actual.is_err() && expected && !STRICTER.contains(&value) {
            mismatches.push(format!(
                "{value:?} must_exist={must_exist}: python accepted, rust={actual:?}"
            ));
        }
    }
    let _ = fs::remove_dir_all(&root);
    assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
}
