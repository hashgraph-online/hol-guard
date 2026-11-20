//! Shipped audit stamps leave a blank or truncated manifest unchanged.

use std::fs;

use super::super::{ShimContext, ShimFacts};
use super::record_package_shim_audit_result;

fn facts() -> ShimFacts {
    ShimFacts {
        environ: std::collections::BTreeMap::new(),
        home: "/Users/home".to_owned(),
        cwd: "/".to_owned(),
        executable: "/usr/bin/python3".to_owned(),
        frozen: false,
        frozen_cli: String::new(),
        trusted_frozen_cli_paths: Vec::new(),
        python_version: (3, 12),
        import_root: "/Users/src".to_owned(),
        argv0: None,
        windows: false,
        sqlite_connect_timeout_seconds: 30.0,
        now: "2026-01-01T00:00:00+00:00".to_owned(),
        shim_dir_transient: None,
    }
}

fn scratch(label: &str) -> std::path::PathBuf {
    let stamp = crate::unique_nanos::unique_nanos();
    let root = fs::canonicalize(std::env::temp_dir())
        .expect("temp dir")
        .join(format!("hol-guard-shim-audit-{label}-{stamp}"));
    fs::create_dir_all(&root).expect("scratch");
    root
}

fn seed(label: &str, original: &str) -> (std::path::PathBuf, std::path::PathBuf, ShimContext) {
    let root = scratch(label);
    let home = root.join("guard-home");
    let manifest_dir = home.join("package-shims");
    fs::create_dir_all(&manifest_dir).expect("dir");
    let manifest = manifest_dir.join("manifest.json");
    fs::write(&manifest, original).expect("seed");
    let context = ShimContext::new(home.to_str().expect("utf8"), None, None, facts());
    (root, manifest, context)
}

#[test]
fn an_existing_blank_manifest_is_not_replaced_with_a_stamp() {
    for original in ["", " \n\t "] {
        let (root, manifest, context) = seed("blank", original);
        let error = record_package_shim_audit_result(&context, None).expect_err("blank");
        assert!(error.contains("not strict JSON"), "{error}");
        assert_eq!(fs::read_to_string(&manifest).expect("unchanged"), original);
        fs::remove_dir_all(&root).expect("cleanup");
    }
}

#[test]
fn a_truncated_nonfinite_manifest_is_left_unchanged() {
    let original = "{\"enabled\": true, \"score\": NaN";
    let (root, manifest, context) = seed("truncated", original);
    let error = record_package_shim_audit_result(&context, None).expect_err("truncated");
    assert!(error.contains("not strict JSON"), "{error}");
    assert_eq!(fs::read_to_string(&manifest).expect("unchanged"), original);
    fs::remove_dir_all(&root).expect("cleanup");
}
