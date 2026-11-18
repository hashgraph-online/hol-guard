//! One install at one source root, seen by two processes: a long-lived
//! one that cached its identity before an in-place upgrade, and the daemon
//! the upgrade started.

use std::path::Path;

use serde_json::{json, Map, Value};

use super::{runtime_matches_current, COMPATIBILITY_VERSION};
use crate::runtime_fingerprint::installed_fingerprint;

fn install(body: &str) -> tempfile::TempDir {
    let root = tempfile::tempdir().expect("source root");
    let package = root.path().join("codex_plugin_scanner");
    std::fs::create_dir_all(&package).expect("package");
    std::fs::write(package.join("__init__.py"), body).expect("module");
    root
}

fn identity(root: &Path, version: &str, fingerprint: &str) -> Map<String, Value> {
    json!({
        "compatibility_version": COMPATIBILITY_VERSION,
        "package_version": version,
        "source_root": root.to_str().expect("utf-8 root"),
        "runtime_fingerprint": fingerprint,
    })
    .as_object()
    .expect("object")
    .clone()
}

#[test]
fn a_caller_from_before_an_upgrade_keeps_the_daemon_running_the_installed_tree() {
    let root = install("VERSION = '1.1.0'\n");
    let upgraded = installed_fingerprint(root.path(), "1.1.0");
    let daemon = identity(root.path(), "1.1.0", &upgraded);
    let stale_caller = identity(root.path(), "1.0.0", &"a".repeat(64));
    assert!(runtime_matches_current(&stale_caller, &daemon));
    let same_version_caller = identity(root.path(), "1.1.0", &"b".repeat(64));
    assert!(runtime_matches_current(&same_version_caller, &daemon));
}

#[test]
fn a_daemon_from_before_an_upgrade_is_still_replaced() {
    let root = install("VERSION = '1.0.0'\n");
    let old = installed_fingerprint(root.path(), "1.0.0");
    std::fs::write(
        root.path().join("codex_plugin_scanner/__init__.py"),
        "VERSION = '1.1.0'\n",
    )
    .expect("upgrade");
    let current = identity(
        root.path(),
        "1.1.0",
        &installed_fingerprint(root.path(), "1.1.0"),
    );
    assert!(!runtime_matches_current(
        &current,
        &identity(root.path(), "1.0.0", &old)
    ));
    // Same version, edited tree: the daemon's identity is no longer the one on disk.
    let edited = identity(
        root.path(),
        "1.1.0",
        &installed_fingerprint(root.path(), "1.1.0"),
    );
    std::fs::write(
        root.path().join("codex_plugin_scanner/__init__.py"),
        "VERSION = '1.1.0' # edit\n",
    )
    .expect("edit");
    let after_edit = identity(
        root.path(),
        "1.1.0",
        &installed_fingerprint(root.path(), "1.1.0"),
    );
    assert!(!runtime_matches_current(&after_edit, &edited));
}

#[test]
fn a_daemon_without_a_readable_install_is_not_kept_by_the_tree_check() {
    let root = install("VERSION = '1.0.0'\n");
    let current = identity(root.path(), "1.0.0", &"c".repeat(64));
    let mut daemon = identity(root.path(), "1.0.0", &"d".repeat(64));
    assert!(!runtime_matches_current(&current, &daemon));
    daemon.remove("package_version");
    let mut caller = current.clone();
    caller.remove("package_version");
    assert!(!runtime_matches_current(&caller, &daemon));
}
