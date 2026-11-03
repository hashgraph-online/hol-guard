use serde_json::json;

use super::{dispatch, parent_directory, version_ordinal};

const PIPX: &str = "/home/u/.local/pipx/venvs/hol-guard/lib/python3.14/site-packages/codex_plugin_scanner/guard/contracts/catalog.json";
const UV: &str = "/home/u/.local/share/uv/tools/hol-guard/lib/python3.12/site-packages/codex_plugin_scanner/guard/contracts/catalog.json";

fn attribution(path: &str, frozen: bool) -> serde_json::Value {
    dispatch(&json!({"resource_path": path, "frozen": frozen})).expect("attribution")
}

#[test]
fn the_install_kind_comes_from_the_path_shape() {
    assert_eq!(attribution(PIPX, false)["install_kind"], json!("pipx"));
    assert_eq!(attribution(UV, false)["install_kind"], json!("uv-tool"));
    assert_eq!(
        attribution("C:\\Python\\Lib\\site-packages\\guard\\c.json", false)["install_kind"],
        json!("site-packages")
    );
    assert_eq!(
        attribution("/repo/src/codex_plugin_scanner/guard/c.json", false)["install_kind"],
        json!("source-checkout")
    );
    assert_eq!(
        attribution("/opt/c.json", false)["install_kind"],
        json!("unknown")
    );
    let bundle = "/Applications/x/org.hol.guard.desktop/core/_internal/catalog.json";
    assert_eq!(
        attribution(bundle, true)["install_kind"],
        json!("desktop-bundle")
    );
    assert_eq!(
        attribution(PIPX, true)["install_kind"],
        json!("frozen-bundle")
    );
}

#[test]
fn two_installs_get_different_roots_and_one_install_keeps_its_root() {
    let pipx = attribution(PIPX, false)["resource_root_digest"].clone();
    assert_ne!(pipx, attribution(UV, false)["resource_root_digest"]);
    assert_eq!(pipx, attribution(PIPX, false)["resource_root_digest"]);
    assert_eq!(pipx.as_str().map(str::len), Some(64));
    // Only the directory counts, not the file name inside it.
    let sibling = PIPX.replace("catalog.json", "other.json");
    assert_eq!(pipx, attribution(&sibling, false)["resource_root_digest"]);
}

#[cfg(unix)]
#[test]
fn the_root_is_read_as_python_reads_a_parent() {
    assert_eq!(parent_directory("/a//b/./c.json"), "/a/b");
    assert_eq!(parent_directory("/a/b/.."), "/a/b");
    assert_eq!(parent_directory("c.json"), ".");
    assert_eq!(parent_directory(""), ".");
    assert_eq!(parent_directory("/"), "/");
}

#[test]
fn versions_order_by_their_leading_numbers() {
    assert_eq!(version_ordinal("3.46.0"), vec![3, 46, 0]);
    assert_eq!(version_ordinal("3.47.0a2"), vec![3, 47, 0]);
    assert_eq!(version_ordinal("3.8.0"), vec![3, 8, 0]);
    assert!(version_ordinal("").is_empty());
    assert!(version_ordinal("not-a-version").is_empty());
}

#[test]
fn only_an_older_writer_is_a_downgrade() {
    let downgrade = |writer: &str, previous: &str| {
        dispatch(&json!({"writer_version": writer, "previous_version": previous}))
            .expect("downgrade")["downgrade"]
            .clone()
    };
    assert_eq!(downgrade("3.36.0", "3.46.0"), json!(true));
    assert_eq!(downgrade("3.47.0a2", "3.46.0"), json!(false));
    assert_eq!(downgrade("3.47.0", "3.47.0a2"), json!(false));
    assert_eq!(downgrade("3.10.0", "3.9.0"), json!(false));
}

#[test]
fn a_mixed_or_partial_shape_is_refused() {
    assert!(dispatch(&json!({})).is_err());
    assert!(dispatch(&json!({"resource_path": PIPX})).is_err());
    assert!(dispatch(&json!({"resource_path": PIPX, "frozen": "no"})).is_err());
    assert!(dispatch(&json!({"resource_path": PIPX, "writer_version": "3.1"})).is_err());
    assert!(dispatch(&json!({"writer_version": "3.1", "previous_version": 3})).is_err());
    assert!(dispatch(&json!({"resource_path": PIPX, "frozen": true, "x": 1})).is_err());
}
