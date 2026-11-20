//! `update_refresh` when the runtime reads the OpenCode install record itself.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use super::super::dispatch;
use super::update_family::{plugin, plugin_paths};
use super::Home;

fn record(home: &Home, active: bool, workspace: Option<&str>, manifest: &str) {
    let connection = rusqlite::Connection::open(home.guard().join("guard.db")).unwrap();
    connection
        .execute_batch(
            "create table if not exists managed_installs (
               harness text primary key, active integer not null, workspace text,
               manifest_json text not null, updated_at text not null);",
        )
        .unwrap();
    connection
        .execute(
            "insert into managed_installs values ('opencode', ?1, ?2, ?3, '2026-03-10T10:00:00+00:00')",
            rusqlite::params![active, workspace, manifest],
        )
        .unwrap();
}

fn stored_refresh(home: &Home) -> Value {
    home.ask(
        "opencode",
        "update_refresh",
        json!({"plugin": plugin(), "store_home": home.guard()}),
    )
}

fn workspace_plugin_paths(home: &Home, workspace: &Path) -> Vec<PathBuf> {
    let mut request = json!({
        "harness": "opencode",
        "op": "plugin_refresh",
        "context": home.context(json!({"PATH": ""})),
        "plugin": plugin(),
    });
    request["context"]["workspace"] = json!(workspace);
    dispatch(&request).unwrap()["paths"]
        .as_array()
        .unwrap()
        .iter()
        .map(|path| PathBuf::from(path.as_str().unwrap()))
        .collect()
}

#[test]
fn opencode_update_from_the_store_has_nothing_to_say_without_an_active_install() {
    let home = Home::new();
    assert_eq!(stored_refresh(&home)["note"], Value::Null);
    record(&home, false, None, "{}");
    assert_eq!(stored_refresh(&home)["note"], Value::Null);
    for path in plugin_paths(&home) {
        assert!(!path.exists(), "{}", path.display());
    }
}

#[test]
fn opencode_update_from_the_store_ignores_an_unreadable_record() {
    let home = Home::new();
    record(&home, true, None, "{oops");
    assert_eq!(stored_refresh(&home)["note"], Value::Null);
    for path in plugin_paths(&home) {
        assert!(!path.exists(), "{}", path.display());
    }
}

#[test]
fn opencode_update_from_the_store_refreshes_the_global_plugin_without_a_workspace() {
    let home = Home::new();
    record(&home, true, Some("   "), "{}");
    let answer = stored_refresh(&home);
    assert!(answer["note"]
        .as_str()
        .unwrap()
        .starts_with("Refreshed the OpenCode pretool plugin"));
    for path in plugin_paths(&home) {
        assert!(path.is_file(), "{}", path.display());
    }
}

#[test]
fn opencode_update_from_the_store_works_in_the_installs_own_workspace() {
    let home = Home::new();
    let workspace = home.home().join("project");
    fs::create_dir_all(&workspace).unwrap();
    record(&home, true, Some("~/project"), "{}");
    let answer = stored_refresh(&home);
    assert!(answer["note"]
        .as_str()
        .unwrap()
        .starts_with("Refreshed the OpenCode pretool plugin"));
    for path in workspace_plugin_paths(&home, &workspace) {
        assert!(path.is_file(), "{}", path.display());
    }
}

#[test]
fn opencode_update_from_the_store_names_a_workspace_it_cannot_resolve() {
    let home = Home::new();
    record(&home, true, Some("~someone/project"), "{}");
    assert_eq!(
        stored_refresh(&home)["note"],
        "Could not inspect OpenCode pretool plugin during update: \
         managed install workspace path is invalid"
    );
}
