use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::super::codex_incident_read::{bounded_regular_bytes, read_hook_files};
use super::super::Ctx;
use super::{ascii_json, report, shape_counts};
use crate::pyjson::{self, PyVal};

fn root() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(dir.path()).unwrap();
    (dir, root)
}

fn ctx(root: &Path, workspace: Option<&Path>) -> Ctx {
    let mut fields = json!({
        "home": root.join("home"),
        "guard_home": root.join("guard"),
        "cwd": root,
        "user_home": root.join("home"),
        "env": {},
        "caller": {"version": "1.2.3"},
    });
    if let Some(workspace) = workspace {
        fields["workspace"] = json!(workspace);
    }
    Ctx::parse(Some(&fields)).unwrap()
}

fn codex_dir(root: &Path) -> PathBuf {
    let codex = root.join("home").join(".codex");
    fs::create_dir_all(&codex).unwrap();
    codex
}

fn hooks(text: &str) -> PyVal {
    pyjson::parse(text).unwrap()
}

#[test]
fn missing_files_read_as_missing() {
    let (_dir, root) = root();
    let codex = codex_dir(&root);
    let read = read_hook_files(&codex.join("config.toml"), &codex.join("hooks.json"));
    assert_eq!(read.status.get("config_status"), Some(&json!("missing")));
    assert_eq!(read.status.get("hooks_enabled"), Some(&json!(true)));
    assert_eq!(read.status.get("hooks_status"), Some(&json!("missing")));
    assert_eq!(read.hooks, PyVal::Null);
}

#[test]
fn oversized_config_is_refused_before_it_is_read() {
    let (_dir, root) = root();
    let config = codex_dir(&root).join("config.toml");
    fs::write(&config, vec![b'#'; 1024 * 1024 + 1]).unwrap();
    assert_eq!(bounded_regular_bytes(&config), (None, "too_large"));
}

#[cfg(unix)]
#[test]
fn linked_config_is_an_unsafe_file_type() {
    let (_dir, root) = root();
    let codex = codex_dir(&root);
    fs::write(root.join("real.toml"), "").unwrap();
    std::os::unix::fs::symlink(root.join("real.toml"), codex.join("config.toml")).unwrap();
    assert_eq!(
        bounded_regular_bytes(&codex.join("config.toml")),
        (None, "unsafe_file_type")
    );
}

#[test]
fn malformed_toml_reports_malformed_without_hooks() {
    let (_dir, root) = root();
    let codex = codex_dir(&root);
    fs::write(codex.join("config.toml"), "[[[ not toml").unwrap();
    let read = read_hook_files(&codex.join("config.toml"), &codex.join("hooks.json"));
    assert_eq!(read.status.get("config_status"), Some(&json!("malformed")));
    assert_eq!(read.status.get("hooks_enabled"), Some(&Value::Null));
    assert!(!read.status.contains_key("hooks_status"));
}

#[test]
fn disabled_feature_and_toml_hooks_table() {
    let (_dir, root) = root();
    let codex = codex_dir(&root);
    fs::write(
        codex.join("config.toml"),
        "[features]\nhooks = false\n\n[[hooks.PreToolUse]]\nmatcher = \"Bash\"\n[[hooks.PreToolUse.hooks]]\ntype = \"command\"\ncommand = \"secret-command\"\n",
    )
    .unwrap();
    let read = read_hook_files(&codex.join("config.toml"), &codex.join("hooks.json"));
    assert_eq!(read.status.get("hooks_enabled"), Some(&json!(false)));
    assert!(!read.status.contains_key("hooks_status"));
    let (groups, handlers) = shape_counts(&read.hooks);
    assert_eq!(groups["PreToolUse"], json!(1));
    assert_eq!(handlers["PreToolUse"], json!(1));
    assert_eq!(groups["PostToolUse"], json!(0));
}

#[test]
fn legacy_hooks_json_is_read_when_toml_has_no_hooks() {
    let (_dir, root) = root();
    let codex = codex_dir(&root);
    fs::write(
        codex.join("hooks.json"),
        r#"{"hooks": {"PostToolUse": [{"hooks": [{}, {}]}]}}"#,
    )
    .unwrap();
    let read = read_hook_files(&codex.join("config.toml"), &codex.join("hooks.json"));
    assert_eq!(read.status.get("config_status"), Some(&json!("missing")));
    assert_eq!(read.status.get("hooks_status"), Some(&json!("read")));
    let (groups, handlers) = shape_counts(&read.hooks);
    assert_eq!(groups["PostToolUse"], json!(1));
    assert_eq!(handlers["PostToolUse"], json!(2));
}

#[test]
fn hooks_json_that_is_not_an_object_is_malformed() {
    let (_dir, root) = root();
    let codex = codex_dir(&root);
    fs::write(codex.join("hooks.json"), "[1, 2]").unwrap();
    let read = read_hook_files(&codex.join("config.toml"), &codex.join("hooks.json"));
    assert_eq!(read.status.get("hooks_status"), Some(&json!("malformed")));
}

#[test]
fn malformed_groups_and_handlers_count_as_null() {
    let (groups, handlers) = shape_counts(&hooks(
        r#"{"PreToolUse": [1], "PermissionRequest": [{"hooks": [1]}], "UserPromptSubmit": {}, "PostToolUse": [{"hooks": []}]}"#,
    ));
    assert_eq!(groups["PreToolUse"], Value::Null);
    assert_eq!(handlers["PreToolUse"], Value::Null);
    assert_eq!(groups["PermissionRequest"], json!(1));
    assert_eq!(handlers["PermissionRequest"], Value::Null);
    assert_eq!(groups["UserPromptSubmit"], Value::Null);
    assert_eq!(handlers["PostToolUse"], json!(0));
    assert_eq!(shape_counts(&PyVal::Null), (Value::Null, Value::Null));
}

#[test]
fn report_never_echoes_commands_and_reports_probe_failure() {
    let (_dir, root) = root();
    let codex = codex_dir(&root);
    fs::write(
        codex.join("hooks.json"),
        r#"{"hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": "private-marker-cmd run"}]}]}}"#,
    )
    .unwrap();
    // No `launch` and no `spec`: the integrity probe cannot run.
    let report = report(&ctx(&root, None), &Map::new(), "2026-01-01T00:00:00+00:00").unwrap();
    let text = ascii_json(&report);
    assert!(!text.contains("private-marker-cmd"));
    let configured = &report["configured"];
    assert_eq!(configured["manifest_integrity"], json!("unverified"));
    assert_eq!(
        configured["reason_code"],
        json!("codex_integrity_probe_failed")
    );
    assert_eq!(
        configured["integrity_probe_exception_class"],
        json!("RuntimeError")
    );
    assert_eq!(configured["managed_events"]["PreToolUse"], json!(false));
    assert_eq!(configured["event_group_counts"]["PreToolUse"], json!(1));
    assert_eq!(report["schema"], json!("hol-guard.codex-incident.v1"));
    assert_eq!(report["cli_package_version"], json!("1.2.3"));
    assert_eq!(report["workspace"], json!({"selected": false}));
    assert_eq!(
        report["daemon"]["discovery_authentication"],
        json!("unverified")
    );
    assert_eq!(report["daemon"]["liveness"], json!("unknown"));
    assert_eq!(report["timeline"]["scope"], json!("recent_bounded_journal"));
}

#[test]
fn unreadable_hooks_skip_the_integrity_probe() {
    let (_dir, root) = root();
    let codex = codex_dir(&root);
    fs::write(codex.join("hooks.json"), "{not json").unwrap();
    let report = report(&ctx(&root, None), &Map::new(), "now").unwrap();
    assert_eq!(
        report["configured"]["reason_code"],
        json!("codex_hooks_unavailable")
    );
    assert_eq!(
        report["configured"]["integrity_probe_exception_class"],
        Value::Null
    );
}

#[test]
fn selected_workspace_hooks_are_counted_but_never_authenticated() {
    let (_dir, root) = root();
    let workspace = root.join("work");
    fs::create_dir_all(workspace.join(".codex")).unwrap();
    fs::write(
        workspace.join(".codex").join("hooks.json"),
        r#"{"hooks": {"PreToolUse": [{"hooks": [{}]}]}}"#,
    )
    .unwrap();
    let report = report(&ctx(&root, Some(&workspace)), &Map::new(), "now").unwrap();
    let observed = &report["workspace"];
    assert_eq!(observed["selected"], json!(true));
    assert_eq!(
        observed["authentication"],
        json!("unverified_local_configuration")
    );
    assert_eq!(observed["event_handler_counts"]["PreToolUse"], json!(1));
}

#[test]
fn report_json_is_sorted_compact_and_ascii() {
    let value = json!({"b": "é😀", "a": {"d": 1, "c": [true, null]}});
    assert_eq!(
        ascii_json(&value),
        r#"{"a":{"c":[true,null],"d":1},"b":"\u00e9\ud83d\ude00"}"#
    );
}
