use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::super::{Ctx, Failure};
use super::{hooks_from_texts, verify_manifest};

fn root() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(dir.path()).unwrap();
    (dir, root)
}

fn ctx(root: &Path) -> Ctx {
    Ctx::parse(Some(&json!({
        "home": root.join("home"),
        "guard_home": root.join("guard"),
        "cwd": root,
        "user_home": root.join("home"),
        "env": {},
    })))
    .unwrap()
}

fn fields(root: &Path) -> Map<String, Value> {
    let spec = json!({
        "guard_home": root.join("guard"),
        "home_dir": root.join("home"),
        "runtime_guard_home": root.join("guard"),
        "workspace_dir": null,
        "config_path": root.join("home").join(".codex").join("config.toml"),
        "interpreter_path": "/usr/bin/python3",
        "package_version": "0.0.0",
        "packaged_file_paths": [],
        "fallback_argv": [],
        "daemon_start_argv": [],
        "event_bindings": [],
    });
    let mut fields = Map::new();
    fields.insert("spec".into(), spec);
    fields.insert("package_roots".into(), json!([]));
    fields.insert("windows".into(), json!(false));
    fields.insert("long_paths".into(), json!({}));
    fields
}

fn reason(answer: &Value) -> &str {
    answer["state"]["integrity_reason"].as_str().unwrap()
}

#[test]
fn a_missing_manifest_is_reported_with_its_path() {
    let (_dir, root) = root();
    let answer = verify_manifest(&ctx(&root), &fields(&root)).ok().unwrap();
    assert_eq!(reason(&answer), "codex_hook_manifest_missing");
    let path = answer["state"]["manifest_path"].as_str().unwrap();
    assert!(path.starts_with(root.join("guard").join("managed").to_str().unwrap()));
    assert!(path.ends_with(".manifest.json"));
}

#[test]
fn a_spent_budget_leaves_the_installation_unverified() {
    let (_dir, root) = root();
    let mut fields = fields(&root);
    fields.insert("budget_spent".into(), json!(true));
    let answer = verify_manifest(&ctx(&root), &fields).ok().unwrap();
    assert_eq!(
        reason(&answer),
        "codex_hook_manifest_verification_unavailable"
    );
    assert_eq!(answer["state"]["integrity_status"], json!("tampered"));
}

#[test]
fn a_captured_manifest_that_is_not_json_is_unreadable() {
    let (_dir, root) = root();
    let mut fields = fields(&root);
    fields.insert("manifest_text".into(), json!("not json"));
    let answer = verify_manifest(&ctx(&root), &fields).ok().unwrap();
    assert_eq!(reason(&answer), "codex_hook_manifest_invalid");
}

#[test]
fn a_captured_manifest_without_authentication_is_refused() {
    let (_dir, root) = root();
    let mut fields = fields(&root);
    fields.insert("manifest_text".into(), json!("{\"harness\":\"codex\"}"));
    let answer = verify_manifest(&ctx(&root), &fields).ok().unwrap();
    assert_eq!(
        reason(&answer),
        "codex_hook_manifest_authentication_missing"
    );
}

#[test]
fn a_spec_that_is_not_an_object_is_invalid() {
    let (_dir, root) = root();
    let mut fields = fields(&root);
    fields.insert("spec".into(), json!("spec"));
    assert!(matches!(
        verify_manifest(&ctx(&root), &fields),
        Err(Failure::Invalid)
    ));
}

#[test]
fn hooks_that_are_not_an_object_stay_unread() {
    assert!(hooks_from_texts(None).ok().unwrap().is_none());
    assert!(hooks_from_texts(Some(&Value::Null)).ok().unwrap().is_none());
    assert!(hooks_from_texts(Some(&json!([]))).ok().unwrap().is_none());
}

#[test]
fn each_group_crosses_as_json_and_one_that_does_not_parse_is_null() {
    let hooks = json!({
        "PreToolUse": ["{\"hooks\":[{\"type\":\"command\"}]}", "{", null, "99999999999999999999"],
        "Unmanaged": ["{}"],
    });
    let wire = hooks_from_texts(Some(&hooks)).ok().unwrap().unwrap();
    assert_eq!(
        wire,
        json!({ "PreToolUse": [{"hooks": [{"type": "command"}]}, null, null, null] })
    );
}

#[test]
fn a_managed_event_that_is_not_a_list_is_invalid() {
    let hooks = json!({ "PreToolUse": "{}" });
    assert!(matches!(
        hooks_from_texts(Some(&hooks)),
        Err(Failure::Invalid)
    ));
}
