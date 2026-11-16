use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::super::Ctx;
use super::prepare;

fn ctx(root: &Path) -> Ctx {
    Ctx::parse(Some(&json!({
        "home": root,
        "guard_home": root.join(".hol-guard"),
        "cwd": root,
        "user_home": root,
        "env": {},
    })))
    .unwrap()
}

fn root() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(dir.path()).unwrap();
    (dir, root)
}

fn fields(value: Value) -> Map<String, Value> {
    value.as_object().unwrap().clone()
}

fn planned(root: &Path, request: Value) -> Value {
    let Ok(answer) = prepare(&ctx(root), &fields(request)) else {
        panic!("the profile plan was refused");
    };
    answer
}

#[test]
fn a_bash_profile_gets_the_launcher_block_and_keeps_its_mode() {
    let (_dir, root) = root();
    let profile = root.join(".bashrc");
    fs::write(&profile, "export EDITOR=vi\n").unwrap();
    fs::set_permissions(&profile, fs::Permissions::from_mode(0o640)).unwrap();
    let answer = planned(&root, json!({"shell": "bash"}));
    let manifest = &answer["manifest"];
    assert_eq!(manifest["changed"], json!(true));
    assert_eq!(manifest["restart_shell_required"], json!(true));
    assert_eq!(manifest["profile_path"], json!(profile.to_string_lossy()));
    let files = answer["files"].as_array().unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0]["no_follow"], json!(true));
    assert_eq!(files[0]["before_mode"], json!(0o640));
    assert_eq!(fs::read_to_string(&profile).unwrap(), "export EDITOR=vi\n");
}

#[test]
fn an_unknown_shell_uses_zshrc_and_a_missing_profile_is_private() {
    let (_dir, root) = root();
    let answer = planned(&root, json!({"shell": "nu"}));
    let path = root.join(".zshrc");
    assert_eq!(
        answer["manifest"]["profile_path"],
        json!(path.to_string_lossy())
    );
    assert_eq!(answer["files"][0]["after_mode"], json!(0o600));
    assert!(!path.exists());
}

#[test]
fn a_transient_guard_home_asks_for_a_manual_path_entry() {
    let (_dir, root) = root();
    let answer = planned(&root, json!({"shell": "zsh", "shim_dir_transient": true}));
    assert_eq!(answer["files"], json!([]));
    assert_eq!(
        answer["manifest"]["manual_path_reason"],
        json!("transient_guard_home")
    );
    assert_eq!(answer["manifest"]["profile_path"], Value::Null);
}

#[test]
fn a_wrong_typed_field_is_invalid() {
    let (_dir, root) = root();
    assert!(prepare(&ctx(&root), &fields(json!({"shell": 3}))).is_err());
    assert!(prepare(&ctx(&root), &fields(json!({"shim_dir_transient": "yes"}))).is_err());
}
