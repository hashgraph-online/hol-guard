use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::super::codex::backup_path;
use super::super::Ctx;
use super::uninstall_plan;

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

fn plan(ctx: &Ctx, authority: &[PathBuf]) -> Value {
    let mut fields = Map::new();
    fields.insert("owned".into(), json!("[]"));
    fields.insert("authority_files".into(), json!(authority));
    uninstall_plan(ctx, &fields).ok().unwrap()
}

fn paths(answer: &Value) -> Vec<String> {
    answer["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|file| file["path"].as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn present_authority_files_are_deleted_and_absent_ones_skipped() {
    let (_dir, root) = root();
    let ctx = ctx(&root);
    let managed = root.join("guard").join("managed").join("codex");
    fs::create_dir_all(&managed).unwrap();
    let manifest = managed.join("hooks-x.manifest.json");
    fs::write(&manifest, "{}").unwrap();
    let receipt = managed.join("hooks-x.authority-receipt.json");
    let answer = plan(&ctx, &[receipt, manifest.clone()]);
    let listed = paths(&answer);
    assert_eq!(listed[0], manifest.to_string_lossy());
    assert!(!listed
        .iter()
        .any(|path| path.ends_with("authority-receipt.json")));
    let file = &answer["files"][0];
    assert_eq!(file["after"], Value::Null);
    assert_eq!(file["no_follow"], json!(true));
    // Every later file is a shell cleanup, compared against disk by the caller.
    let compared: Vec<usize> = (1..listed.len()).collect();
    assert_eq!(answer["compared"], json!(compared));
    assert!(answer["manifest"].is_string());
}

#[test]
fn an_empty_backup_without_a_config_deletes_the_backup() {
    let (_dir, root) = root();
    let ctx = ctx(&root);
    let backup = backup_path(&ctx);
    fs::create_dir_all(backup.parent().unwrap()).unwrap();
    fs::write(&backup, "").unwrap();
    let answer = plan(&ctx, &[]);
    let config = root.join("home").join(".codex").join("config.toml");
    assert_eq!(
        paths(&answer)[..2],
        [
            config.to_string_lossy().into_owned(),
            backup.to_string_lossy().into_owned()
        ]
    );
    assert_eq!(answer["files"][0]["before"], Value::Null);
    assert_eq!(answer["files"][0]["after"], Value::Null);
    assert_eq!(answer["files"][1]["after"], Value::Null);
}
