use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Map, Value};

use super::super::Ctx;
use super::runtime_hooks_verified;

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
    let config = root.join("home").join(".codex").join("config.toml");
    let spec = json!({
        "guard_home": root.join("guard"),
        "home_dir": root.join("home"),
        "runtime_guard_home": root.join("guard"),
        "workspace_dir": null,
        "config_path": config,
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

/// Guard's bridge hooks on both intercept events, under the given config.
fn write_codex(root: &Path, config: &str) {
    let codex = root.join("home").join(".codex");
    fs::create_dir_all(&codex).unwrap();
    fs::write(codex.join("config.toml"), config).unwrap();
    let bridge = root.join("bin").join("codex_daemon_hook_bridge.py");
    fs::create_dir_all(bridge.parent().unwrap()).unwrap();
    fs::write(&bridge, "").unwrap();
    let python = root.join("bin").join("python3");
    fs::write(&python, "").unwrap();
    let command = format!("{} {} --harness codex", python.display(), bridge.display());
    let group = json!({"matcher": "Bash", "hooks": [{"type": "command", "command": command}]});
    let hooks = json!({"hooks": {"PreToolUse": [group], "PermissionRequest": [group]}});
    fs::write(codex.join("hooks.json"), hooks.to_string()).unwrap();
}

fn verified(root: &Path) -> Value {
    runtime_hooks_verified(&ctx(root), &fields(root))
        .ok()
        .unwrap()["verified"]
        .clone()
}

#[cfg(unix)]
#[test]
fn live_guard_hooks_that_intercept_the_shell_are_verified() {
    let (_dir, root) = root();
    write_codex(&root, "[features]\nhooks = true\n");
    assert_eq!(verified(&root), json!(true));
}

#[test]
fn disabled_hooks_fall_back_to_the_unverified_manifest() {
    let (_dir, root) = root();
    write_codex(&root, "[features]\nhooks = false\n");
    assert_eq!(verified(&root), json!(false));
}

#[test]
fn no_codex_config_is_not_verified() {
    let (_dir, root) = root();
    assert_eq!(verified(&root), json!(false));
}
