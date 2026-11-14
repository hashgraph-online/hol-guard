use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use super::super::Ctx;
use super::{canary, node_check};

fn script(path: &Path, body: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

fn ctx(root: &Path, env: Value) -> Ctx {
    Ctx::parse(Some(&json!({
        "home": root,
        "guard_home": root,
        "cwd": root,
        "user_home": root,
        "env": env,
    })))
    .unwrap()
}

fn root() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(dir.path()).unwrap();
    (dir, root)
}

#[test]
fn the_canary_gets_the_synthetic_read_and_only_the_hook_environment() {
    let (_dir, root) = root();
    let hook = root.join("PreToolUse");
    script(
        &hook,
        "cat > \"$0.input\"; env > \"$0.env\"; printf '{\"cancel\": false}\\n'",
    );
    let context = ctx(
        &root,
        json!({"PATH": "/usr/bin:/bin", "HOME": root, "NODE_OPTIONS": "--require=x.js"}),
    );
    let run = canary(
        &context,
        &[hook.to_string_lossy().into_owned()],
        "{\"hookName\": \"PreToolUse\"}",
    );
    assert_eq!(
        run,
        json!({"returncode": 0, "stdout": "{\"cancel\": false}\n", "error": null})
    );
    assert_eq!(
        fs::read_to_string(root.join("PreToolUse.input")).unwrap(),
        "{\"hookName\": \"PreToolUse\"}"
    );
    let env = fs::read_to_string(root.join("PreToolUse.env")).unwrap();
    assert!(env.lines().any(|line| line == "HOL_GUARD_CLINE_CANARY=1"));
    assert!(env
        .lines()
        .any(|line| line == format!("HOME={}", root.display())));
    assert!(!env.contains("NODE_OPTIONS"));

    let missing = canary(
        &context,
        &[root.join("absent").to_string_lossy().into_owned()],
        "",
    );
    assert_eq!(missing["returncode"], Value::Null);
    assert_eq!(missing["stdout"], "");
    assert!(missing["error"].is_string());
}

#[test]
fn node_checks_the_plugin_after_ending_options_and_without_preloads() {
    let (_dir, root) = root();
    let bin = root.join("bin");
    script(
        &bin.join("node"),
        "printf '%s\\n' \"$@\" > \"$0.args\"; env > \"$0.env\"; exit 1",
    );
    let context = ctx(
        &root,
        json!({
            "PATH": bin,
            "NODE_OPTIONS": "--require=untrusted.js",
            "NODE_PATH": "/untrusted/modules",
            "LD_PRELOAD": "/untrusted/library.so",
        }),
    );
    assert_eq!(
        node_check(&context, "--eval=index.js"),
        json!({"ok": false, "return_code": 1})
    );
    assert_eq!(
        fs::read_to_string(bin.join("node.args")).unwrap(),
        "--check\n--\n--eval=index.js\n"
    );
    let env = fs::read_to_string(bin.join("node.env")).unwrap();
    for name in ["NODE_OPTIONS", "NODE_PATH", "LD_PRELOAD"] {
        assert!(!env.contains(name), "{name}");
    }
    let empty = ctx(&root, json!({"PATH": root.join("empty")}));
    assert_eq!(
        node_check(&empty, "index.js"),
        json!({"ok": true, "skipped": true, "reason": "node_not_available"})
    );
}

#[test]
fn a_real_node_checks_the_plugin_without_executing_it() {
    let Ok(path) = std::env::var("PATH") else {
        return;
    };
    let (_dir, root) = root();
    let context = ctx(&root, json!({"PATH": path}));
    if super::which::which(&context, "node").is_none() {
        return;
    }
    let marker = root.join("must-not-run");
    let prelude = format!(
        "require('node:fs').writeFileSync({}, 'executed');\n",
        json!(marker.to_string_lossy())
    );
    for (source, ok) in [("export default {};", true), ("function broken( {", false)] {
        let index = root.join("index.js");
        fs::write(&index, format!("{prelude}{source}")).unwrap();
        let verdict = node_check(&context, &index.to_string_lossy());
        assert_eq!(verdict["ok"], json!(ok), "{verdict}");
        assert!(!marker.exists());
    }
}
