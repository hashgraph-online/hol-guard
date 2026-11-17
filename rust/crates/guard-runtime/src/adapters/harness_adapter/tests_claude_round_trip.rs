//! Claude install followed by uninstall gives the user back their settings.

use std::fs;

use serde_json::{json, Map, Value};

use super::super::{after, dispatch, shim, Home};
use super::{ask, facts, run, settings};

#[test]
fn install_then_uninstall_returns_every_unrelated_user_setting() {
    let home = Home::new();
    let original = json!({
        "model": "synthetic-model",
        "env": {"SYNTHETIC_FLAG": "1"},
        "permissions": {"allow": ["Bash(npm test)"], "deny": ["Read(./secrets/**)"]},
        "statusLine": {"type": "command", "command": "status-script"},
        "hooks": {
            "PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "user-lint"}]}],
            "Stop": [{"hooks": [{"type": "command", "command": "notify"}]}]
        },
        "futureKey": {"nested": ["kept", 1, true, null]},
        "unicode": "caf\u{e9} \u{2014} \u{1f512}"
    });
    assert_eq!(round_trip(&home, &original), original);
}

/// A file with no hooks of its own must not come back with an empty `hooks`.
#[test]
fn install_then_uninstall_leaves_no_hooks_key_in_a_file_that_had_none() {
    let home = Home::new();
    let original = json!({"model": "synthetic-model", "env": {"SYNTHETIC_FLAG": "1"}});
    assert_eq!(round_trip(&home, &original), original);
}

fn round_trip(home: &Home, original: &Value) -> Value {
    fs::create_dir_all(settings(home).parent().unwrap()).unwrap();
    fs::write(
        settings(home),
        serde_json::to_string_pretty(original).unwrap(),
    )
    .unwrap();
    let answer = run(home, "prepare_install", json!({"shim": shim()}), &facts());
    let with_guard = after(&answer["files"][0]);
    let installed: Value = serde_json::from_str(&with_guard).unwrap();
    assert_ne!(
        installed["hooks"]["SessionStart"],
        Value::Null,
        "install added nothing"
    );
    fs::write(settings(home), &with_guard).unwrap();
    let answer = ask(home, "prepare_uninstall", &Map::new());
    serde_json::from_str(answer["writes"][0]["text"].as_str().unwrap()).unwrap()
}

/// Hooks always install into the user file; a workspace's own Claude files
/// must be byte-identical after install and uninstall for that workspace.
#[test]
fn install_then_uninstall_for_a_workspace_leaves_its_claude_files_untouched() {
    let home = Home::new();
    let workspace = home.root.join("project");
    let claude_dir = workspace.join(".claude");
    fs::create_dir_all(&claude_dir).unwrap();
    let shared = "{\n  \"permissions\": {\"allow\": [\"Bash(make)\"]},\n  \"hooks\": {\"Stop\": [{\"hooks\": [{\"type\": \"command\", \"command\": \"notify\"}]}]}\n}\n";
    let local = "{ \"env\": {\"LOCAL\": \"caf\u{e9}\"} }";
    fs::write(claude_dir.join("settings.json"), shared).unwrap();
    fs::write(claude_dir.join("settings.local.json"), local).unwrap();
    let ask_in = |op: &str, mut fields: Map<String, Value>| {
        let mut context = home.context(json!({"PATH": ""}));
        context["workspace"] = json!(workspace);
        fields.insert("harness".into(), json!("claude-code"));
        fields.insert("op".into(), json!(op));
        fields.insert("context".into(), context);
        let answer = dispatch(&Value::Object(fields.clone())).unwrap();
        if answer.get("reply").is_none() {
            return answer;
        }
        fields.insert("facts".into(), json!(facts()));
        dispatch(&Value::Object(fields)).unwrap()
    };
    let mut fields = Map::new();
    fields.insert("shim".into(), json!(shim()));
    let answer = ask_in("prepare_install", fields);
    for change in answer["files"].as_array().unwrap() {
        let path = std::path::PathBuf::from(change["path"].as_str().unwrap());
        assert!(!path.starts_with(&workspace), "install planned {path:?}");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, after(change)).unwrap();
    }
    let answer = ask_in("prepare_uninstall", Map::new());
    for write in answer["writes"].as_array().into_iter().flatten() {
        let path = std::path::PathBuf::from(write["path"].as_str().unwrap());
        assert!(!path.starts_with(&workspace), "uninstall wrote {path:?}");
    }
    assert_eq!(
        fs::read_to_string(claude_dir.join("settings.json")).unwrap(),
        shared
    );
    assert_eq!(
        fs::read_to_string(claude_dir.join("settings.local.json")).unwrap(),
        local
    );
}
