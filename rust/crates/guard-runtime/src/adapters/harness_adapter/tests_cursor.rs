//! Cursor through the `harness_adapter` kind, answering its replies the way
//! the Python glue does.

use std::fs;
use std::path::Path;

use serde_json::{json, Map, Value};

use super::{after, dispatch, Home};
use crate::runner_authority_op::KindResult;

fn facts(bridge: Value) -> String {
    json!({
        "bridge": bridge,
        "attestation": {"command": ["/g/bin/hol-guard"], "identity": {"sha256": "ab12cd"}, "python": null},
        "interpreter": null,
        "frozen_recovery": ["/g/bin/hol-guard", "cursor", "recover"],
    })
    .to_string()
}

fn ask(home: &Home, op: &str, fields: &Map<String, Value>) -> KindResult {
    let mut request =
        json!({"harness": "cursor", "op": op, "context": home.context(json!({"PATH": ""}))});
    for (key, value) in fields {
        request[key] = value.clone();
    }
    dispatch(&request)
}

/// Answer every reply until the op settles, as `_cursor_ask` does.
fn run(home: &Home, op: &str, bridge: Value) -> KindResult {
    let mut fields = Map::new();
    for _ in 0..16 {
        let answer = ask(home, op, &fields)?;
        let Some(reply) = answer.get("reply").and_then(Value::as_object) else {
            return Ok(answer);
        };
        let (key, value) = reply.iter().next().unwrap();
        let answered = match key.as_str() {
            "facts" => json!(facts(bridge.clone())),
            "servers" => json!(
                json!({"detect": value, "managed": [], "skipped": [], "observed": []}).to_string()
            ),
            other => panic!("unexpected reply {other}"),
        };
        fields.insert(key.clone(), answered);
    }
    panic!("{op} never settled");
}

fn bridge() -> Value {
    json!("/g/bin/hol-guard-runtime")
}

fn write(path: &Path, text: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

#[test]
fn cursor_ops_ask_for_facts_before_planning() {
    let home = Home::new();
    let answer = ask(&home, "prepare_install", &Map::new()).unwrap();
    assert_eq!(answer, json!({"reply": {"facts": null}}));
}

#[test]
fn cursor_prepare_without_an_enrolled_key_is_a_transition_error() {
    let home = Home::new();
    let answer = run(&home, "prepare_install", bridge()).unwrap();
    assert_eq!(
        answer["transition_error"],
        "adapter_preparation_authority_missing"
    );
    let answer = run(&home, "prepare_install", Value::Null).unwrap();
    assert_eq!(
        answer["transition_error"],
        "adapter_preparation_native_cursor_bridge_missing"
    );
    assert!(!home.guard().join("cursor").exists());
}

#[test]
fn cursor_install_without_a_bridge_writes_nothing() {
    let home = Home::new();
    let answer = run(&home, "install", Value::Null).unwrap();
    assert_eq!(
        answer["runtime_error"],
        "guard_cursor_native_bridge_unavailable"
    );
    assert_eq!(fs::read_dir(home.guard()).unwrap().count(), 0);
}

#[test]
fn cursor_install_keeps_other_hooks_beside_guards() {
    let home = Home::new();
    let hooks = home.home().join(".cursor").join("hooks.json");
    write(
        &hooks,
        r#"{"version": 1, "hooks": {"stop": [{"command": "./other-tool.sh"}]}}"#,
    );
    let answer = run(&home, "install", bridge()).unwrap();
    let identity = answer["identity"][0].as_str().unwrap();
    assert_eq!(fs::read(identity).unwrap().len(), 32);
    let planned = answer["files"]
        .as_array()
        .unwrap()
        .iter()
        .find(|change| change["path"] == json!(hooks))
        .expect("hooks.json is planned");
    let merged: Value = serde_json::from_str(&after(planned)).unwrap();
    let text = merged.to_string();
    assert!(text.contains("./other-tool.sh"));
    assert!(text.contains("hol-guard-cursor-hook.py"));
    assert!(merged["hooks"]["preToolUse"].is_array());
    let manifest: Value = serde_json::from_str(answer["manifest"].as_str().unwrap()).unwrap();
    assert_eq!(manifest["harness"], "cursor");
}

#[test]
fn cursor_without_hooks_is_inactive_and_not_rebound() {
    let home = Home::new();
    let state = run(&home, "hook_state", bridge()).unwrap();
    let state: Value = serde_json::from_str(state["state"].as_str().unwrap()).unwrap();
    assert_eq!(state["protection_active"], false);
    assert!(run(&home, "health", bridge()).unwrap()["verified"].is_null());
    let rebind = run(&home, "rebind", bridge()).unwrap();
    assert_eq!(rebind["rebound"], false);
}

fn rebind_with_caller(caller: Value) -> Value {
    let home = Home::new();
    let mut request = json!({
        "harness": "cursor",
        "op": "rebind",
        "context": home.context(json!({"PATH": ""})),
    });
    request["context"]["caller"] = caller;
    request["facts"] = json!(facts(bridge()));
    dispatch(&request).unwrap()
}

fn frozen_caller(prune_safe: bool, runnable: bool) -> Value {
    json!({
        "executable": "/g/core",
        "executable_resolved": "/g/core",
        "frozen": true,
        "launcher": "/g/bin/hol-guard-core",
        "frozen_launcher": "/g/bin/hol-guard-core",
        "launcher_prune_safe": prune_safe,
        "launcher_runnable": runnable,
        "cli_executable": "/g/core",
        "package_root": "/opt/guard/site",
        "version": "0.0.0",
    })
}

#[test]
fn a_rebind_needs_a_prune_safe_runnable_frozen_launcher_from_the_caller() {
    for (prune_safe, runnable) in [(false, true), (true, false), (false, false)] {
        let answer = rebind_with_caller(frozen_caller(prune_safe, runnable));
        assert_eq!(answer["reason"], "stable_frozen_cli_unavailable");
    }
    let answer = rebind_with_caller(frozen_caller(true, true));
    assert_eq!(answer["reason"], "cursor_hook_script_absent");
}

#[test]
fn cursor_uninstall_of_an_empty_home_reports_inactive() {
    let home = Home::new();
    let answer = run(&home, "uninstall", bridge()).unwrap();
    let manifest: Value = serde_json::from_str(answer["manifest"].as_str().unwrap()).unwrap();
    assert_eq!(manifest["active"], false);
    assert_eq!(manifest["restored"], false);
}

#[test]
fn cursor_rejects_a_missing_hook_script() {
    let home = Home::new();
    let missing = home
        .home()
        .join(".cursor")
        .join("hooks")
        .join("hol-guard-cursor-hook.py");
    let mut fields = Map::new();
    fields.insert("script".into(), json!(missing));
    let answer = ask(&home, "frozen_hook_script", &fields).unwrap();
    assert_eq!(answer["accepted"], false);
}

#[test]
fn cursor_install_then_uninstall_returns_the_users_hooks_file() {
    let home = Home::new();
    let hooks = home.home().join(".cursor").join("hooks.json");
    let original = json!({
        "version": 1,
        "hooks": {
            "stop": [{"command": "./other-tool.sh"}],
            "beforeShellExecution": [{"command": "./audit.sh", "timeout": 5}]
        },
        "futureKey": {"nested": ["kept", 1, true, null]},
        "unicode": "caf\u{e9} \u{2014} \u{1f512}"
    });
    write(&hooks, &serde_json::to_string_pretty(&original).unwrap());
    let answer = run(&home, "install", bridge()).unwrap();
    for change in answer["files"].as_array().unwrap() {
        let path = Path::new(change["path"].as_str().unwrap());
        if change["after"].is_string() {
            write(path, &after(change));
        }
    }
    let installed = fs::read_to_string(&hooks).unwrap();
    assert!(
        installed.contains("hol-guard-cursor-hook.py"),
        "install added nothing"
    );
    run(&home, "uninstall", bridge()).unwrap();
    let cleaned: Value = serde_json::from_str(&fs::read_to_string(&hooks).unwrap()).unwrap();
    assert_eq!(cleaned, original);
}

#[test]
fn cursor_uninstall_keeps_a_hook_the_user_added_after_install() {
    let home = Home::new();
    let hooks = home.home().join(".cursor").join("hooks.json");
    write(
        &hooks,
        r#"{"version": 1, "hooks": {"stop": [{"command": "./other-tool.sh"}]}}"#,
    );
    let answer = run(&home, "install", bridge()).unwrap();
    for change in answer["files"].as_array().unwrap() {
        if change["after"].is_string() {
            write(Path::new(change["path"].as_str().unwrap()), &after(change));
        }
    }
    let mut edited: Value = serde_json::from_str(&fs::read_to_string(&hooks).unwrap()).unwrap();
    edited["hooks"]["stop"]
        .as_array_mut()
        .unwrap()
        .push(json!({"command": "./added-later.sh"}));
    write(&hooks, &serde_json::to_string_pretty(&edited).unwrap());
    run(&home, "uninstall", bridge()).unwrap();
    let cleaned: Value = serde_json::from_str(&fs::read_to_string(&hooks).unwrap()).unwrap();
    assert_eq!(
        cleaned,
        json!({"version": 1, "hooks": {"stop": [
            {"command": "./other-tool.sh"},
            {"command": "./added-later.sh"}
        ]}})
    );
}

/// When Guard's entries are the only hooks, uninstall keeps the file for the
/// user's other top-level keys instead of deleting it.
#[test]
fn cursor_uninstall_keeps_top_level_keys_when_guard_held_the_only_hooks() {
    let home = Home::new();
    let hooks = home.home().join(".cursor").join("hooks.json");
    write(
        &hooks,
        r#"{"version": 1, "hooks": {}, "futureKey": "keep"}"#,
    );
    let answer = run(&home, "install", bridge()).unwrap();
    for change in answer["files"].as_array().unwrap() {
        if change["after"].is_string() {
            write(Path::new(change["path"].as_str().unwrap()), &after(change));
        }
    }
    let mut edited: Value = serde_json::from_str(&fs::read_to_string(&hooks).unwrap()).unwrap();
    edited["addedLater"] = json!(true);
    write(&hooks, &serde_json::to_string_pretty(&edited).unwrap());
    run(&home, "uninstall", bridge()).unwrap();
    let cleaned: Value = serde_json::from_str(&fs::read_to_string(&hooks).unwrap()).unwrap();
    assert_eq!(
        cleaned,
        json!({"version": 1, "hooks": {}, "futureKey": "keep", "addedLater": true})
    );
}

/// A hooks file with no hooks of its own comes back byte for byte.
#[test]
fn cursor_uninstall_restores_a_file_that_had_no_hooks_of_its_own() {
    let home = Home::new();
    let hooks = home.home().join(".cursor").join("hooks.json");
    let original = "{\n  \"version\": 1,\n  \"hooks\": {}\n}\n";
    write(&hooks, original);
    let answer = run(&home, "install", bridge()).unwrap();
    for change in answer["files"].as_array().unwrap() {
        if change["after"].is_string() {
            write(Path::new(change["path"].as_str().unwrap()), &after(change));
        }
    }
    assert_ne!(fs::read_to_string(&hooks).unwrap(), original);
    run(&home, "uninstall", bridge()).unwrap();
    assert_eq!(fs::read_to_string(&hooks).unwrap(), original);
}

#[test]
fn cursor_uninstall_keeps_a_file_whose_guard_hooks_are_already_gone() {
    let home = Home::new();
    let hooks = home.home().join(".cursor").join("hooks.json");
    write(&hooks, "{\n  \"version\": 1,\n  \"hooks\": {}\n}\n");
    let answer = run(&home, "install", bridge()).unwrap();
    for change in answer["files"].as_array().unwrap() {
        if change["after"].is_string() {
            write(Path::new(change["path"].as_str().unwrap()), &after(change));
        }
    }
    // The user removed Guard's entries by hand and added a hook of their own.
    let edited =
        "{\n  \"version\": 1,\n  \"hooks\": {\"stop\": [{\"command\": \"./later.sh\"}]}\n}\n";
    write(&hooks, edited);
    run(&home, "uninstall", bridge()).unwrap();
    assert_eq!(fs::read_to_string(&hooks).unwrap(), edited);
}
