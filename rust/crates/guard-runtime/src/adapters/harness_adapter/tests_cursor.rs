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
        "frozen": false,
        "frozen_launcher": null,
        "executable": "/usr/bin/python3",
        "frozen_recovery": ["/g/bin/hol-guard", "cursor", "recover"],
        "can_rebind": true,
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
            "expand" => {
                let mut paths = fields
                    .get("long_paths")
                    .and_then(Value::as_object)
                    .cloned()
                    .unwrap_or_default();
                for token in value.as_array().unwrap() {
                    paths.insert(token.as_str().unwrap().to_owned(), token.clone());
                }
                Value::Object(paths)
            }
            // Windows asks Python to quote each hook line; any text will do.
            "render" => {
                let mut pairs = fields
                    .get("rendered")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                for argv in value.as_array().unwrap() {
                    let words: Vec<&str> = argv
                        .as_array()
                        .unwrap()
                        .iter()
                        .filter_map(Value::as_str)
                        .collect();
                    pairs.push(json!([argv, words.join(" ")]));
                }
                Value::Array(pairs)
            }
            "relaunch" => json!(value
                .as_array()
                .unwrap()
                .iter()
                .map(|args| json!([args, ["/g/bin/hol-guard", args]]))
                .collect::<Vec<_>>()),
            "servers" => json!(
                json!({"detect": value, "managed": [], "skipped": [], "observed": []}).to_string()
            ),
            other => panic!("unexpected reply {other}"),
        };
        let field = match key.as_str() {
            "expand" => "long_paths",
            "render" => "rendered",
            other => other,
        };
        fields.insert(field.to_owned(), answered);
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
