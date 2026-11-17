//! `config_hooks`: Guard's groups go into the config payload, each hook's
//! state follows its handler, and the Guard handlers written are trusted.

use serde_json::{json, Value};

use super::{group, Home};

const BRIDGE: [&str; 3] = ["/g/hol-guard-runtime", "codex-hook-bridge", "{}"];

fn managed(home: &Home) -> String {
    let answer = home.ask(
        "codex",
        "groups",
        json!({"argv": BRIDGE, "long_timeout": 85}),
    );
    answer["groups"].as_str().unwrap().to_owned()
}

fn fields(home: &Home, payload: &Value) -> Value {
    json!({
        "payload": payload.to_string(),
        "tokens": {},
        "owned": "[]",
        "managed": managed(home),
        "config": home.home().join(".codex/config.toml"),
        "cwd": null,
        "guard_home": home.guard(),
        "package_root": "/opt/guard/site",
        "expected": "[]",
        "argv": BRIDGE,
        "legacy_argv": ["/py", "-m", "codex_plugin_scanner.cli"],
        "statuses": [],
        "windows": false,
        "long_paths": {},
    })
}

fn installed(home: &Home, payload: &Value) -> Value {
    let answer = home.ask("codex", "config_hooks", fields(home, payload));
    serde_json::from_str(answer["payload"].as_str().unwrap()).unwrap()
}

#[test]
fn guard_groups_are_written_and_trusted() {
    let home = Home::new();
    let payload = installed(
        &home,
        &json!({"model": "o3", "features": {"codex_hooks": true, "x": 1}}),
    );
    assert_eq!(payload["model"], "o3");
    assert_eq!(payload["features"], json!({"x": 1, "hooks": true}));
    let hooks = payload["hooks"].as_object().unwrap();
    for event in [
        "PreToolUse",
        "PermissionRequest",
        "UserPromptSubmit",
        "PostToolUse",
    ] {
        assert!(hooks[event].is_array(), "{event} missing");
    }
    let state = hooks["state"].as_object().unwrap();
    assert_eq!(state.len(), 4);
    assert!(state.values().all(|entry| entry["trusted_hash"]
        .as_str()
        .is_some_and(|hash| !hash.is_empty())));
}

#[test]
fn a_foreign_hook_keeps_its_state_and_is_not_trusted() {
    let home = Home::new();
    let foreign = format!(
        "{}:stop:0:0",
        home.home().join(".codex/config.toml").display()
    );
    let payload = installed(
        &home,
        &json!({"hooks": {
            "Stop": [group("echo done", 5)],
            "state": {&foreign: {"enabled": false}},
        }}),
    );
    let hooks = payload["hooks"].as_object().unwrap();
    assert_eq!(hooks["Stop"][0]["hooks"][0]["command"], "echo done");
    let state = hooks["state"].as_object().unwrap();
    assert_eq!(state.len(), 5);
    assert_eq!(state[&foreign], json!({"enabled": false}));
    assert_eq!(hooks["PreToolUse"].as_array().unwrap().len(), 1);
}

#[test]
fn a_malformed_request_is_refused() {
    let home = Home::new();
    let mut request = fields(&home, &json!({}));
    request["payload"] = json!("[1]");
    request["harness"] = json!("codex");
    request["op"] = json!("config_hooks");
    request["context"] = home.context(json!({"PATH": ""}));
    let answer = super::super::super::dispatch(&request);
    assert!(answer.map_or(true, |answer| answer.get("payload").is_none()));
}
