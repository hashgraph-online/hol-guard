//! Claude Code through the `harness_adapter` kind, answering its `facts`
//! reply the way the Python glue does.

use std::fs;

use serde_json::{json, Map, Value};

use super::{after, dispatch, shim, Home};

fn facts(bridge: Option<&str>, frozen: bool) -> String {
    json!({
        "bridge": bridge,
        "session_runtime": bridge,
        "runtime_build": "1.2.3+abc123",
        "frozen": frozen,
        "launcher": frozen.then_some("/g/bin/hol-guard"),
        "python": "/usr/bin/python3",
        "package_root": "/src",
        "daemon_url": "http://127.0.0.1:4781",
        "query_extras": [["harness", "claude-code"]],
        "recovery_home": ["/g/bin/hol-guard", "daemon", "start"],
        "recovery_context": ["/g/bin/hol-guard", "daemon", "start", "--home"],
    })
    .to_string()
}

fn ask(home: &Home, op: &str, fields: &Map<String, Value>) -> Value {
    let mut request =
        json!({"harness": "claude-code", "op": op, "context": home.context(json!({"PATH": ""}))});
    for (key, value) in fields {
        request[key] = value.clone();
    }
    dispatch(&request).unwrap()
}

/// Answer the `facts` reply once, as `ClaudeCodeHarnessAdapter._ask` does.
fn run(home: &Home, op: &str, extra: Value, facts_text: &str) -> Value {
    let mut fields = extra.as_object().cloned().unwrap_or_default();
    let answer = ask(home, op, &fields);
    let Some(reply) = answer.get("reply") else {
        return answer;
    };
    assert_eq!(reply, &json!({"facts": null}));
    fields.insert("facts".into(), json!(facts_text));
    let answer = ask(home, op, &fields);
    assert!(answer.get("reply").is_none(), "{answer}");
    answer
}

fn settings(home: &Home) -> std::path::PathBuf {
    home.home().join(".claude").join("settings.json")
}

fn installed(home: &Home, bridge: Option<&str>) -> Value {
    let answer = run(
        home,
        "prepare_install",
        json!({"shim": shim()}),
        &facts(bridge, false),
    );
    serde_json::from_str(&after(&answer["files"][0])).unwrap()
}

#[test]
fn install_writes_session_start_and_every_runtime_group() {
    let home = Home::new();
    let payload = installed(&home, Some("/rt/hol-guard-runtime"));
    let hooks = payload["hooks"].as_object().unwrap();
    let session = hooks["SessionStart"].as_array().unwrap();
    let matchers: Vec<&str> = session
        .iter()
        .map(|group| group["matcher"].as_str().unwrap())
        .collect();
    assert_eq!(matchers, ["startup", "resume", "clear", "compact"]);
    let session_handler = &session[0]["hooks"][0];
    assert_eq!(session_handler["command"], "/rt/hol-guard-runtime");
    assert_eq!(session_handler["args"][1], "session-start");
    assert_eq!(session_handler["timeout"], 10);
    for event in [
        "PreToolUse",
        "PermissionRequest",
        "PostToolUse",
        "Notification",
        "Stop",
    ] {
        let handler = &hooks[event][0]["hooks"][0];
        assert_eq!(handler["args"][0], "claude-hook-bridge", "{event}");
        assert_eq!(
            handler["args"][1], "HOL_GUARD_CLAUDE_DAEMON_HOOK",
            "{event}"
        );
    }
    assert!(hooks["Stop"][0].get("matcher").is_none());
    let config: Value = serde_json::from_str(
        hooks["PreToolUse"][0]["hooks"][0]["args"][2]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(config["fallback_daemon_url"], "http://127.0.0.1:4781");
    assert_eq!(config["recovery_command"][1], "daemon");
    assert!(config["query"]
        .as_str()
        .unwrap()
        .ends_with("&harness=claude-code"));
}

#[test]
fn install_keeps_user_entries_and_replaces_stale_guard_ones() {
    let home = Home::new();
    fs::create_dir_all(settings(&home).parent().unwrap()).unwrap();
    let stale = json!({"type": "command", "command": "/old/python", "args": ["-c", "x", "HOL_GUARD_CLAUDE_DAEMON_HOOK"]});
    let user = json!({"type": "command", "command": "lint"});
    let before = json!({
        "theme": "dark",
        "hooks": {
            "PreToolUse": [{"matcher": "Bash", "hooks": [user, stale]}],
            "PermissionDenied": [{"hooks": [stale]}],
        },
    });
    fs::write(settings(&home), before.to_string()).unwrap();
    let payload = installed(&home, None);
    assert_eq!(payload["theme"], "dark");
    let pre = payload["hooks"]["PreToolUse"].as_array().unwrap();
    assert_eq!(pre[0]["hooks"], json!([user]));
    assert_eq!(pre[1]["hooks"][0]["command"], "/usr/bin/python3");
    assert!(payload["hooks"].get("PermissionDenied").is_none());
}

#[test]
fn install_refuses_settings_that_are_not_an_object() {
    let home = Home::new();
    fs::create_dir_all(settings(&home).parent().unwrap()).unwrap();
    fs::write(settings(&home), "[]").unwrap();
    let answer = ask(
        &home,
        "prepare_install",
        json!({"shim": shim()}).as_object().unwrap(),
    );
    assert_eq!(
        answer["refusal"],
        "Claude Code settings must be a JSON object before installation."
    );
}

#[test]
fn frozen_builds_launch_the_stable_cli() {
    let home = Home::new();
    let frozen = facts(None, true);
    let argv = |which: &str| run(&home, "argv", json!({"which": which}), &frozen)["argv"].clone();
    assert_eq!(argv("hook")[0], "/g/bin/hol-guard");
    assert_eq!(argv("hook")[1], "hook");
    assert_eq!(argv("daemon")[1], "__guard-claude-hook");
    let session = argv("session_start");
    assert_eq!(session[1], "__guard-claude-hook");
    assert_eq!(session[2], "HOL_GUARD_CLAUDE_SESSION_START_HOOK");
    assert_eq!(session.as_array().unwrap().len(), 5);
}

#[test]
fn source_checkout_argv_imports_from_the_package_root() {
    let home = Home::new();
    let source = facts(None, false);
    let hook = run(&home, "argv", json!({"which": "hook"}), &source)["argv"].clone();
    assert_eq!(hook[0], "/usr/bin/python3");
    assert!(hook[2]
        .as_str()
        .unwrap()
        .contains("sys.path.insert(0, '/src')"));
    let session = run(
        &home,
        "argv",
        json!({"which": "python_session_start"}),
        &source,
    )["argv"]
        .clone();
    assert!(session[2].as_str().unwrap().starts_with(
        "_HOL_GUARD_CLAUDE_SESSION_START_HOOK_MARKER = 'HOL_GUARD_CLAUDE_SESSION_START_HOOK';"
    ));
}

#[test]
fn uninstall_prunes_guard_entries_only() {
    let home = Home::new();
    let payload = installed(&home, None);
    let mut payload = payload.as_object().unwrap().clone();
    payload["hooks"]["Stop"]
        .as_array_mut()
        .unwrap()
        .push(json!({"hooks": [{"type": "command", "command": "notify"}]}));
    fs::create_dir_all(settings(&home).parent().unwrap()).unwrap();
    fs::write(settings(&home), Value::Object(payload).to_string()).unwrap();
    let answer = ask(&home, "prepare_uninstall", &Map::new());
    let text = answer["writes"][0]["text"].as_str().unwrap();
    let cleaned: Value = serde_json::from_str(text).unwrap();
    assert_eq!(cleaned["hooks"]["PreToolUse"], json!([]));
    assert_eq!(cleaned["hooks"]["Stop"][0]["hooks"][0]["command"], "notify");
    assert_eq!(
        answer["finish"]["notes"][0],
        "Guard hook entries removed from ~/.claude/settings.json"
    );
}

#[test]
fn diagnostics_mark_an_active_setup_without_hooks_broken() {
    let home = Home::new();
    let fields = json!({"setup_status": "active", "warnings": ["earlier"]});
    let answer = ask(&home, "diagnostics", fields.as_object().unwrap());
    let update: Value = serde_json::from_str(answer["update"].as_str().unwrap()).unwrap();
    assert_eq!(update["setup_status"], "broken");
    assert_eq!(update["warnings"][0], "earlier");
    assert!(update["warnings"][1]
        .as_str()
        .unwrap()
        .contains("(PreToolUse, PermissionRequest)"));
    let payload = installed(&home, None);
    fs::create_dir_all(settings(&home).parent().unwrap()).unwrap();
    fs::write(settings(&home), payload.to_string()).unwrap();
    let answer = ask(&home, "diagnostics", fields.as_object().unwrap());
    assert_eq!(answer["update"], "{}");
}

#[test]
fn refresh_leaves_settings_without_hooks_alone() {
    let home = Home::new();
    let answer = ask(&home, "refresh", &Map::new());
    assert_eq!(answer["text"], Value::Null);
}
