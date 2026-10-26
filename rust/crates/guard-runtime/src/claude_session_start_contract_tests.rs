use serde_json::{json, Value};

use super::*;
use crate::claude_hook_bridge::BRIDGE_MARKER;
use crate::claude_session_start::SESSION_START_MARKER;

/// Written by the Python refresh (`tests/test_claude_session_start_native.py`
/// proves it), so these checks hold the Rust lane to the Python bytes.
const FIXTURE: &str =
    include_str!("../../../../tests/fixtures/claude_session_start/settings-current.v1.json");

fn fixture() -> Value {
    serde_json::from_str(FIXTURE).unwrap()
}

fn template(fixture: &Value) -> DaemonHookTemplate {
    DaemonHookTemplate {
        command: fixture["daemon_hook_command"]
            .as_array()
            .unwrap()
            .iter()
            .map(|part| part.as_str().unwrap().to_owned())
            .collect(),
        bridge_config: fixture["bridge_config"].as_object().unwrap().clone(),
    }
}

fn url(fixture: &Value) -> &str {
    fixture["daemon_url"].as_str().unwrap()
}

/// `settings_current` for the fixture after `mutate` edits its settings.
fn current_after(mutate: impl FnOnce(&mut Value)) -> bool {
    let fixture = fixture();
    let mut settings = fixture["settings"].clone();
    mutate(&mut settings);
    settings_current(
        &contract().unwrap(),
        &settings,
        &template(&fixture),
        url(&fixture),
    )
}

fn guard_handler<'a>(settings: &'a mut Value, event: &str) -> &'a mut Value {
    let entries = settings["hooks"][event].as_array_mut().unwrap();
    let entry = entries
        .iter_mut()
        .find(|entry| {
            entry["hooks"]
                .as_array()
                .unwrap()
                .iter()
                .any(|handler| handler["command"] != json!("/usr/bin/true"))
        })
        .unwrap();
    entry["hooks"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|handler| handler["command"] != json!("/usr/bin/true"))
        .unwrap()
}

#[test]
fn compiled_contract_matches_the_lane_and_bridge_constants() {
    let contract = contract().unwrap();
    assert_eq!(contract.daemon_hook_marker, BRIDGE_MARKER);
    assert_eq!(contract.session_start_hook_marker, SESSION_START_MARKER);
    assert_eq!(contract.session_start_event, "SessionStart");
    assert_eq!(contract.settings_path, ".claude/settings.json");
    assert_eq!(
        contract.session_start_context,
        "HOL Guard protection is active for this workspace."
    );
    assert_eq!(
        contract.pruned_events,
        ["PermissionDenied", "UserPromptSubmit"]
    );
    assert_eq!(contract.runtime_groups.len(), 5);
}

#[test]
fn malformed_contracts_are_refused_like_python() {
    let mutations: [fn(&mut Value); 9] = [
        |doc| doc["schema"] = json!("other"),
        |doc| doc["runtime_groups"][0]["timeout_seconds"] = json!(0),
        |doc| doc["runtime_groups"][0]["timeout_seconds"] = json!(true),
        |doc| {
            doc["runtime_groups"][1]
                .as_object_mut()
                .unwrap()
                .remove("matcher");
        },
        |doc| {
            let first = doc["runtime_groups"][0].clone();
            doc["runtime_groups"].as_array_mut().unwrap().push(first);
        },
        |doc| doc["markers"]["daemon_hook"] = json!(""),
        |doc| doc["session_start"]["matchers"] = json!("startup"),
        |doc| {
            doc.as_object_mut().unwrap().remove("bridge_config");
        },
        |doc| doc["runtime_groups"][0]["timeout_seconds"] = json!(30.5),
    ];
    for mutate in mutations {
        let mut document: Value = serde_json::from_str(CONTRACT_TEXT).unwrap();
        mutate(&mut document);
        let error = parse_contract(&document).unwrap_err();
        assert!(
            error.starts_with("claude_hook_groups_contract_invalid"),
            "{error}"
        );
    }
}

#[test]
fn bridge_config_text_is_the_python_argument_byte_for_byte() {
    let fixture = fixture();
    let text = bridge_config_text(&contract().unwrap(), &template(&fixture), url(&fixture));
    let installed = fixture["settings"]["hooks"]["Stop"][0]["hooks"][0]["args"][2].clone();
    assert_eq!(text.as_deref(), installed.as_str());
    assert!(text.unwrap().contains("雪"));
}

#[test]
fn bridge_config_refuses_templates_it_cannot_reproduce() {
    let fixture = fixture();
    let contract = contract().unwrap();
    let mut with_url = template(&fixture);
    with_url.bridge_config.insert(
        "fallback_daemon_url".to_owned(),
        json!("http://127.0.0.1:1"),
    );
    let mut unknown = template(&fixture);
    unknown.bridge_config.insert("extra".to_owned(), json!("x"));
    let mut missing = template(&fixture);
    missing.bridge_config.remove("query");
    let mut number = template(&fixture);
    number.bridge_config.insert("query".to_owned(), json!(1));
    for template in [with_url, unknown, missing, number] {
        assert_eq!(
            bridge_config_text(&contract, &template, url(&fixture)),
            None
        );
    }
}

#[test]
fn python_written_settings_are_current() {
    assert!(current_after(|_| {}));
}

#[test]
fn non_guard_entries_are_ignored() {
    assert!(current_after(|settings| {
        let user = json!({"type": "command", "command": "/usr/bin/env", "args": [], "timeout": 1});
        for event in ["PreToolUse", "Stop", "PermissionDenied", "SessionStart"] {
            let entries = &mut settings["hooks"][event];
            if entries.is_null() {
                *entries = json!([]);
            }
            let group = json!({"matcher": "Bash", "hooks": [user.clone()]});
            entries.as_array_mut().unwrap().push(group);
        }
        settings["hooks"]["PostToolUse"]
            .as_array_mut()
            .unwrap()
            .push(json!("junk"));
        settings["model"] = json!("another");
    }));
}

#[test]
fn every_kind_of_drift_is_not_current() {
    let drifts: [fn(&mut Value); 12] = [
        |s| guard_handler(s, "PreToolUse")["timeout"] = json!(31),
        |s| guard_handler(s, "PreToolUse")["timeout"] = json!(30.0),
        |s| {
            guard_handler(s, "PreToolUse")
                .as_object_mut()
                .unwrap()
                .remove("statusMessage");
        },
        |s| guard_handler(s, "PostToolUse")["statusMessage"] = json!("extra"),
        |s| guard_handler(s, "Notification")["args"][2] = json!("{}"),
        |s| guard_handler(s, "Stop")["command"] = json!("/other/runtime"),
        |s| s["hooks"]["PreToolUse"][0]["matcher"] = json!("Bash"),
        |s| s["hooks"]["Stop"][0]["matcher"] = json!("*"),
        |s| {
            s["hooks"]
                .as_object_mut()
                .unwrap()
                .remove("PermissionRequest");
        },
        |s| {
            let duplicate = s["hooks"]["Stop"][0].clone();
            s["hooks"]["Stop"].as_array_mut().unwrap().push(duplicate);
        },
        |s| {
            let stale = s["hooks"]["Stop"][0].clone();
            s["hooks"]["UserPromptSubmit"]
                .as_array_mut()
                .unwrap()
                .push(stale);
        },
        |s| {
            let flat = guard_handler(s, "Stop").clone();
            s["hooks"]["Stop"] = json!([flat]);
        },
    ];
    for (index, drift) in drifts.into_iter().enumerate() {
        assert!(!current_after(drift), "drift {index} was called current");
    }
}

#[test]
fn unreadable_documents_are_not_current() {
    assert!(!current_after(|s| s["hooks"] = json!([])));
    assert!(!current_after(|s| {
        s.as_object_mut().unwrap().remove("hooks");
    }));
    assert!(!current_after(|s| {
        guard_handler(s, "Stop")["type"] = json!(["command"]);
    }));
    assert!(!current_after(|s| {
        s["hooks"]["PreToolUse"][0]["hooks"]
            .as_array_mut()
            .unwrap()
            .push(json!({"type": {"x": 1}}));
    }));
    let fixture = fixture();
    let mut empty = template(&fixture);
    empty.command.clear();
    assert!(!settings_current(
        &contract().unwrap(),
        &fixture["settings"],
        &empty,
        url(&fixture)
    ));
    assert!(!settings_current(
        &contract().unwrap(),
        &fixture["settings"],
        &template(&fixture),
        "http://127.0.0.1:1"
    ));
}

#[test]
fn guard_markers_are_recognized_like_python() {
    let contract = contract().unwrap();
    for command in [
        "x HOL_GUARD_CLAUDE_DAEMON_HOOK",
        "HOL_GUARD_CLAUDE_SESSION_START_HOOK",
        "python -m codex_plugin_scanner.cli guard hook",
        "codex_plugin_scanner.cli', 'guard', 'hook'",
        "ensure_guard_daemon(x) HOL Guard protection is active for this workspace.",
    ] {
        assert!(is_guard_command(&contract, command), "{command}");
    }
    for command in [
        "codex_plugin_scanner.cli scan",
        "ensure_guard_daemon(x)",
        "",
    ] {
        assert!(!is_guard_command(&contract, command), "{command}");
    }
    let http = json!({"type": "http", "url": "http://127.0.0.1:9/v1/hooks/claude-code"});
    assert_eq!(is_guard_handler(&contract, &http), Ok(true));
    let remote = json!({"type": "http", "url": "http://10.0.0.1:9/v1/hooks/claude-code"});
    assert_eq!(is_guard_handler(&contract, &remote), Ok(false));
}
