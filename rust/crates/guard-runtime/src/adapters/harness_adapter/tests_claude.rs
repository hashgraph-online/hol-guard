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

fn target(home: &Home, workspace: Option<&std::path::Path>, env: Value) -> Value {
    let mut context = home.context(env);
    context["workspace"] = json!(workspace);
    dispatch(&json!({"harness": "claude-code", "op": "install_target", "context": context}))
        .unwrap()
}

#[test]
fn install_target_names_the_user_file_and_never_a_project_file() {
    let home = Home::new();
    let workspace = home.root.join("project");
    let answer = target(&home, Some(&workspace), json!({"PATH": ""}));
    assert_eq!(answer["scope"], "user");
    assert_eq!(answer["settings_path"], json!(settings(&home)));
    assert!(answer["workspace_note"]
        .as_str()
        .unwrap()
        .contains("does not install into"));
    let scopes: Vec<_> = answer["precedence"]
        .as_array()
        .unwrap()
        .iter()
        .map(|layer| (layer["scope"].clone(), layer["guard_writes"].clone()))
        .collect();
    assert_eq!(
        scopes,
        vec![
            (json!("managed"), json!(false)),
            (json!("project_local"), json!(false)),
            (json!("project"), json!(false)),
            (json!("user"), json!(true)),
        ]
    );
    assert_eq!(
        answer["rollback"]["command"],
        json!([
            "hol-guard",
            "uninstall",
            "claude-code",
            "--guard-home",
            home.guard()
        ])
    );
    assert_eq!(answer["hook_overrides"], json!([]));
    assert!(!workspace.exists());
}

#[test]
fn install_target_reports_hooks_turned_off_by_a_project_file() {
    let home = Home::new();
    let workspace = home.root.join("project");
    fs::create_dir_all(workspace.join(".claude")).unwrap();
    fs::write(
        workspace.join(".claude/settings.local.json"),
        r#"{"disableAllHooks": true}"#,
    )
    .unwrap();
    fs::write(workspace.join(".claude/settings.json"), "not json").unwrap();
    let answer = target(&home, Some(&workspace), json!({"PATH": ""}));
    let overrides = answer["hook_overrides"].as_array().unwrap();
    assert_eq!(overrides.len(), 1);
    assert_eq!(overrides[0]["code"], "disable_all_hooks");
    assert_eq!(overrides[0]["scope"], "project_local");
}

#[test]
fn install_target_reports_a_claude_config_dir_elsewhere() {
    let home = Home::new();
    let elsewhere = home.root.join("other-claude");
    let answer = target(
        &home,
        None,
        json!({"PATH": "", "CLAUDE_CONFIG_DIR": elsewhere}),
    );
    assert_eq!(answer["hook_overrides"][0]["code"], "config_dir_elsewhere");
    let same = target(
        &home,
        None,
        json!({"PATH": "", "CLAUDE_CONFIG_DIR": home.home().join(".claude")}),
    );
    assert_eq!(same["hook_overrides"], json!([]));
}

#[cfg(unix)]
#[test]
fn install_target_follows_a_linked_claude_config_dir() {
    let home = Home::new();
    let claude = home.home().join(".claude");
    std::fs::create_dir_all(&claude).unwrap();
    let link = home.root.join("linked-claude");
    std::os::unix::fs::symlink(&claude, &link).unwrap();
    let answer = target(&home, None, json!({"PATH": "", "CLAUDE_CONFIG_DIR": link}));
    assert_eq!(answer["hook_overrides"], json!([]));
}

#[test]
fn install_target_undo_names_the_home_the_install_used() {
    let home = Home::new();
    let mut context = home.context(json!({"PATH": ""}));
    context["user_home"] = json!(home.root.join("someone-else"));
    context["guard_home"] = json!(home.root.join("someone-else").join(".hol-guard"));
    let answer =
        dispatch(&json!({"harness": "claude-code", "op": "install_target", "context": context}))
            .unwrap();
    assert_eq!(
        answer["rollback"]["command"],
        json!([
            "hol-guard",
            "uninstall",
            "claude-code",
            "--home",
            home.home(),
            "--guard-home",
            home.root.join("someone-else").join(".hol-guard")
        ])
    );
    // With --home, the CLI already takes that directory as the Guard home.
    context["guard_home"] = json!(home.home());
    let implied =
        dispatch(&json!({"harness": "claude-code", "op": "install_target", "context": context}))
            .unwrap();
    assert_eq!(
        implied["rollback"]["command"],
        json!([
            "hol-guard",
            "uninstall",
            "claude-code",
            "--home",
            home.home()
        ])
    );
}

#[test]
fn a_copied_undo_quotes_paths_for_the_shell_that_runs_it() {
    use super::super::claude_install_target::shell_word;
    assert_eq!(shell_word("/tmp/plain", false), "/tmp/plain");
    assert_eq!(shell_word("/tmp/Guard State", false), "'/tmp/Guard State'");
    assert_eq!(shell_word("/tmp/it's", false), "'/tmp/it'\\''s'");
    assert_eq!(shell_word(r"C:\Guard", true), r"C:\Guard");
    assert_eq!(shell_word(r"C:\Guard State", true), r"'C:\Guard State'");
    // PowerShell expands `$` and backticks inside double quotes, so a Windows
    // path goes in single quotes, with a single quote doubled.
    assert_eq!(shell_word(r"C:\Guard $cache", true), r"'C:\Guard $cache'");
    assert_eq!(shell_word(r"C:\it's", true), r"'C:\it''s'");
    assert_eq!(
        shell_word("C:\\Users\\O\u{2019}Brien", true),
        "'C:\\Users\\O\u{2019}\u{2019}Brien'"
    );
    assert_eq!(shell_word(r"C:\Guard&State", true), r"'C:\Guard&State'");
    assert_eq!(shell_word(r"C:\Guard", false), r"'C:\Guard'");
}

#[test]
fn install_target_uses_the_highest_precedence_disable_all_hooks() {
    let home = Home::new();
    let workspace = home.root.join("project");
    fs::create_dir_all(workspace.join(".claude")).unwrap();
    fs::create_dir_all(home.home().join(".claude")).unwrap();
    fs::write(settings(&home), r#"{"disableAllHooks": true}"#).unwrap();
    fs::write(
        workspace.join(".claude/settings.json"),
        r#"{"disableAllHooks": false}"#,
    )
    .unwrap();
    let answer = target(&home, Some(&workspace), json!({"PATH": ""}));
    assert_eq!(answer["hook_overrides"], json!([]));
    let user_only = target(&home, None, json!({"PATH": ""}));
    assert_eq!(user_only["hook_overrides"][0]["scope"], "user");
}

#[test]
fn install_target_reads_a_fixture_managed_policy_only() {
    let home = Home::new();
    fs::write(
        home.root.join("managed-settings.json"),
        r#"{"allowManagedHooksOnly": true}"#,
    )
    .unwrap();
    let answer = target(&home, None, json!({"PATH": ""}));
    assert_eq!(answer["hook_overrides"][0]["code"], "managed_hooks_only");
}

#[cfg(unix)]
#[test]
fn install_target_does_not_read_a_device_or_an_oversized_settings_file() {
    let home = Home::new();
    let workspace = home.root.join("project");
    fs::create_dir_all(workspace.join(".claude")).unwrap();
    std::os::unix::fs::symlink("/dev/zero", workspace.join(".claude/settings.json")).unwrap();
    let mut big = br#"{"disableAllHooks": true, "pad": ""#.to_vec();
    big.resize(2 * 1024 * 1024, b' ');
    big.extend_from_slice(br#""}"#);
    fs::write(workspace.join(".claude/settings.local.json"), big).unwrap();
    let answer = target(&home, Some(&workspace), json!({"PATH": ""}));
    assert_eq!(answer["hook_overrides"], json!([]));
}

#[test]
fn install_notes_name_the_settings_file_and_the_rollback() {
    let home = Home::new();
    let answer = run(
        &home,
        "prepare_install",
        json!({"shim": shim()}),
        &facts(None, false),
    );
    let manifest: Value = serde_json::from_str(answer["manifest"].as_str().unwrap()).unwrap();
    // Compare decoded strings: JSON text would escape Windows backslashes.
    let notes: Vec<&str> = manifest["notes"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let written = format!("user settings at {}", settings(&home).display());
    assert!(
        notes.iter().any(|note| note.contains(&written)),
        "{notes:?}"
    );
    assert!(
        notes
            .iter()
            .any(|note| note.contains("hol-guard uninstall claude-code --guard-home")),
        "{notes:?}"
    );
}

/// Drop the empty hook lists uninstall leaves behind; they hold no user data.
fn without_empty_hook_lists(mut payload: Value) -> Value {
    if let Some(hooks) = payload.get_mut("hooks").and_then(Value::as_object_mut) {
        hooks.retain(|_, groups| groups.as_array().is_none_or(|list| !list.is_empty()));
    }
    payload
}

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
    fs::create_dir_all(settings(&home).parent().unwrap()).unwrap();
    fs::write(
        settings(&home),
        serde_json::to_string_pretty(&original).unwrap(),
    )
    .unwrap();
    let answer = run(
        &home,
        "prepare_install",
        json!({"shim": shim()}),
        &facts(None, false),
    );
    let with_guard = after(&answer["files"][0]);
    let installed: Value = serde_json::from_str(&with_guard).unwrap();
    assert_ne!(
        installed["hooks"]["SessionStart"],
        Value::Null,
        "install added nothing"
    );
    fs::write(settings(&home), &with_guard).unwrap();
    let answer = ask(&home, "prepare_uninstall", &Map::new());
    let cleaned: Value =
        serde_json::from_str(answer["writes"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(without_empty_hook_lists(cleaned), original);
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
        fields.insert("facts".into(), json!(facts(None, false)));
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
