//! Claude Code through the `harness_adapter` kind, answering its `facts`
//! reply the way the Python glue does.

use std::fs;

use serde_json::{json, Map, Value};

use super::{after, dispatch, shim, Home};

#[path = "tests_claude_render.rs"]
mod render;
#[path = "tests_claude_round_trip.rs"]
mod round_trip;

fn facts() -> String {
    json!({
        "daemon_url": "http://127.0.0.1:4781",
        "query_extras": [["runtime-harness", "cursor"], ["workspace", "/cursor/project"]],
    })
    .to_string()
}

const RUNTIME: &str = "/g/hol-guard-runtime";

/// The caller stamp, whose native runtime is `bridge` or absent.
fn stamped(frozen: bool, bridge: Option<&str>) -> Value {
    let mut stamp = super::caller(frozen);
    stamp["native_runtime"] = match bridge {
        None => Value::Null,
        Some(path) => {
            let mut runtime = stamp["native_runtime"].clone();
            runtime["path"] = json!(path);
            runtime
        }
    };
    stamp
}

#[test]
fn install_without_a_native_runtime_asks_for_repair() {
    let home = Home::new();
    for frozen in [false, true] {
        let answer = run(
            &home,
            "prepare_install",
            json!({"shim": shim(), "caller": stamped(frozen, None)}),
            &facts(),
        );
        assert_eq!(
            answer["runtime_error"],
            crate::harness_adapter::claude_argv::RUNTIME_MISSING,
            "{frozen}"
        );
    }
}

fn ask(home: &Home, op: &str, fields: &Map<String, Value>) -> Value {
    let mut request =
        json!({"harness": "claude-code", "op": op, "context": home.context(json!({"PATH": ""}))});
    for (key, value) in fields {
        // The calling process is stamped into the context, not the request.
        if key == "caller" {
            request["context"]["caller"] = value.clone();
        } else if key == "env" {
            request["context"]["env"] = value.clone();
        } else {
            request[key] = value.clone();
        }
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
    installed_as(home, bridge, false)
}

fn installed_as(home: &Home, bridge: Option<&str>, frozen: bool) -> Value {
    let caller = match (frozen, bridge) {
        // A frozen caller names the durable copy of a runtime that exists.
        (true, Some(_)) => super::frozen_with_runtime(home).0,
        _ => stamped(frozen, bridge),
    };
    let answer = run(
        home,
        "prepare_install",
        json!({"shim": shim(), "caller": caller}),
        &facts(),
    );
    serde_json::from_str(&after(&answer["files"][0])).unwrap()
}

fn pre_tool_config(payload: &Value) -> Value {
    let args = &payload["hooks"]["PreToolUse"][0]["hooks"][0]["args"];
    serde_json::from_str(args[2].as_str().unwrap()).unwrap()
}

#[test]
fn a_frozen_bridge_recovers_its_daemon_through_the_frozen_launcher() {
    let home = Home::new();
    let payload = installed_as(&home, Some("/rt/hol-guard-runtime"), true);
    let recovery = pre_tool_config(&payload)["recovery_command"].clone();
    assert_eq!(recovery[0], "/g/bin/hol-guard-core");
    assert_eq!(recovery[1], "--_hol-guard-codex-daemon-recover");
    let binding: Value = serde_json::from_str(recovery[2].as_str().unwrap()).unwrap();
    assert!(binding["guard_home"].is_string() && binding["home_dir"].is_string());
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
    let recovery = config["recovery_command"].as_array().unwrap();
    assert_eq!(recovery[..3], ["/py", "-I", "-c"]);
    assert!(recovery[3]
        .as_str()
        .unwrap()
        .contains("schedule_guard_daemon_recovery"));
    // Cursor markers in the installer's environment stay out of the hook.
    let query = config["query"].as_str().unwrap();
    assert!(query.starts_with("guard-home="), "{query}");
    assert!(!query.contains("runtime-harness"), "{query}");
    assert!(!query.contains("cursor"), "{query}");
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
    let payload = installed(&home, Some(RUNTIME));
    assert_eq!(payload["theme"], "dark");
    let pre = payload["hooks"]["PreToolUse"].as_array().unwrap();
    assert_eq!(pre[0]["hooks"], json!([user]));
    assert_eq!(pre[1]["hooks"][0]["command"], RUNTIME);
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
    let facts = facts();
    let argv = |which: &str| {
        let fields = json!({"which": which, "caller": stamped(true, None)});
        run(&home, "argv", fields, &facts)["argv"].clone()
    };
    assert_eq!(argv("hook")[0], "/g/bin/hol-guard");
    assert_eq!(argv("hook")[1], "hook");
    let session = argv("session_start");
    assert_eq!(session[1], "__guard-claude-hook");
    assert_eq!(session[2], "HOL_GUARD_CLAUDE_SESSION_START_HOOK");
    assert_eq!(session.as_array().unwrap().len(), 5);
}

#[test]
fn source_checkout_argv_imports_from_the_package_root() {
    let home = Home::new();
    let source = facts();
    let caller = stamped(false, None);
    let hook = run(
        &home,
        "argv",
        json!({"which": "hook", "caller": caller}),
        &source,
    )["argv"]
        .clone();
    assert_eq!(hook[0], "/py");
    assert!(hook[2]
        .as_str()
        .unwrap()
        .contains("sys.path.insert(0, '/opt/guard/site')"));
    let session = run(
        &home,
        "argv",
        json!({"which": "python_session_start", "caller": caller}),
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
    let payload = installed(&home, Some(RUNTIME));
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
    assert_eq!(cleaned["hooks"].get("PreToolUse"), None);
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
    let payload = installed(&home, Some(RUNTIME));
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

#[test]
fn refresh_writes_the_settings_it_rewrote() {
    let home = Home::new();
    let path = settings(&home);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, r#"{"model": "kept", "hooks": {}}"#).unwrap();
    let answer = run(
        &home,
        "refresh",
        json!({"caller": stamped(false, Some(RUNTIME))}),
        &facts(),
    );
    let text = answer["text"].as_str().unwrap();
    assert_eq!(fs::read_to_string(&path).unwrap(), text);
    let written: Value = serde_json::from_str(text).unwrap();
    assert_eq!(written["model"], "kept");
    assert!(written["hooks"]["SessionStart"].is_array());
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
    // The same command as the shell that will run it, so the caller shows it as is.
    let words: Vec<String> = answer["rollback"]["command"]
        .as_array()
        .unwrap()
        .iter()
        .map(|word| {
            super::super::claude_install_target::shell_word(word.as_str().unwrap(), cfg!(windows))
        })
        .collect();
    assert_eq!(answer["rollback"]["command_text"], json!(words.join(" ")));
    assert_eq!(
        answer["rollback"]["shell"],
        json!(if cfg!(windows) { "powershell" } else { "sh" })
    );
    assert_eq!(answer["hook_overrides"], json!([]));
    assert!(!workspace.exists());
}

#[test]
fn install_target_names_the_session_modes_guard_does_not_cover() {
    let home = Home::new();
    let answer = target(&home, None, json!({"PATH": ""}));
    let text = answer["text"].as_str().unwrap();
    for mode in ["--bare", "leave out `user`", "claude --bg", "not qualified"] {
        assert!(text.contains(mode), "install output omits {mode}");
    }
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
    let answer = run(&home, "prepare_install", json!({"shim": shim()}), &facts());
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
