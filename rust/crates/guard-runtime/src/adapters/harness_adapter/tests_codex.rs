//! Codex through the `harness_adapter` kind: the ops `codex.py` asks, each
//! with the fields the Python glue sends.

use std::fs;

use serde_json::{json, Value};

use super::{after, Home};

const SHELL_BEGIN: &str = "# >>> HOL Guard Codex shell guard >>>";
const SHELL_END: &str = "# <<< HOL Guard Codex shell guard <<<";
const PROXY_ARGS: [&str; 5] = [
    "-m",
    "codex_plugin_scanner.cli",
    "guard",
    "codex-mcp-proxy",
    "--server",
];

fn ask(home: &Home, op: &str, extra: Value) -> Value {
    home.ask("codex", op, extra)
}

fn group(command: &str, timeout: i64) -> Value {
    json!({"matcher": "Bash", "hooks": [{"type": "command", "command": command, "timeout": timeout}]})
}

fn config_with(hooks: &Value) -> String {
    json!({"features": {"hooks": true}, "hooks": hooks}).to_string()
}

fn argv_fields(home: &Home, frozen: bool) -> Value {
    json!({
        "home_is_current": false,
        "runtime_guard_home": home.guard(),
        "workspace_explicit": false,
        "python": "/py",
        "frozen": frozen,
        "package_root": "/opt/guard/site",
        "bridge": "/g/bridge.py",
        "native_bridge": "/g/hol-guard-runtime",
        "manifest_path": "/g/manifest.json",
        "long_timeout": 85,
    })
}

#[test]
fn argv_wraps_the_bridge_and_derives_its_launch_commands() {
    let home = Home::new();
    let answer = ask(&home, "argv", argv_fields(&home, false));
    let argv = answer["argv"].as_array().unwrap();
    assert_eq!(
        argv[..5],
        [
            json!("/g/hol-guard-runtime"),
            json!("codex-hook-bridge"),
            json!("/py"),
            json!("-I"),
            json!("/g/bridge.py"),
        ]
    );
    let config: Value = serde_json::from_str(argv[5].as_str().unwrap()).unwrap();
    assert_eq!(config["hook_timeouts"]["PreToolUse"], 85);
    assert_eq!(config["hook_timeouts"]["PermissionRequest"], 30);
    let fallback = answer["fallback"].as_array().unwrap();
    assert_eq!(config["fallback_command"], answer["fallback"]);
    assert_eq!(fallback[..3], [json!("/py"), json!("-I"), json!("-c")]);
    assert!(fallback[3]
        .as_str()
        .unwrap()
        .contains("from codex_plugin_scanner.cli import main"));
    assert_eq!(
        fallback[4..8],
        [
            json!("guard"),
            json!("hook"),
            json!("--harness"),
            json!("codex")
        ]
    );
    assert!(fallback.contains(&json!("--home")));
    let start = answer["start"].as_array().unwrap();
    assert_eq!(config["start_command"], answer["start"]);
    assert!(start[3]
        .as_str()
        .unwrap()
        .contains("schedule_guard_daemon_recovery"));
}

#[test]
fn a_frozen_guard_is_its_own_interpreter_for_every_launch() {
    let home = Home::new();
    let answer = ask(&home, "argv", argv_fields(&home, true));
    let argv = answer["argv"].as_array().unwrap();
    assert_eq!(
        argv[2..4],
        [json!("/py"), json!("--_hol-guard-codex-bridge")]
    );
    assert_eq!(argv.len(), 5);
    let fallback = answer["fallback"].as_array().unwrap();
    assert_eq!(
        fallback[..4],
        [
            json!("/py"),
            json!("hook"),
            json!("--harness"),
            json!("codex")
        ]
    );
    let start = answer["start"].as_array().unwrap();
    assert_eq!(
        start[..2],
        [json!("/py"), json!("--_hol-guard-codex-daemon-recover")]
    );
    let payload: Value = serde_json::from_str(start[2].as_str().unwrap()).unwrap();
    assert!(payload["guard_home"].is_string() && payload["home_dir"].is_string());
}

#[test]
fn groups_register_every_event_with_one_bound_handler() {
    let home = Home::new();
    let answer = ask(
        &home,
        "groups",
        json!({"argv": ["/py", "-I"], "command": "/py -I", "env": "{}", "long_timeout": 85}),
    );
    let groups: Value = serde_json::from_str(answer["groups"].as_str().unwrap()).unwrap();
    let mut events: Vec<&String> = groups.as_object().unwrap().keys().collect();
    events.sort();
    assert_eq!(
        events,
        [
            "PermissionRequest",
            "PostToolUse",
            "PreToolUse",
            "UserPromptSubmit"
        ]
    );
    assert_eq!(groups["PostToolUse"]["matcher"], "Bash|Read|mcp__.*");
    assert!(groups["UserPromptSubmit"].get("matcher").is_none());
    let bindings: Value = serde_json::from_str(answer["bindings"].as_str().unwrap()).unwrap();
    assert_eq!(
        bindings[0]["handler_id"],
        "codex:PreToolUse:guard-handler-v1"
    );
    assert_eq!(bindings[0]["handler"]["timeout"], 85);
}

#[test]
fn doctor_status_separates_leftover_config_from_a_broken_setup() {
    let home = Home::new();
    let missing = json!(["Codex command is not available on PATH"]);
    let other = json!(["Codex hook manifest is invalid"]);
    let status = |status: &str, base: &str, warnings: &Value| {
        ask(
            &home,
            "doctor_status",
            json!({"status": status, "base_status": base, "warnings": warnings}),
        )["status"]
            .clone()
    };
    assert_eq!(status("not_found", "not_found", &other), "broken");
    assert_eq!(status("not_found", "not_found", &missing), "not_found");
    assert_eq!(status("broken", "not_found", &missing), "not_found");
    assert_eq!(status("broken", "installed", &missing), "broken");
}

#[test]
fn migrate_appends_new_groups_once_and_refuses_a_conflict() {
    let home = Home::new();
    let config = config_with(&json!({"PreToolUse": [group("audit", 5)]}));
    let hooks = json!({"PreToolUse": [group("audit", 5), group("lint", 5)]}).to_string();
    let answer = ask(&home, "migrate", json!({"config": config, "hooks": hooks}));
    assert_eq!(answer["changed"], true);
    let merged: Value = serde_json::from_str(answer["config"].as_str().unwrap()).unwrap();
    assert_eq!(merged["hooks"]["PreToolUse"].as_array().unwrap().len(), 2);

    let again = ask(
        &home,
        "migrate",
        json!({"config": answer["config"], "hooks": hooks}),
    );
    assert_eq!(again["changed"], false);

    let conflict = json!({"PreToolUse": [group("audit", 9)]}).to_string();
    let refused = ask(
        &home,
        "migrate",
        json!({"config": config, "hooks": conflict}),
    );
    let message = refused["runtime_error"].as_str().unwrap();
    assert!(message.starts_with("codex_hook_migration_conflict"));
}

#[test]
fn readback_and_subset_refuse_a_lost_group() {
    let home = Home::new();
    let both = config_with(&json!({"PreToolUse": [group("audit", 5), group("lint", 5)]}));
    let one = config_with(&json!({"PreToolUse": [group("audit", 5)]}));
    let kept = ask(
        &home,
        "readback",
        json!({"expected": both, "actual": both, "source_path": "/c"}),
    );
    assert_eq!(kept, json!({}));
    let lost = ask(
        &home,
        "readback",
        json!({"expected": both, "actual": one, "source_path": "/c"}),
    );
    assert!(lost["runtime_error"]
        .as_str()
        .unwrap()
        .starts_with("codex_hook_migration_readback_mismatch"));
    assert_eq!(
        ask(&home, "subset", json!({"expected": one, "actual": both})),
        json!({})
    );
    let missing = ask(
        &home,
        "subset",
        json!({"expected": both, "actual": one, "hooks_path": "/h", "config_path": "/c"}),
    );
    assert!(missing["runtime_error"].as_str().unwrap().contains("/h"));
}

#[test]
fn alternate_cleanup_drops_guard_entries_and_the_idle_hook_feature() {
    let home = Home::new();
    let payload = json!({
        "features": {"hooks": true},
        "hooks": {"PreToolUse": [group("guard", 5)]},
        "mcp_servers": {
            "managed": {"command": "npx", "args": ["server"]},
            "user": {"command": "npx", "args": ["mine"]},
        },
    })
    .to_string();
    let answer = ask(
        &home,
        "alternate_cleanup",
        json!({
            "payload": payload,
            "remove_hooks": true,
            "legacy": {"removed": true, "cleaned": "{}"},
            "managed_server_names": ["managed"],
        }),
    );
    assert_eq!(answer["changed"], true);
    assert_eq!(answer["hooks_changed"], true);
    let rendered: Value = serde_json::from_str(answer["rendered"].as_str().unwrap()).unwrap();
    assert_eq!(
        rendered,
        json!({"mcp_servers": {"user": {"command": "npx", "args": ["mine"]}}})
    );
}

#[test]
fn managed_mcp_asks_for_each_proxy_launch_then_rewrites_it() {
    let home = Home::new();
    let payload =
        json!({"mcp_servers": {"p": {"command": "/old/python", "args": PROXY_ARGS}}}).to_string();
    let fields =
        json!({"payload": payload, "servers": [{"name": "new", "entry": "{\"command\":\"x\"}"}]});
    let reply = ask(&home, "managed_mcp", fields.clone());
    assert_eq!(reply["reply"]["relaunch"]["p"], json!(PROXY_ARGS));

    let mut answered = fields;
    answered["relaunch"] = json!({"p": ["/new/python", PROXY_ARGS]});
    let answer = ask(&home, "managed_mcp", answered);
    assert_eq!(answer["migrated"], json!(["p"]));
    let rendered: Value = serde_json::from_str(answer["rendered"].as_str().unwrap()).unwrap();
    assert_eq!(rendered["mcp_servers"]["p"]["command"], "/new/python");
    assert_eq!(rendered["mcp_servers"]["new"], json!({"command": "x"}));
}

#[test]
fn shell_cleanup_removes_only_the_guard_block() {
    let home = Home::new();
    let zshenv = home.home().join(".zshenv");
    fs::write(
        &zshenv,
        format!("export A=1\n{SHELL_BEGIN}\nlegacy\n{SHELL_END}\nexport B=2\n"),
    )
    .unwrap();
    let answer = ask(&home, "shell_cleanup", json!({}));
    let files = answer["files"].as_array().unwrap();
    let change = files
        .iter()
        .find(|change| change["path"].as_str().unwrap().ends_with(".zshenv"))
        .unwrap();
    assert_eq!(after(change), "export A=1\nexport B=2\n");
    assert!(files
        .iter()
        .filter(|other| other["path"] != change["path"])
        .all(|other| other["before"].is_null()));
}

#[test]
fn managed_mcp_leaves_a_workspace_entry_shadowing_a_global_server() {
    let home = Home::new();
    let workspace = json!({"mcp_servers": {"shared": {"command": "mine"}}}).to_string();
    let entry = "{\"command\":\"x\"}";
    let servers = json!([
        {"name": "shared", "source_scope": "global", "entry": entry},
        {"name": "project", "source_scope": "project", "entry": entry},
    ]);
    let rendered = |workspace_payload: Value| {
        let answer = ask(
            &home,
            "managed_mcp",
            json!({"payload": "{}", "workspace_payload": workspace_payload, "servers": servers}),
        );
        let rendered: Value = serde_json::from_str(answer["rendered"].as_str().unwrap()).unwrap();
        rendered["mcp_servers"].clone()
    };
    let shadowed = rendered(json!(workspace));
    assert!(shadowed.get("shared").is_none());
    assert_eq!(shadowed["project"], json!({"command": "x"}));
    assert_eq!(rendered(Value::Null)["shared"], json!({"command": "x"}));
}
