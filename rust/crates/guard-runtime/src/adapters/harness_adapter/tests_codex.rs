//! Codex through the `harness_adapter` kind: the ops `codex.py` asks, each
//! with the fields the Python glue sends.

use std::fs;

use serde_json::{json, Value};

use super::{after, Home};

#[path = "tests_codex_alternate_plan.rs"]
mod alternate_plan;
#[path = "tests_codex_config_hooks.rs"]
mod config_hooks;
#[path = "tests_codex_install_request.rs"]
mod install_request;
#[path = "tests_codex_main_plan.rs"]
mod main_plan;
#[path = "tests_codex_migration.rs"]
mod migration;
#[path = "tests_codex_spec.rs"]
mod spec;
#[path = "tests_codex_uninstall.rs"]
mod uninstall;
#[path = "tests_codex_uninstall_config.rs"]
mod uninstall_config;

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
        "caller": if frozen { super::frozen_with_runtime(home).0 } else { super::caller(false) },
        "manifest_path": "/g/manifest.json",
        "long_timeout": 85,
    })
}

#[test]
fn argv_wraps_the_bridge_and_derives_its_launch_commands() {
    let home = Home::new();
    let answer = ask(&home, "argv", argv_fields(&home, false));
    let argv = answer["argv"].as_array().unwrap();
    assert_eq!(argv.len(), 3);
    assert_eq!(
        argv[..2],
        [json!("/g/hol-guard-runtime"), json!("codex-hook-bridge")]
    );
    let config: Value = serde_json::from_str(argv[2].as_str().unwrap()).unwrap();
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
fn argv_without_a_native_runtime_asks_for_repair() {
    let home = Home::new();
    for frozen in [false, true] {
        let mut fields = argv_fields(&home, frozen);
        fields["caller"]["native_runtime"] = Value::Null;
        let answer = ask(&home, "argv", fields);
        assert_eq!(
            answer["runtime_error"],
            crate::harness_adapter::claude_argv::RUNTIME_MISSING
        );
    }
}

#[test]
fn a_frozen_guard_is_its_own_interpreter_for_every_launch() {
    let home = Home::new();
    let answer = ask(&home, "argv", argv_fields(&home, true));
    let (_, copy) = super::frozen_with_runtime(&home);
    let argv = answer["argv"].as_array().unwrap();
    // A frozen Guard's bundled runtime vanishes with its process, so the
    // hook names the durable copy under the Guard home.
    assert_eq!(argv[..2], [json!(copy), json!("codex-hook-bridge")]);
    assert_eq!(argv.len(), 3);
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
        json!({"argv": ["/py", "-I"], "long_timeout": 85}),
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
    assert_eq!(bindings[0]["handler"]["command"], "/py -I");
}

#[test]
fn each_handler_pins_the_callers_package_and_codex_home() {
    let home = Home::new();
    let codex_home = home.home().join(".codex");
    let env_for = |frozen: bool| {
        let fields = json!({"argv": ["/py"], "long_timeout": 85, "caller": super::caller(frozen)});
        let answer = home.ask_env(
            "codex",
            "groups",
            fields,
            json!({"PATH": "", "HOL_GUARD_NATIVE": "1", "HOL_GUARD_TEST_MODE": ""}),
        );
        let groups: Value = serde_json::from_str(answer["groups"].as_str().unwrap()).unwrap();
        groups["PreToolUse"]["hooks"][0]["env"].clone()
    };
    assert_eq!(
        env_for(false),
        json!({"PYTHONPATH": "/opt/guard/site", "HOL_GUARD_NATIVE": "1", "CODEX_HOME": codex_home})
    );
    // A frozen build imports from its own archive, so it pins no package.
    assert_eq!(
        env_for(true),
        json!({"HOL_GUARD_NATIVE": "1", "CODEX_HOME": codex_home})
    );
}

#[cfg(unix)]
#[test]
fn a_posix_groups_command_is_shlex_joined() {
    let home = Home::new();
    let fields = json!({"argv": ["/a b/py", "-I"], "long_timeout": 85});
    let answer = ask(&home, "groups", fields);
    let groups: Value = serde_json::from_str(answer["groups"].as_str().unwrap()).unwrap();
    assert_eq!(groups["PreToolUse"]["hooks"][0]["command"], "'/a b/py' -I");
}

#[cfg(windows)]
#[test]
fn a_windows_groups_command_uses_the_short_names_it_is_given() {
    let home = Home::new();
    let mut fields = json!({"argv": ["C:\\Program Files\\py.exe", "-I"], "long_timeout": 85});
    fields["short_names"] =
        json!({"C:\\Program Files\\py.exe": ["C:\\PROGRA~1\\py.exe", "C:\\Program Files\\py.exe"]});
    let answer = ask(&home, "groups", fields);
    let groups: Value = serde_json::from_str(answer["groups"].as_str().unwrap()).unwrap();
    assert_eq!(
        groups["PreToolUse"]["hooks"][0]["command"],
        "C:\\PROGRA~1\\py.exe -I"
    );
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
    let status = "HOL Guard checking Bash command";
    let current = json!({
        "type": "command",
        "command": "/py -I /pkg/bridge.py '{\"a\":1}'",
        "statusMessage": status,
    });
    let payload = json!({
        "features": {"hooks": true},
        "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [current]}]},
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
            "managed_server_names": ["managed"],
            "expected": json!([{"event": "PreToolUse", "group": {"matcher": "Bash"}}]).to_string(),
            "argv": ["/py", "-I", "/pkg/bridge.py", "{\"a\":1}"],
            "legacy_argv": ["/old", "x"],
            "statuses": [status],
            "windows": false,
            "long_paths": {},
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
fn managed_mcp_rewrites_each_proxy_to_the_callers_launch() {
    let home = Home::new();
    let payload =
        json!({"mcp_servers": {"p": {"command": "/old/python", "args": PROXY_ARGS}}}).to_string();
    let fields =
        json!({"payload": payload, "servers": [{"name": "new", "entry": "{\"command\":\"x\"}"}]});
    let answer = ask(&home, "managed_mcp", fields);
    assert_eq!(answer["migrated"], json!(["p"]));
    let rendered: Value = serde_json::from_str(answer["rendered"].as_str().unwrap()).unwrap();
    // The stamp's runtime cannot relay, so the proxy keeps its Python launch.
    assert_eq!(rendered["mcp_servers"]["p"]["command"], "/py");
    assert_eq!(rendered["mcp_servers"]["p"]["args"], json!(PROXY_ARGS));
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

/// Every tool the PreToolUse rows of the Codex protection contract name.
fn contract_pre_tool_tools() -> Vec<String> {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../../../../src/codex_plugin_scanner/guard/contracts/harness-protection-contracts.v1.json"
    ))
    .expect("contract parses");
    let codex = contract["contracts"]
        .as_array()
        .and_then(|rows| rows.iter().find(|row| row["harness"] == "codex"))
        .expect("codex contract");
    codex["capability_events"]
        .as_array()
        .expect("rows")
        .iter()
        .filter(|row| row["event"] == "PreToolUse")
        .flat_map(|row| row["tools"].as_array().cloned().unwrap_or_default())
        .filter_map(|tool| tool.as_str().map(str::to_owned))
        .collect()
}

#[test]
fn every_codex_file_write_tool_is_a_contract_row_the_hook_matcher_sends() {
    let matcher = regex::Regex::new(super::super::codex::TOOL_MATCHER).expect("matcher");
    let tools = contract_pre_tool_tools();
    for tool in ["apply_patch", "Write", "Edit", "MultiEdit"] {
        assert!(tools.iter().any(|named| named == tool), "{tool} has no row");
    }
    for tool in &tools {
        let sample = tool
            .strip_suffix('*')
            .map_or(tool.clone(), |prefix| format!("{prefix}server__tool"));
        assert!(
            matcher.is_match(&sample),
            "{tool} is a row the matcher never sends"
        );
    }
    // Every matcher branch has a row, so the matcher cannot widen silently.
    for branch in super::super::codex::TOOL_MATCHER.split('|') {
        let named = branch
            .trim_start_matches('^')
            .trim_end_matches('$')
            .replace(".*", "*");
        assert!(tools.contains(&named), "matcher branch {branch} has no row");
    }
    assert!(!matcher.is_match("apply_patch_preview"));
}
