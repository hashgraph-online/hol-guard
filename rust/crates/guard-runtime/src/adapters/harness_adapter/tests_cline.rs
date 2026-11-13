//! Cline through the `harness_adapter` kind.

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};

use super::Home;

const MARKER: &str = "# HOL_GUARD_MANAGED_CLINE_HOOK_V1\n";

fn no_cli() -> Value {
    json!({"path": null, "output": ""})
}

fn write(path: &Path, text: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

fn hook_root(home: &Home) -> PathBuf {
    home.home().join("Documents/Cline/Hooks")
}

fn managed(home: &Home) -> PathBuf {
    home.guard().join("managed/cline")
}

fn hook_facts(home: &Home) -> Value {
    let runtime = home.root.join("native-runtime");
    fs::write(&runtime, b"").unwrap();
    json!({
        "python": true,
        "runtime": runtime,
        "hook_argv": ["guard", "hook"],
        "guard_cli": ["guard"],
        "identity": {"runtime": "python"},
    })
}

fn install_hooks(home: &Home) -> Value {
    home.ask(
        "cline",
        "install_transport",
        json!({"transport": "hooks", "frozen": false, "facts": hook_facts(home)}),
    )
}

#[test]
fn frozen_auto_install_plans_the_durable_plugin_with_hook_fallback() {
    let home = Home::new();
    let plan = home.ask(
        "cline",
        "install_plan",
        json!({"surface": "auto", "frozen": true, "cli": no_cli()}),
    );
    assert_eq!(plan["surface"], "auto");
    assert_eq!(plan["transport"], "plugin");
    assert_eq!(plan["fallback"], true);
    assert_eq!(plan["shim"], true);
    assert_eq!(plan["mcp"], true);
}

#[test]
fn editor_surface_means_hooks_and_unknown_surfaces_are_refused() {
    let home = Home::new();
    let plan = home.ask(
        "cline",
        "install_plan",
        json!({"surface": " Editor ", "frozen": false, "cli": no_cli()}),
    );
    assert_eq!(plan["surface"], "hooks");
    assert_eq!(plan["shim"], false);
    let refused = home.ask(
        "cline",
        "install_plan",
        json!({"surface": "bogus", "frozen": false, "cli": no_cli()}),
    );
    assert_eq!(refused["refusal"], "Unsupported Cline surface: bogus");
}

#[test]
fn frozen_hook_repair_is_a_runtime_error_the_install_can_report() {
    let home = Home::new();
    let answer = home.ask(
        "cline",
        "install_transport",
        json!({"transport": "hooks", "frozen": true, "facts": hook_facts(&home)}),
    );
    assert!(answer["runtime_error"]
        .as_str()
        .unwrap()
        .contains("managed plugin"));
}

#[test]
fn hook_install_never_overwrites_a_user_hook() {
    let home = Home::new();
    write(&hook_root(&home).join("PreToolUse"), "#!/bin/sh\nexit 0\n");
    let answer = install_hooks(&home);
    assert!(answer["runtime_error"]
        .as_str()
        .unwrap()
        .contains("user-owned PreToolUse hook"));
    assert_eq!(
        fs::read_to_string(hook_root(&home).join("PreToolUse")).unwrap(),
        "#!/bin/sh\nexit 0\n"
    );
}

#[test]
fn hook_install_replaces_legacy_workers_and_asks_for_the_canary() {
    let home = Home::new();
    let workers = managed(&home).join("hook-workers");
    write(&workers.join("PreToolUse.py"), MARKER);
    write(&workers.join("PostToolUse.py"), "print('user file')\n");
    write(&hook_root(&home).join("PreToolUse"), MARKER);
    let answer = install_hooks(&home);
    assert!(!workers.join("PreToolUse.py").exists());
    assert!(workers.join("PostToolUse.py").exists());
    let manifest = &answer["manifest"];
    let worker = manifest["managed_hook_workers"]["PreToolUse"]
        .as_str()
        .unwrap();
    assert_eq!(worker, workers.join("PreToolUse.json").to_str().unwrap());
    assert!(Path::new(worker).is_file());
    let canary = &answer["probe"]["canary"];
    let launcher = hook_root(&home).join("PreToolUse");
    assert_eq!(canary["argv"], json!([launcher]));
    let input: Value = serde_json::from_str(canary["input"].as_str().unwrap()).unwrap();
    assert_eq!(input["hookName"], "PreToolUse");
}

#[test]
fn a_failed_canary_removes_the_hooks_it_judged() {
    let home = Home::new();
    let installed = install_hooks(&home);
    let answer = home.ask(
        "cline",
        "confirm_transport",
        json!({
            "transport": "hooks",
            "manifest": installed["manifest"].to_string(),
            "canary": {"returncode": 1, "stdout": "", "error": null},
        }),
    );
    assert!(answer["runtime_error"]
        .as_str()
        .unwrap()
        .contains("bounded canary"));
    assert!(!hook_root(&home).join("PreToolUse").exists());
}

#[test]
fn a_passing_canary_confirms_hooks_and_finish_records_the_transport() {
    let home = Home::new();
    let installed = install_hooks(&home);
    let run = json!({"returncode": 0, "stdout": "{\"cancel\": false}\n", "error": null});
    let confirmed = home.ask(
        "cline",
        "confirm_transport",
        json!({
            "transport": "hooks",
            "manifest": installed["manifest"].to_string(),
            "canary": run,
        }),
    );
    assert_eq!(confirmed["synthetic_canary"], json!({"ok": true}));
    assert_eq!(confirmed["active_transport"], "hooks");
    assert_eq!(confirmed["previous_transport"], Value::Null);
    let finished = home.ask(
        "cline",
        "finish_install",
        json!({
            "surface": "hooks",
            "transport": "hooks",
            "transport_manifest": confirmed.to_string(),
            "shim": null,
            "mcp_install": null,
            "cli": no_cli(),
            "canary": run,
        }),
    );
    assert_eq!(finished["harness"], "cline");
    assert_eq!(finished["active_transport"], "hooks");
    assert_eq!(finished["native_hooks"]["installed"], true);
    let state: Value = serde_json::from_str(
        &fs::read_to_string(managed(&home).join("adapter-state.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(state["active_transport"], "hooks");
    assert_eq!(state["surface"], "hooks");

    let removed = home.ask("cline", "uninstall", json!({"surface": "hooks"}));
    assert_eq!(removed["manifest"]["native_hooks"]["complete"], true);
    assert_eq!(removed["remove_shim"], false);
    assert!(!hook_root(&home).join("PreToolUse").exists());
}

#[test]
fn a_user_hook_in_a_later_slot_leaves_no_launcher_behind() {
    let home = Home::new();
    write(&hook_root(&home).join("PostToolUse"), "#!/bin/sh\nexit 0\n");
    let answer = install_hooks(&home);
    assert!(answer["runtime_error"].is_string());
    assert!(!hook_root(&home).join("PreToolUse").exists());
}

#[test]
fn a_user_package_manifest_blocks_the_plugin_install() {
    let home = Home::new();
    let package = home.home().join(".cline/plugins/hol-guard/package.json");
    write(&package, "{\"name\": \"mine\"}\n");
    let answer = home.ask(
        "cline",
        "install_transport",
        json!({"transport": "plugin", "frozen": false, "facts": hook_facts(&home)}),
    );
    assert!(answer["runtime_error"]
        .as_str()
        .unwrap()
        .contains("user-owned"));
    assert_eq!(
        fs::read_to_string(&package).unwrap(),
        "{\"name\": \"mine\"}\n"
    );
}

#[test]
fn a_manifest_that_stops_loading_the_plugin_fails_integrity() {
    let home = Home::new();
    let answer = home.ask(
        "cline",
        "install_transport",
        json!({"transport": "plugin", "frozen": false, "facts": hook_facts(&home)}),
    );
    assert!(answer.get("runtime_error").is_none(), "{answer}");
    let integrity = |home: &Home| {
        let probe = home.ask("cline", "runtime_probe", json!({"cli": no_cli()}));
        probe["probe"]["plugin"]["integrity_ok"].clone()
    };
    assert_eq!(integrity(&home), true);
    let package = home.home().join(".cline/plugins/hol-guard/package.json");
    write(
        &package,
        "{\"name\": \"hol-guard-cline-plugin\", \"cline\": {\"plugins\": []}}\n",
    );
    assert_eq!(integrity(&home), false);
}

#[test]
fn a_state_path_outside_the_slots_is_never_run_or_removed() {
    let home = Home::new();
    let outside = home.root.join("outside/PreToolUse");
    write(&outside, MARKER);
    write(
        &managed(&home).join("native-hooks-state.json"),
        &json!({
            "paths": {"PreToolUse": outside},
            "sha256": {"PreToolUse": "attacker-controlled"},
        })
        .to_string(),
    );
    let probe = home.ask("cline", "runtime_probe", json!({"cli": no_cli()}));
    assert_eq!(probe["probe"]["native_hooks"]["installed"], false);
    let removed = home.ask("cline", "uninstall", json!({"surface": "hooks"}));
    let hooks = &removed["manifest"]["native_hooks"];
    assert_eq!(hooks["complete"], false);
    assert!(hooks["retained_modified_or_unowned"]
        .as_array()
        .unwrap()
        .contains(&json!(outside)));
    assert!(outside.exists());
}

#[test]
fn mcp_proxies_keep_remote_servers_and_restore_the_exact_text() {
    let home = Home::new();
    let settings = home
        .home()
        .join(".cline/data/settings/cline_mcp_settings.json");
    let original = "{\n  \"mcpServers\": {\n    \"local\": {\"command\": \"node\", \"args\": [\"server.js\"]},\n    \"remote\": {\"url\": \"https://example.invalid/mcp\"}\n  }\n}\n";
    write(&settings, original);
    let scan = home.ask("cline", "mcp_scan", json!({}));
    let found = &scan["candidates"][0];
    assert_eq!(found["managed"][0]["name"], "local");
    assert_eq!(found["remote"], json!(["remote"]));
    let replacements =
        json!({"local": {"command": "/py", "args": ["cline-mcp-proxy"], "type": "stdio"}});
    let mut entry = found.clone();
    entry["replacements"] = json!(replacements.to_string());
    let applied = home.ask(
        "cline",
        "mcp_apply",
        json!({"entries": json!([entry]).to_string()}),
    );
    assert_eq!(applied["managed_servers"], json!(["local"]));
    assert_eq!(applied["skipped_remote_servers"], json!(["remote"]));
    let managed: Value = serde_json::from_str(&fs::read_to_string(&settings).unwrap()).unwrap();
    assert_eq!(managed["mcpServers"]["local"]["command"], "/py");
    assert_eq!(
        managed["mcpServers"]["remote"],
        json!({"url": "https://example.invalid/mcp"})
    );

    let removed = home.ask("cline", "uninstall", json!({}));
    assert_eq!(removed["manifest"]["mcp"]["complete"], true);
    assert_eq!(removed["remove_shim"], true);
    assert_eq!(fs::read_to_string(&settings).unwrap(), original);
}

#[test]
fn two_spellings_of_one_settings_file_plan_it_once() {
    let home = Home::new();
    let settings = home
        .home()
        .join(".cline/data/settings/cline_mcp_settings.json");
    write(
        &settings,
        r#"{"mcpServers": {"local": {"command": "node", "args": []}}}"#,
    );
    fs::create_dir_all(home.home().join(".cline/settings")).unwrap();
    let alias = home
        .home()
        .join(".cline/settings/../data/settings/cline_mcp_settings.json");
    let scan = home.ask_env(
        "cline",
        "mcp_scan",
        json!({}),
        json!({"CLINE_MCP_SETTINGS_PATH": alias}),
    );
    assert_eq!(scan["candidates"].as_array().unwrap().len(), 1);
}

#[test]
fn a_changed_settings_file_is_not_rewritten_from_a_stale_scan() {
    let home = Home::new();
    let settings = home
        .home()
        .join(".cline/data/settings/cline_mcp_settings.json");
    write(
        &settings,
        r#"{"mcpServers": {"local": {"command": "node", "args": []}}}"#,
    );
    let scan = home.ask("cline", "mcp_scan", json!({}));
    let mut entry = scan["candidates"][0].clone();
    entry["replacements"] = json!(json!({"local": {"command": "/py"}}).to_string());
    write(&settings, r#"{"mcpServers": {}}"#);
    let answer = home.ask(
        "cline",
        "mcp_apply",
        json!({"entries": json!([entry]).to_string()}),
    );
    assert_eq!(answer["integrity"], "target_changed");
}

#[test]
fn diagnostic_warnings_name_duplicates_pending_proof_and_jetbrains() {
    let home = Home::new();
    let answer = home.ask(
        "cline",
        "diagnostic_warnings",
        json!({
            "warnings": ["seen"],
            "probe": {
                "duplicate_managed_transports": true,
                "active_transport": "plugin",
                "plugin": {"ready": false},
                "jetbrains_detected": true,
            },
        }),
    );
    let warnings = answer["warnings"].as_array().unwrap();
    assert_eq!(warnings.len(), 4);
    assert_eq!(warnings[0], "seen");
    let quiet = home.ask(
        "cline",
        "diagnostic_warnings",
        json!({"warnings": [], "probe": null}),
    );
    assert_eq!(quiet["warnings"], json!([]));
}

#[test]
fn the_cli_version_comes_from_its_output() {
    let home = Home::new();
    let cli = home.root.join("bin/cline");
    write(&cli, "");
    let probe = home.ask(
        "cline",
        "runtime_probe",
        json!({"cli": {"path": cli, "output": "cline 4.5.6\n"}}),
    );
    assert_eq!(probe["probe"]["cli_version"], "4.5.6");
    assert_eq!(probe["probe"]["hosts"], json!(["cli"]));
}
