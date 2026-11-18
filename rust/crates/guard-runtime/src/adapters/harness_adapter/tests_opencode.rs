//! OpenCode through the `harness_adapter` kind.

use std::fs;
use std::path::Path;

use serde_json::{json, Value};

use super::super::dispatch;
use super::{after, caller, frozen_with_runtime, shim, Home};

/// The plugin render arguments Python sends: the attested facts, with no
/// native bridge argv, which the native runtime builds from the caller stamp.
fn plugin() -> Value {
    let vectors: Value = serde_json::from_str(include_str!(
        "../../../testdata/opencode/plugin_render_vectors.json"
    ))
    .unwrap();
    let mut args = vectors["cases"][0]["args"].clone();
    args.as_object_mut().unwrap().remove("native_bridge_argv");
    args
}

fn global(home: &Home) -> std::path::PathBuf {
    home.home().join(".config/opencode")
}

fn write(path: &Path, text: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

fn apply(files: &[Value]) {
    for file in files {
        let path = Path::new(file["path"].as_str().unwrap());
        if file["after"].is_null() {
            let _ = fs::remove_file(path);
            continue;
        }
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, after(file)).unwrap();
    }
}

fn install(home: &Home) -> Value {
    home.ask(
        "opencode",
        "prepare_install",
        json!({"shim": shim(), "plugin": plugin()}),
    )
}

/// A source caller whose interpreter launches each managed proxy.
fn launch() -> Value {
    let mut stamp = caller(false);
    stamp["executable"] = json!("/py/bin/python");
    stamp
}

/// An install with managed servers, built from `stamp` and an environment
/// that sets the import path and one native binding.
fn install_with(home: &Home, stamp: Value) -> Value {
    // Python attests the same frozen state the caller stamp carries.
    let mut args = plugin();
    args["frozen"] = stamp["frozen"].clone();
    home.ask_env(
        "opencode",
        "prepare_install",
        json!({"shim": shim(), "plugin": args, "caller": stamp}),
        json!({"PATH": "", "PYTHONPATH": "/g/lib", "HOL_GUARD_NATIVE": "1"}),
    )
}

const SERVERS: &str = r#"{
  "mcp": {
    "files": {
      "type": "local",
      "command": ["npx", "files-server"],
      "environment": {"TOKEN": "abc", "PYTHONPATH": "/evil"}
    },
    "hosted": {"type": "remote", "url": "https://x.example/mcp"}
  }
}"#;

fn managed_config(home: &Home, answer: &Value) -> Value {
    let target = global(home).join("opencode.json");
    let files = answer["files"].as_array().unwrap();
    serde_json::from_str(&after(file(files, &target))).unwrap()
}

fn file<'a>(files: &'a [Value], path: &Path) -> &'a Value {
    files
        .iter()
        .find(|file| file["path"] == json!(path))
        .unwrap_or_else(|| panic!("no change at {}", path.display()))
}

#[test]
fn policy_path_is_the_global_root_config_without_a_workspace() {
    let home = Home::new();
    let answer = home.ask("opencode", "policy_path", json!({}));
    assert_eq!(answer["path"], json!(global(&home).join("opencode.json")));
}

#[test]
fn detect_reads_jsonc_comments_and_skips_empty_configs() {
    let home = Home::new();
    write(
        &global(&home).join("opencode.jsonc"),
        "{\n  // servers\n  \"mcp\": {\"files\": {\"type\": \"local\", \"command\": [\"npx\", \"files\"]}}\n}\n",
    );
    write(&global(&home).join("opencode.json"), "{}");
    let answer = home.ask("opencode", "detect", json!({}));
    assert!(answer.get("firewall").is_none());
    assert!(answer["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .any(|artifact| artifact["artifact_type"] == json!("mcp_server")));
    let paths = answer["config_paths"].as_array().unwrap();
    assert!(paths.contains(&json!(global(&home).join("opencode.jsonc"))));
    assert!(!paths.contains(&json!(global(&home).join("opencode.json"))));
}

#[test]
fn install_updates_the_root_config_and_backs_up_the_original() {
    let home = Home::new();
    let target = global(&home).join("opencode.json");
    write(&target, "{\"theme\": \"dark\"}");
    let answer = install(&home);
    let files = answer["files"].as_array().unwrap();
    let config: Value = serde_json::from_str(&after(file(files, &target))).unwrap();
    assert_eq!(config["theme"], "dark");
    assert_eq!(config["$schema"], "https://opencode.ai/config.json");
    assert_eq!(config["permission"]["bash"]["rm -rf *"], "deny");
    assert_eq!(file(files, &target)["after_mode"], json!(0o600));
    let backup = files
        .iter()
        .find(|file| file["path"].as_str().unwrap().ends_with(".backup.json"))
        .unwrap();
    let envelope: Value = serde_json::from_str(&after(backup)).unwrap();
    assert_eq!(
        envelope,
        json!({"existed": true, "content": "{\"theme\": \"dark\"}"})
    );
    let plugin = global(&home).join("plugins/hol-guard-pretool.ts");
    assert_eq!(file(files, &plugin)["after_mode"], json!(0o644));
    let manifest: Value = serde_json::from_str(answer["manifest"].as_str().unwrap()).unwrap();
    assert_eq!(manifest["active"], json!(true));
    assert_eq!(manifest["notes"][0], "shim note");
    assert_eq!(manifest["runtime_env_var"], "OPENCODE_CONFIG_CONTENT");
}

#[test]
fn install_reads_a_comment_ended_by_a_lone_carriage_return() {
    let home = Home::new();
    let target = global(&home).join("opencode.json");
    write(&target, "// note\r{\"theme\": \"dark\"}");
    let answer = install(&home);
    let files = answer["files"].as_array().unwrap();
    let config: Value = serde_json::from_str(&after(file(files, &target))).unwrap();
    assert_eq!(config["theme"], "dark");
}

#[test]
fn install_refuses_an_invalid_config() {
    let home = Home::new();
    write(&global(&home).join("opencode.json"), "{oops");
    let answer = install(&home);
    let refusal = answer["refusal"].as_str().unwrap();
    assert!(refusal.starts_with("Refusing to install with an invalid OpenCode config at "));
}

#[test]
fn uninstall_restores_the_backed_up_config_and_removes_the_plugins() {
    let home = Home::new();
    let target = global(&home).join("opencode.json");
    write(&target, "{\"theme\": \"dark\"}");
    apply(install(&home)["files"].as_array().unwrap());
    let plan = home.ask("opencode", "prepare_uninstall", json!({}));
    assert_eq!(plan["writes"][0]["path"], json!(target));
    assert_eq!(plan["writes"][0]["text"], "{\"theme\": \"dark\"}");
    let deletes = plan["deletes"].as_array().unwrap();
    assert_eq!(deletes.len(), 4);
    assert!(deletes.contains(&json!(global(&home).join("plugins/hol-guard-pretool.ts"))));
    let finished = home.ask(
        "opencode",
        "finish_uninstall",
        json!({"shim": shim(), "finish": plan["finish"], "removed": deletes}),
    );
    let manifest: Value = serde_json::from_str(finished["manifest"].as_str().unwrap()).unwrap();
    assert_eq!(manifest["active"], json!(false));
    assert_eq!(
        manifest["removed_plugin_paths"].as_array().unwrap().len(),
        2
    );
}

#[test]
fn uninstall_removes_a_config_guard_created() {
    let home = Home::new();
    apply(install(&home)["files"].as_array().unwrap());
    let plan = home.ask("opencode", "prepare_uninstall", json!({}));
    assert_eq!(plan["writes"], json!([]));
    let target = global(&home).join("opencode.json");
    assert!(plan["deletes"].as_array().unwrap().contains(&json!(target)));
}

#[test]
fn protection_reports_every_missing_piece() {
    let home = Home::new();
    let answer = home.ask("opencode", "protection", json!({}));
    let checks: Value = serde_json::from_str(answer["checks"].as_str().unwrap()).unwrap();
    assert_eq!(checks["ready"], json!(false));
    assert_eq!(checks["warnings"].as_array().unwrap().len(), 4);
    assert_eq!(checks["mcp_proxy_configured"], json!(false));
}

#[test]
fn plugin_refresh_is_current_once_both_copies_match() {
    let home = Home::new();
    let first = home.ask("opencode", "plugin_refresh", json!({"plugin": plugin()}));
    assert_eq!(first["current"], json!(false));
    for path in first["paths"].as_array().unwrap() {
        write(
            Path::new(path.as_str().unwrap()),
            first["source"].as_str().unwrap(),
        );
    }
    let second = home.ask("opencode", "plugin_refresh", json!({"plugin": plugin()}));
    assert_eq!(second["current"], json!(true));
}

#[test]
fn plugin_names_the_native_bridge_from_the_caller_stamp() {
    let home = Home::new();
    let answer = home.ask("opencode", "plugin_refresh", json!({"plugin": plugin()}));
    let source = answer["source"].as_str().unwrap();
    assert!(source.contains("/g/hol-guard-runtime"));
    assert!(source.contains(r#""harness": "opencode", "timeout_seconds": 25"#));
}

#[test]
fn plugin_of_a_frozen_caller_names_no_native_bridge() {
    let home = Home::new();
    let (stamp, copy) = frozen_with_runtime(&home);
    let mut args = plugin();
    args["frozen"] = json!(true);
    let answer = home.ask(
        "opencode",
        "plugin_refresh",
        json!({"plugin": args, "caller": stamp}),
    );
    assert!(!answer["source"].as_str().unwrap().contains(&copy));
}

#[test]
fn plugin_without_a_native_runtime_asks_for_repair() {
    let home = Home::new();
    let mut stamp = caller(false);
    stamp["native_runtime"] = Value::Null;
    let answer = home.ask(
        "opencode",
        "plugin_refresh",
        json!({"plugin": plugin(), "caller": stamp}),
    );
    assert!(answer["runtime_error"]
        .as_str()
        .unwrap()
        .contains("hol-guard repair"));
}

#[test]
fn refresh_skips_an_invalid_config_with_a_warning() {
    let home = Home::new();
    write(&global(&home).join("opencode.json"), "{oops");
    let applied = home.ask("opencode", "refresh_apply", json!({}));
    assert_eq!(applied["refreshed"], json!(0));
    assert_eq!(applied["warnings"].as_array().unwrap().len(), 1);
}

#[cfg(unix)]
#[test]
fn detect_finds_the_cli_in_its_installer_directory_under_a_terminal_path() {
    use std::os::unix::fs::PermissionsExt;
    let home = Home::new();
    let installer = home.home().join(".opencode").join("bin");
    let cli = installer.join("opencode");
    write(&cli, "#!/bin/sh\n");
    fs::set_permissions(&installer, fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(&cli, fs::Permissions::from_mode(0o755)).unwrap();
    // A terminal PATH that names a user directory but not ~/.opencode/bin,
    // and no host directory where an installed opencode could be found.
    let other = home.root.join("other-bin");
    fs::create_dir_all(&other).unwrap();
    let path = other.display().to_string();
    let answer = home.ask_env("opencode", "detect", json!({}), json!({"PATH": path}));
    assert_eq!(answer["command_available"], json!(true));

    // A group-writable installer directory is still refused.
    fs::set_permissions(&installer, fs::Permissions::from_mode(0o775)).unwrap();
    let answer = home.ask_env("opencode", "detect", json!({}), json!({"PATH": path}));
    assert_eq!(answer["command_available"], json!(false));
}

#[test]
fn runtime_probe_needs_the_command_on_path() {
    let home = Home::new();
    let answer = home.ask("opencode", "runtime_probe", json!({}));
    assert_eq!(answer, json!({"commands": null}));
}

#[test]
fn install_without_servers_attests_the_plugin_guard_cli_itself() {
    let home = Home::new();
    let answer = home.ask("opencode", "prepare_install", json!({"shim": shim()}));
    assert_eq!(
        answer,
        json!({"runtime_error": super::super::attested_cli::REINSTALL})
    );
}

#[test]
fn install_with_servers_builds_the_launch_then_attests_the_plugin_guard_cli() {
    let home = Home::new();
    write(&global(&home).join("opencode.json"), SERVERS);
    let answer = home.ask("opencode", "prepare_install", json!({"shim": shim()}));
    assert_eq!(
        answer,
        json!({"runtime_error": super::super::attested_cli::REINSTALL})
    );
}

#[test]
fn install_refuses_a_caller_without_launch_facts() {
    let home = Home::new();
    write(&global(&home).join("opencode.json"), SERVERS);
    let mut stamp = launch();
    stamp.as_object_mut().unwrap().remove("frozen");
    let mut context = home.context(json!({"PATH": ""}));
    context["caller"] = stamp;
    let request = json!({
        "harness": "opencode",
        "op": "prepare_install",
        "context": context,
        "shim": shim(),
        "plugin": plugin(),
    });
    assert!(dispatch(&request).is_err(), "{request}");
}

#[test]
fn install_routes_a_local_server_through_the_guard_proxy() {
    let home = Home::new();
    let target = global(&home).join("opencode.json");
    write(&target, SERVERS);
    let answer = install_with(&home, launch());
    let config = managed_config(&home, &answer);
    assert_eq!(config["mcp"]["files"]["enabled"], json!(false));
    assert_eq!(config["mcp"]["hosted"]["type"], "remote");
    let companion = &config["mcp"]["hol-guard::files"];
    assert_eq!(companion["type"], "local");
    assert_eq!(
        json!(companion["command"].as_array().expect("command")[..5]),
        json!([
            "/py/bin/python",
            "-m",
            "codex_plugin_scanner.cli",
            "guard",
            "opencode-mcp-proxy"
        ])
    );
    let command = companion["command"].as_array().unwrap();
    assert!(command.contains(&json!("--command")));
    assert!(command.contains(&json!("npx")));
    assert!(command.contains(&json!("--arg=files-server")));
    assert!(!command.contains(&json!("--workspace")));
    assert_eq!(
        companion["environment"],
        json!({"PYTHONPATH": "/g/lib", "TOKEN": "abc", "HOL_GUARD_NATIVE": "1"})
    );
    let manifest: Value = serde_json::from_str(answer["manifest"].as_str().unwrap()).unwrap();
    assert_eq!(manifest["managed_servers"], json!(["files"]));
    assert_eq!(manifest["skipped_servers"], json!(["hosted"]));
    assert_eq!(manifest["source_config_paths"], json!([target]));
}

#[test]
fn install_launches_the_proxy_through_the_native_relay_when_one_is_selected() {
    let home = Home::new();
    write(&global(&home).join("opencode.json"), SERVERS);
    let mut stamp = launch();
    stamp["native_runtime"]["features"] = json!(["mcp-stdio-relay-v1", "bounded-hook-bridge-v1"]);
    let config = managed_config(&home, &install_with(&home, stamp));
    assert_eq!(
        json!(
            config["mcp"]["hol-guard::files"]["command"]
                .as_array()
                .expect("command")[..4]
        ),
        json!(["/g/hol-guard-runtime", "mcp-relay", "/py/bin/python", "-m"])
    );
    // A frozen launcher is relayed whole, through the durable runtime copy.
    let (mut stamp, copy) = frozen_with_runtime(&home);
    stamp["native_runtime"]["features"] = json!(["mcp-stdio-relay-v1"]);
    stamp["executable_resolved"] = json!("/py/bin/python");
    let config = managed_config(&home, &install_with(&home, stamp));
    assert_eq!(
        json!(
            config["mcp"]["hol-guard::files"]["command"]
                .as_array()
                .expect("command")[..4]
        ),
        json!([copy, "mcp-relay", "/py/bin/python", "-m"])
    );
}

#[test]
fn install_drops_the_module_prefix_for_a_frozen_launcher() {
    let home = Home::new();
    write(&global(&home).join("opencode.json"), SERVERS);
    let mut stamp = caller(true);
    stamp["executable_resolved"] = json!("/app/hol-guard");
    let config = managed_config(&home, &install_with(&home, stamp));
    assert_eq!(
        json!(
            config["mcp"]["hol-guard::files"]["command"]
                .as_array()
                .expect("command")[..2]
        ),
        json!(["/app/hol-guard", "opencode-mcp-proxy"])
    );
}

#[test]
fn install_ignores_a_server_that_is_already_a_guard_proxy() {
    let home = Home::new();
    let target = global(&home).join("opencode.json");
    write(&target, SERVERS);
    let first = install_with(&home, launch());
    apply(first["files"].as_array().unwrap());
    let answer = install_with(&home, launch());
    let manifest: Value = serde_json::from_str(answer["manifest"].as_str().unwrap()).unwrap();
    assert_eq!(manifest["managed_servers"], json!(["files"]));
    let config = managed_config(&home, &answer);
    assert_eq!(config["mcp"]["files"]["enabled"], json!(false));
}
