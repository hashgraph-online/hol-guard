//! OpenCode through the `harness_adapter` kind.

use std::fs;
use std::path::Path;

use serde_json::{json, Value};

use super::super::dispatch;
use super::{after, shim, Home};

fn plugin() -> Value {
    let vectors: Value = serde_json::from_str(include_str!(
        "../../../testdata/opencode/plugin_render_vectors.json"
    ))
    .unwrap();
    vectors["cases"][0]["args"].clone()
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
    let found = home.ask("opencode", "install_detection", json!({}));
    home.ask(
        "opencode",
        "prepare_install",
        json!({
            "shim": shim(),
            "servers": "[]",
            "skipped": "[]",
            "artifacts": "[]",
            "source_config_paths": "[]",
            "plugin": plugin(),
            "digest": found["digest"],
        }),
    )
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
    assert_eq!(answer["firewall"], json!(true));
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
fn install_refuses_a_config_that_moved_after_detection() {
    let home = Home::new();
    let target = global(&home).join("opencode.json");
    write(&target, "{}");
    let found = home.ask("opencode", "install_detection", json!({}));
    write(&target, "{\"theme\": \"light\"}");
    let request = json!({
        "harness": "opencode",
        "op": "prepare_install",
        "context": home.context(json!({"PATH": ""})),
        "shim": shim(),
        "servers": "[]",
        "skipped": "[]",
        "artifacts": "[]",
        "source_config_paths": "[]",
        "plugin": plugin(),
        "digest": found["digest"],
    });
    assert_eq!(
        dispatch(&request).unwrap(),
        json!({"integrity": "target_changed"})
    );
}

#[test]
fn install_refuses_an_invalid_config() {
    let home = Home::new();
    write(&global(&home).join("opencode.json"), "{oops");
    let answer = home.ask("opencode", "install_detection", json!({}));
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
    let answer = home.ask(
        "opencode",
        "protection",
        json!({"managed_active": false, "config_paths": []}),
    );
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
fn refresh_skips_an_invalid_config_with_a_warning() {
    let home = Home::new();
    write(&global(&home).join("opencode.json"), "{oops");
    let answer = home.ask("opencode", "refresh_scan", json!({}));
    assert_eq!(answer["candidates"], json!([]));
    assert_eq!(answer["warnings"].as_array().unwrap().len(), 1);
    let applied = home.ask("opencode", "refresh_apply", json!({"commands": "[]"}));
    assert_eq!(applied, json!({"refreshed": 0}));
}

#[test]
fn runtime_probe_needs_the_command_on_path() {
    let home = Home::new();
    let answer = home.ask("opencode", "runtime_probe", json!({}));
    assert_eq!(answer, json!({"commands": null}));
}
