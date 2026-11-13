//! Grok and ZCode through the `harness_adapter` kind.

use std::fs;
use std::path::Path;

use serde_json::{json, Value};

use super::{after, shim, Home};

fn apply(files: &[Value]) {
    for file in files {
        let path = Path::new(file["path"].as_str().unwrap());
        if file["after"].is_null() {
            continue;
        }
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, after(file)).unwrap();
    }
}

fn manifest(answer: &Value) -> Value {
    serde_json::from_str(answer["manifest"].as_str().unwrap()).unwrap()
}

#[test]
fn grok_hook_answers_json_inside_the_hook_timeout() {
    let home = Home::new();
    let answer = home.ask("grok", "hook_spec", json!({}));
    assert_eq!(answer["timeout_seconds"], 85);
    assert_eq!(
        answer["cli_args"].as_array().unwrap().last().unwrap(),
        "--json"
    );
}

#[test]
fn grok_launch_without_a_trusted_executable_is_not_found() {
    let home = Home::new();
    let answer = home.ask("grok", "launch_command", json!({"args": []}));
    assert!(answer["not_found"].is_string(), "{answer}");
}

#[test]
fn grok_install_writes_both_hooks_and_uninstall_removes_them() {
    let home = Home::new();
    let answer = home.ask(
        "grok",
        "prepare_install",
        json!({"shim": shim(), "hook_argv": ["/py", "hook"], "retired_commands": []}),
    );
    let files = answer["files"].as_array().unwrap();
    assert_eq!(files.len(), 8);
    let pretool = after(&files[4]);
    assert!(files[4]["path"]
        .as_str()
        .unwrap()
        .ends_with(".grok/hooks/hol-guard-pretooluse.json"));
    assert!(pretool.contains("/py hook") && pretool.contains("\"timeout\": 90"));
    let notes = manifest(&answer)["notes"].clone();
    assert_eq!(notes.as_array().unwrap().last().unwrap(), "shim note");
    apply(files);

    let uninstall = home.ask("grok", "prepare_uninstall", json!({}));
    assert_eq!(uninstall["writes"][0]["raw"], true);
    let deletes: Vec<&str> = uninstall["deletes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|path| path.as_str().unwrap())
        .collect();
    assert_eq!(deletes.len(), 3);
    assert!(deletes
        .iter()
        .any(|path| path.ends_with("hol-guard-pretooluse.json")));
    let finished = home.ask(
        "grok",
        "finish_uninstall",
        json!({"shim": shim(), "finish": uninstall["finish"].clone()}),
    );
    assert_eq!(
        manifest(&finished)["notes"][0],
        "Guard hook files and launcher removed."
    );
}

#[test]
fn grok_repeated_install_does_not_back_up_its_own_hooks() {
    let home = Home::new();
    let args = json!({"shim": shim(), "hook_argv": ["/py", "hook"], "retired_commands": []});
    apply(
        home.ask("grok", "prepare_install", args.clone())["files"]
            .as_array()
            .unwrap(),
    );
    let again = home.ask("grok", "prepare_install", args);
    let files = again["files"].as_array().unwrap();
    assert!(
        files[1]["after"].is_null() && files[2]["after"].is_null(),
        "{again}"
    );
    apply(files);

    let uninstall = home.ask("grok", "prepare_uninstall", json!({}));
    assert_eq!(uninstall["copies"], json!([]), "{uninstall}");
}

#[test]
fn zcode_install_writes_the_desktop_surface_only_until_the_cli_migrates() {
    let home = Home::new();
    let answer = home.ask(
        "zcode",
        "prepare_install",
        json!({"shim": shim(), "hook_argv": ["/py", "hook"]}),
    );
    let files = answer["files"].as_array().unwrap();
    assert_eq!(files.len(), 3);
    assert!(files[1]["path"]
        .as_str()
        .unwrap()
        .ends_with(".zcode/cli/config.json"));
    assert!(after(&files[1]).contains("\"events\""));
    let state: Value = serde_json::from_str(&after(&files[2])).unwrap();
    assert_eq!(state["hooks_enabled_before"].as_object().unwrap().len(), 2);
    let notes = manifest(&answer)["notes"].clone();
    assert!(notes[1]
        .as_str()
        .unwrap()
        .starts_with("The CLI's ~/.zcode/cli/setting.json does not exist yet"));
    apply(files);

    let uninstall = home.ask("zcode", "prepare_uninstall", json!({}));
    assert_eq!(uninstall["writes"][0]["no_follow"], true);
    assert!(!after_text(&uninstall["writes"][0]).contains("/py hook"));
}

fn after_text(write: &Value) -> String {
    write["text"].as_str().unwrap().to_owned()
}

#[test]
fn zcode_install_refuses_a_config_that_is_not_an_object() {
    let home = Home::new();
    let config = home.home().join(".zcode/cli/config.json");
    fs::create_dir_all(config.parent().unwrap()).unwrap();
    fs::write(&config, "[]\n").unwrap();
    let answer = home.ask(
        "zcode",
        "prepare_install",
        json!({"shim": shim(), "hook_argv": ["/py", "hook"]}),
    );
    assert_eq!(
        answer["refusal"],
        "ZCode config must be a JSON object: config.json"
    );
}

#[test]
fn zcode_runtime_signal_counts_as_installed() {
    let home = Home::new();
    let answer = home.ask_env(
        "zcode",
        "detect",
        json!({}),
        json!({"PATH": "", "__CFBundleIdentifier": "dev.zcode.app"}),
    );
    assert_eq!(answer["installed"], true);
    assert_eq!(answer["warnings"].as_array().unwrap().len(), 1);
}

#[test]
fn grok_protection_names_the_hook_files_and_their_timeouts() {
    let home = Home::new();
    let answer = home.ask("grok", "protection", json!({}));
    assert!(answer["prompt_hook_path"]
        .as_str()
        .unwrap()
        .ends_with(".grok/hooks/hol-guard-prompt.json"));
    assert_eq!(answer["pretool_timeout_seconds"], 90);
    assert_eq!(answer["hook_internal_timeout_seconds"], 85);
    assert!(!answer["managed_deny_rules"].as_array().unwrap().is_empty());
    let observe = home.ask("grok", "observe_hook", json!({"command": "/py hook"}));
    let hook: Value = serde_json::from_str(observe["hook"].as_str().unwrap()).unwrap();
    assert_eq!(hook["hooks"]["SessionStart"][0]["hooks"][0]["timeout"], 15);
}
