//! `managed_install`, `adapter_install`, `adapter_uninstall` and
//! `managed_update`: installs done under one native installation transaction.

use std::fs;

use serde_json::{json, Value};

use super::Home;

fn interpreter() -> Value {
    json!({
        "executable": "/opt/python/bin/python3",
        "frozen": false,
        "package_interpreter": "/opt/python/bin/python3",
        "python_flags": ["-I", "-P"],
        "import_root": "/opt/site",
        "launcher_env": [],
    })
}

fn owned(extra: Value) -> Value {
    let mut request = json!({
        "client_pid": std::process::id(),
        "thread": 7,
        "actor": "managed.install",
        "process_identity": "test-process",
        "deadline_ms": 2000,
        "transition": {"package_roots": [], "budget": null},
        "interpreter": interpreter(),
        "shell_profile": null,
        "frozen": null,
        "runtime": null,
        "facts": {},
        "now": "2026-11-18T00:00:00+00:00",
        "source": "test",
        "workspace": null,
    });
    for (key, value) in extra.as_object().unwrap() {
        request[key] = value.clone();
    }
    request
}

fn journal(home: &Home) -> Vec<Value> {
    let path = home.guard().join("managed/codex/authority-mutations.jsonl");
    fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn operations(home: &Home) -> Vec<String> {
    journal(home)
        .iter()
        .map(|line| line["operation"].as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn an_adapter_install_journals_its_launchers_under_its_own_owner() {
    let home = Home::new();
    fs::create_dir_all(home.guard().join("bin")).unwrap();
    let answer = home.ask("gemini", "adapter_install", owned(json!({})));
    assert_eq!(answer["ok"], json!(true), "{answer}");
    let manifest: Value = serde_json::from_str(answer["manifest"].as_str().unwrap()).unwrap();
    assert_eq!(manifest["harness"], json!("gemini"));
    assert_eq!(manifest["active"], json!(true));
    assert_eq!(manifest["config_path"], manifest["shim_path"]);
    let operations = operations(&home);
    assert_eq!(operations.first().map(String::as_str), Some("begin"));
    assert_eq!(operations.last().map(String::as_str), Some("committed"));
    // Between `begin` and `committed` sit the launcher writes this install made.
    assert!(operations.len() > 2, "{operations:?}");
}

#[test]
fn a_hooked_harness_install_writes_its_settings_under_its_own_owner() {
    let home = Home::new();
    let answer = home.ask("muse", "adapter_install", owned(json!({})));
    assert_eq!(answer["ok"], json!(true), "{answer}");
    let manifest: Value = serde_json::from_str(answer["manifest"].as_str().unwrap()).unwrap();
    assert_eq!(manifest["harness"], json!("muse"));
    assert_eq!(manifest["active"], json!(true));
    let operations = operations(&home);
    assert_eq!(operations.first().map(String::as_str), Some("begin"));
    assert_eq!(operations.last().map(String::as_str), Some("committed"));
}

#[test]
fn a_pending_transition_refuses_an_install_before_any_write() {
    let home = Home::new();
    fs::create_dir_all(home.guard().join("managed")).unwrap();
    fs::write(home.guard().join("managed/runtime-transition.json"), "{}").unwrap();
    let answer = home.ask("gemini", "adapter_install", owned(json!({})));
    assert_eq!(answer["ok"], json!(false), "{answer}");
    assert_eq!(answer["failure"]["kind"], json!("transition"));
    assert_eq!(answer["failure"]["reason"], json!("pending_transition"));
    assert!(!home.guard().join("bin").exists());
}

#[test]
fn a_managed_install_with_an_unknown_command_is_invalid() {
    let home = Home::new();
    let answer = home.ask(
        "gemini",
        "managed_install",
        owned(json!({"command": "reinstall", "targets": []})),
    );
    assert_eq!(answer["ok"], json!(false), "{answer}");
    assert_eq!(
        answer["failure"]["reason"],
        json!("native_transition_invalid")
    );
}

#[test]
fn a_managed_install_without_targets_records_nothing() {
    let home = Home::new();
    let answer = home.ask(
        "gemini",
        "managed_install",
        owned(json!({"command": "install", "targets": []})),
    );
    assert_eq!(answer["ok"], json!(true), "{answer}");
    assert_eq!(answer["rows"], json!([]));
    assert_eq!(answer["guidance"], Value::Null);
    assert_eq!(operations(&home), ["begin", "committed"]);
}

#[test]
fn an_owner_token_that_python_never_registered_is_refused() {
    let home = Home::new();
    let answer = home.ask(
        "gemini",
        "adapter_install",
        owned(json!({"owner": "no-such-owner"})),
    );
    assert_eq!(answer["ok"], json!(false), "{answer}");
    assert_eq!(answer["failure"]["kind"], json!("runtime"));
}

#[test]
fn an_update_repair_with_no_active_install_changes_nothing() {
    let home = Home::new();
    for update in ["grok", "bounded"] {
        let answer = home.ask("grok", "managed_update", owned(json!({"update": update})));
        assert_eq!(answer["installs"], json!([]), "{update}: {answer}");
        assert_eq!(
            answer["notes"].as_array().map(Vec::len),
            Some(0),
            "{update}: {answer}"
        );
    }
    assert!(journal(&home).is_empty());
}
