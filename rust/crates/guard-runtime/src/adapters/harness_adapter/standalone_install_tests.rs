//! `shim_install`, `profile_install`, `cursor_hooks_install` and
//! `workspace_skills_scan`: the installs that stand alone.

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
        "thread": 9,
        "actor": "harness-shim.install",
        "process_identity": "test-process",
        "deadline_ms": 2000,
        "transition": {"package_roots": [], "budget": null},
        "interpreter": interpreter(),
    });
    for (key, value) in extra.as_object().unwrap() {
        request[key] = value.clone();
    }
    request
}

fn operations(home: &Home) -> Vec<String> {
    let path = home.guard().join("managed/codex/authority-mutations.jsonl");
    fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(|line| {
            let line: Value = serde_json::from_str(line).unwrap();
            line["operation"].as_str().unwrap().to_owned()
        })
        .collect()
}

fn pending(home: &Home) {
    fs::create_dir_all(home.guard().join("managed")).unwrap();
    fs::write(home.guard().join("managed/runtime-transition.json"), "{}").unwrap();
}

#[test]
fn a_shim_install_journals_the_launcher_under_its_own_owner() {
    let home = Home::new();
    fs::create_dir_all(home.guard().join("bin")).unwrap();
    let answer = home.ask(
        "gemini",
        "shim_install",
        owned(json!({"harness": "gemini", "launcher_name": null, "display_name": null})),
    );
    assert_eq!(answer["ok"], json!(true), "{answer}");
    let manifest: Value = serde_json::from_str(answer["manifest"].as_str().unwrap()).unwrap();
    assert_eq!(manifest["shim_command"], json!("guard-gemini"));
    let operations = operations(&home);
    assert_eq!(operations.first().map(String::as_str), Some("begin"));
    assert_eq!(operations.last().map(String::as_str), Some("committed"));
    assert!(operations.len() > 2, "{operations:?}");
}

#[test]
fn a_pending_transition_refuses_each_standalone_install_before_any_write() {
    for (op, fields) in [
        (
            "shim_install",
            json!({"harness": "gemini", "launcher_name": null, "display_name": null}),
        ),
        (
            "profile_install",
            json!({"shell_profile": {"shell": "zsh", "shim_dir_transient": false}}),
        ),
        ("cursor_hooks_install", json!({})),
    ] {
        let home = Home::new();
        pending(&home);
        let answer = home.ask("cursor", op, owned(fields));
        assert_eq!(answer["ok"], json!(false), "{op}: {answer}");
        assert_eq!(
            answer["failure"]["reason"],
            json!("pending_transition"),
            "{op}: {answer}"
        );
        assert!(!home.guard().join("bin").exists(), "{op}");
    }
}

#[test]
fn a_profile_that_cannot_be_written_answers_its_manifest_without_an_owner() {
    let home = Home::new();
    let answer = home.ask(
        "gemini",
        "profile_install",
        owned(json!({"shell_profile": {"shell": "zsh", "shim_dir_transient": true}})),
    );
    assert_eq!(answer["ok"], json!(true), "{answer}");
    assert_eq!(
        answer["manifest"]["manual_path_reason"],
        json!("transient_guard_home")
    );
    assert!(operations(&home).is_empty());
}

#[test]
fn a_profile_install_writes_the_path_block_under_its_own_owner() {
    let home = Home::new();
    fs::create_dir_all(home.guard().join("bin")).unwrap();
    let answer = home.ask(
        "gemini",
        "profile_install",
        owned(json!({"shell_profile": {"shell": "zsh", "shim_dir_transient": false}})),
    );
    assert_eq!(answer["ok"], json!(true), "{answer}");
    assert_eq!(answer["manifest"]["changed"], json!(true), "{answer}");
    let profile = fs::read_to_string(home.home().join(".zshrc")).unwrap();
    assert!(profile.contains("guard/bin"), "{profile}");
    assert_eq!(
        operations(&home).last().map(String::as_str),
        Some("committed")
    );
}

#[test]
fn a_workspace_without_skills_scans_to_nothing() {
    let home = Home::new();
    let workspace = home.home().join("project");
    fs::create_dir_all(&workspace).unwrap();
    let answer = home.ask(
        "gemini",
        "workspace_skills_scan",
        json!({
            "workspace_dir": workspace,
            "now": "2026-11-18T00:00:00+00:00",
            "source": "test",
        }),
    );
    assert_eq!(answer, json!({"skill_scan": []}));
}

#[test]
fn a_skills_scan_without_a_workspace_is_invalid() {
    let home = Home::new();
    let answer = crate::harness_adapter::dispatch(&json!({
        "harness": "gemini",
        "op": "workspace_skills_scan",
        "context": home.context(json!({"PATH": ""})),
        "now": "2026-11-18T00:00:00+00:00",
        "source": "test",
    }));
    assert!(answer.is_err());
}
