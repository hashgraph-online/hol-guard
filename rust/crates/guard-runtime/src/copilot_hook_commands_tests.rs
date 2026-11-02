use std::fs;

use serde_json::{json, Value};

use super::{is_managed, py_string_literal, run_command};

const BRIDGE_CODE: &str =
    "from codex_plugin_scanner.guard.adapters.bounded_cli_hook_bridge import main_from_argv";

/// `shlex.join`.
fn join(tokens: &[&str]) -> String {
    tokens
        .iter()
        .map(|token| format!("'{}'", token.replace('\'', r#"'"'"'"#)))
        .collect::<Vec<_>>()
        .join(" ")
}

fn config(harness: &str, cli_args: Value) -> String {
    json!({"harness": harness, "cli_args": cli_args}).to_string()
}

fn copilot_config() -> String {
    config("copilot", json!(["guard", "hook", "--harness", "copilot"]))
}

#[test]
fn recognizes_the_legacy_module_spelling() {
    let command = r#""/usr/bin/python3" -m codex_plugin_scanner.cli guard hook --harness copilot"#;
    assert!(is_managed(command, None));
    assert!(is_managed(
        "PYTHON -m codex_plugin_scanner.cli GUARD HOOK --harness=COPILOT",
        None
    ));
    assert!(!is_managed(
        "python -m codex_plugin_scanner.cli guard hook --harness cursor",
        None
    ));
}

#[test]
fn recognizes_an_isolated_inline_bridge() {
    let command = join(&["python", "-I", "-c", BRIDGE_CODE, &copilot_config()]);
    assert!(is_managed(&command, None));

    let other = config("cursor", json!(["guard", "hook", "--harness", "cursor"]));
    assert!(!is_managed(
        &join(&["python", "-I", "-c", BRIDGE_CODE, &other]),
        None
    ));
    // An interpreter flag Guard never writes makes the command the user's.
    assert!(!is_managed(
        &join(&["python", "-X", "dev", "-c", BRIDGE_CODE, &copilot_config()]),
        None
    ));
    assert!(!is_managed(
        &join(&["node", "-I", "-c", BRIDGE_CODE, &copilot_config()]),
        None
    ));
    let no_hook = config("copilot", json!(["guard", "scan", "--harness", "copilot"]));
    assert!(!is_managed(
        &join(&["python", "-c", BRIDGE_CODE, &no_hook]),
        None
    ));
}

#[test]
fn recognizes_the_frozen_launcher_and_its_native_prefix() {
    let launcher = "/Applications/HOL Guard.app/Contents/MacOS/hol-guard";
    let frozen = join(&[launcher, "__guard-bounded-hook", &copilot_config()]);
    assert!(is_managed(&frozen, None));
    let native = join(&[
        "/opt/hol guard runtime",
        "bounded-hook-bridge",
        launcher,
        "__guard-bounded-hook",
        &copilot_config(),
    ]);
    assert!(is_managed(&native, None));
    let native_python = join(&[
        "/opt/hol guard runtime",
        "bounded-hook-bridge",
        "/usr/bin/python3",
        "-I",
        "-c",
        BRIDGE_CODE,
        &copilot_config(),
    ]);
    assert!(is_managed(&native_python, None));

    assert!(!is_managed(
        &join(&["/usr/bin/other", "__guard-bounded-hook", &copilot_config()]),
        None
    ));
    let mixed = config(
        "copilot",
        json!(["guard", "hook", 1, "--harness", "copilot"]),
    );
    assert!(!is_managed(
        &join(&[launcher, "__guard-bounded-hook", &mixed]),
        None
    ));
    assert!(!is_managed(
        &join(&[launcher, "__guard-bounded-hook", "not json"]),
        None
    ));
}

#[test]
fn an_isolated_script_is_guards_only_at_the_current_guard_home() {
    let root = tempfile::tempdir().expect("tempdir");
    let interpreter = root.path().join("python3");
    fs::write(&interpreter, b"#!/bin/sh\n").expect("interpreter");
    let script = root.path().join("guard/managed/bounded-hooks/copilot.py");
    fs::create_dir_all(script.parent().expect("parent")).expect("script dir");
    fs::write(&script, b"# hook\n").expect("script");
    let other = root.path().join("other/managed/bounded-hooks/copilot.py");
    let (interpreter, script, other) = (
        interpreter.to_string_lossy().into_owned(),
        script.to_string_lossy().into_owned(),
        other.to_string_lossy().into_owned(),
    );
    let bridge = Some((interpreter.as_str(), script.as_str()));

    assert!(is_managed(&join(&[&interpreter, "-I", &script]), bridge));
    assert!(!is_managed(&join(&[&interpreter, "-I", &other]), bridge));
    assert!(!is_managed(&join(&[&interpreter, "-I", &script]), None));
}

#[test]
fn recognizes_an_inline_cli_whose_guard_argv_targets_copilot() {
    let code = |argv: &str| {
        format!(
            "import json, sys; from codex_plugin_scanner.cli import main; sys.exit(main(json.loads('{argv}')))"
        )
    };
    let copilot = code(r#"[\"guard\", \"hook\", \"--harness\", \"copilot\"]"#);
    assert!(is_managed(&join(&["python3", "-c", &copilot]), None));
    let escaped = code(r#"[\x22guard\x22, "hook", \"--harness=copilot\"]"#);
    assert!(is_managed(&join(&["python3", "-c", &escaped]), None));

    let cursor = code(r#"[\"guard\", \"hook\", \"--harness\", \"cursor\"]"#);
    assert!(!is_managed(&join(&["python3", "-c", &cursor]), None));
    let elsewhere = format!(
        "import json; json.loads('{}')",
        r#"[\"guard\", \"hook\", \"--harness\", \"copilot\"]"#
    );
    assert!(!is_managed(&join(&["python3", "-c", &elsewhere]), None));
}

#[test]
fn reads_python_string_literals_like_literal_eval() {
    assert_eq!(py_string_literal(r#"'a\'b'"#).as_deref(), Some("a'b"));
    assert_eq!(py_string_literal(r#""\x41\101B""#).as_deref(), Some("AAB"));
    assert_eq!(py_string_literal(r"'\q'").as_deref(), Some(r"\q"));
    assert_eq!(py_string_literal(r"'\ud800'").as_deref(), Some("\u{FFFD}"));
    assert_eq!(py_string_literal(r"'\x4'"), None);
    assert_eq!(py_string_literal(r"'\N{BULLET}'"), None);
    assert_eq!(py_string_literal("'a\nb'"), None);
}

#[test]
fn command_answers_one_flag_per_command() {
    let request = json!({
        "schema": "copilot-hook-commands.v1",
        "commands": [
            join(&["python", "-I", "-c", BRIDGE_CODE, &copilot_config()]),
            "echo user hook",
            "python -I /tmp/copilot.py",
        ],
        "interpreter": null,
        "script": null,
    });
    let bytes = run_command(request.to_string().as_bytes()).expect("answer");
    let answer: Value = serde_json::from_slice(&bytes).expect("json");
    assert_eq!(answer, json!({"managed": [true, false, false]}));
}

#[test]
fn command_refuses_malformed_requests() {
    for request in [
        "not json".to_owned(),
        json!({"schema": "other", "commands": []}).to_string(),
        json!({"schema": "copilot-hook-commands.v1", "commands": [1]}).to_string(),
        json!({"schema": "copilot-hook-commands.v1", "commands": [], "extra": 1}).to_string(),
        json!({"schema": "copilot-hook-commands.v1", "commands": vec![""; 1025]}).to_string(),
    ] {
        assert_eq!(
            run_command(request.as_bytes()),
            Err("copilot_hook_commands_request_invalid".to_owned()),
            "{request}"
        );
    }
}
