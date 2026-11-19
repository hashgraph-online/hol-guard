//! `probe_runtime`: the harness CLI probes the native runtime runs itself.

use serde_json::{json, Value};

use super::Home;

fn probe(home: &Home, harness: &str, env: Value, probes: bool) -> Value {
    let mut request = json!({
        "harness": harness,
        "op": "probe_runtime",
        "context": home.context(env),
    });
    request["context"]["probes"] = json!(probes);
    super::dispatch(&request).unwrap()
}

#[test]
fn a_harness_without_its_cli_answers_no_probe() {
    let home = Home::new();
    for harness in ["claude-code", "copilot", "opencode"] {
        assert_eq!(
            probe(&home, harness, json!({"PATH": ""}), true),
            json!({"probe": null}),
            "{harness}"
        );
    }
}

#[test]
fn a_context_with_a_malformed_probes_flag_is_refused() {
    let home = Home::new();
    let mut request = json!({
        "harness": "claude-code",
        "op": "probe_runtime",
        "context": home.context(json!({"PATH": ""})),
    });
    request["context"]["probes"] = json!("yes");
    assert!(super::dispatch(&request).is_err());
}

#[cfg(unix)]
fn fixture_cli(home: &Home, name: &str, script: &str) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt as _;

    let bin = home.root.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let path = bin.join(name);
    std::fs::write(&path, script).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

#[cfg(unix)]
#[test]
fn passive_doctor_gets_the_skipped_record_without_running_the_cli() {
    let home = Home::new();
    let marker = home.root.join("ran");
    let cli = fixture_cli(
        &home,
        "claude",
        &format!("#!/bin/sh\ntouch '{}'\n", marker.display()),
    );
    let bin = cli.parent().unwrap().to_owned();
    let answer = probe(&home, "claude-code", json!({"PATH": bin}), false);
    assert_eq!(
        answer,
        json!({"probe": {
            "command": [cli, "--help"],
            "ok": null,
            "return_code": null,
            "stdout": "",
            "stderr": "",
            "skipped": true,
            "skip_reason": "global_doctor_passive_checks",
        }})
    );
    assert!(!marker.exists());
}

#[cfg(unix)]
#[test]
fn claude_code_help_runs_through_the_command_probe() {
    let home = Home::new();
    let cli = fixture_cli(&home, "claude", "#!/bin/sh\necho \"usage: $1\"\n");
    let bin = cli.parent().unwrap().to_owned();
    let answer = probe(&home, "claude-code", json!({"PATH": bin}), true);
    let record = &answer["probe"];
    assert_eq!(record["command"], json!([cli, "--help"]));
    assert_eq!(record["return_code"], json!(0));
    assert!(record["stdout"].as_str().unwrap().contains("usage: --help"));
}
