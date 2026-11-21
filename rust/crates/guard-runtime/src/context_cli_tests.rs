use serde_json::json;

use super::args::{parse, Action, Parsed};
use super::render;

fn argv(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| (*item).to_owned()).collect()
}

fn command(items: &[&str]) -> super::args::Command {
    match parse(&argv(items)) {
        Ok(Parsed::Run(command)) => command,
        Ok(Parsed::Help(_)) => panic!("help for {items:?}"),
        Err(message) => panic!("{items:?}: {message}"),
    }
}

#[test]
fn control_subcommands_map_to_engine_requests() {
    for (name, kind) in [
        ("status", "status"),
        ("runtimes", "installations"),
        ("check", "recheck"),
        ("start", "activate"),
        ("off", "stop"),
    ] {
        let parsed = command(&["--guard-home", "/g", name, "--json"]);
        assert_eq!(parsed.guard_home.as_deref(), Some("/g"));
        assert!(parsed.json);
        assert!(matches!(parsed.action, Action::Control(found) if found == kind));
    }
}

#[test]
fn version_subcommands_frame_their_input() {
    let input = |items: &[&str]| match command(items).action {
        Action::Versions(input) => serde_json::Value::Object(input),
        _ => panic!("not a version request"),
    };
    assert_eq!(input(&["jobs"]), json!({"action": "jobs"}));
    assert_eq!(
        input(&["job", "j1"]),
        json!({"action": "job", "job_id": "j1"})
    );
    assert_eq!(
        input(&["switch", "--job-id", "j1", "rt", "--generation=7"]),
        json!({"action": "prepare_switch", "job_id": "j1", "target_runtime_id": "rt", "expected_generation": "7"})
    );
    assert_eq!(
        input(&[
            "commit",
            "j1",
            "--generation",
            "7",
            "--acknowledge-reconnect"
        ]),
        json!({"action": "commit", "job_id": "j1", "expected_generation": "7", "reconnect": true})
    );
    assert_eq!(
        input(&["commit", "j1", "--generation", "7"]),
        json!({"action": "commit", "job_id": "j1", "expected_generation": "7", "reconnect": false})
    );
    assert_eq!(
        input(&["cancel", "j1"]),
        json!({"action": "cancel", "job_id": "j1"})
    );
    assert_eq!(
        input(&["recover", "j1"]),
        json!({"action": "recover", "job_id": "j1"})
    );
}

#[test]
fn lean_reads_its_action_and_limit() {
    match command(&["lean", "on", "--limit", "50000"]).action {
        Action::Lean { action, limit } => {
            assert_eq!(action, "enable");
            assert_eq!(limit, Some(50_000));
        }
        _ => panic!("not lean"),
    }
    assert!(matches!(
        command(&["lean"]).action,
        Action::Lean {
            action: "status",
            limit: None
        }
    ));
}

#[test]
fn bad_arguments_are_refused() {
    for items in [
        vec![],
        vec!["nope"],
        vec!["status", "extra"],
        vec!["switch", "rt"],
        vec!["commit", "j1"],
        vec!["lean", "sideways"],
        vec!["lean", "on", "--limit", "many"],
        vec!["status", "--limit", "5"],
        vec!["status", "--unknown"],
        vec!["--guard-home"],
    ] {
        assert!(parse(&argv(&items)).is_err(), "{items:?}");
    }
    assert!(matches!(parse(&argv(&["--help"])), Ok(Parsed::Help(_))));
}

#[test]
fn status_text_names_the_builtin_engine() {
    let text = render::status(&json!({
        "availability": "available",
        "requested_enabled": true,
        "effective_enabled": false,
        "job": {"operation": "verify", "phase": "running"},
        "diagnostic": null,
        "installation_options": [
            {"runtime_id": "rt", "platform": "macos", "qualification": "guard_builtin"},
            {"runtime_id": "other", "platform": "macos", "qualification": "other"},
        ],
    }));
    assert_eq!(
        text,
        "CIGAR context assistance: available\n\
         Requested: True · Active: False\n\
         Background operation: verify (running)\n  \
         rt: Built into Guard · macos · guard_builtin\n\
         CIGAR runs on the engine built into Guard; no Python or download is needed. \
         Choose preferences in Protection → Context assistance.\n"
    );
    let none = render::status(&json!({
        "availability": "off", "requested_enabled": false, "effective_enabled": false,
        "job": null, "diagnostic": "d", "installation_options": [],
    }));
    assert!(none.contains("Diagnostic: d\n"));
    assert!(none.contains("The built-in engine is unavailable on this machine.\n"));
}

#[test]
fn version_text_lists_jobs() {
    let state = json!({"availability": "available", "generation": "g1"});
    assert_eq!(
        render::versions(&json!({"state": state, "result": {"jobs": []}})),
        "CIGAR: available · generation g1\nNo setup jobs.\n"
    );
    let ready = render::versions(&json!({"state": state, "result": {
        "job_id": "j1", "operation": "switch", "phase": "ready", "code": "ok",
        "can_commit": true, "keeps_disabled": true, "reconnect_required": false,
    }}));
    assert!(ready.ends_with(
        "j1: switch · ready (ok)\nReady to select. CIGAR stays off; enable it separately when needed.\n"
    ));
}

#[test]
fn a_lost_lean_answer_does_not_claim_nothing_changed() {
    let lost = super::codex::lean_failure("codex_config_unconfirmed");
    assert!(!lost.contains("Nothing was changed"), "{lost}");
    assert!(super::codex::lean_failure("codex_config_busy").ends_with("Nothing was changed."));
}
