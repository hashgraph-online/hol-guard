use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;

fn evaluate_in(harness: &str, command: &str, cwd: Option<&str>) -> (String, String) {
    let result = evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &json!({"tool_name":"bash","tool_input":{"command":command}}),
        None,
        None,
        None,
        cwd,
    );
    (result.decision, result.minimum_action)
}

fn workspace(label: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "pretool-guard-diagnostics-{label}-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn evaluate(harness: &str, command: &str) -> (String, String) {
    let cwd = workspace("clean");
    evaluate_in(harness, command, cwd.to_str())
}

#[test]
fn guard_read_only_diagnostics_are_explicitly_benign() {
    for harness in ["omp", "zcode"] {
        for command in [
            "hol-guard --version",
            "hol-guard status",
            "hol-guard status --json",
            "hol-guard daemon status",
            "hol-guard daemon status --json",
            "hol-guard doctor",
            "hol-guard doctor --json",
            "hol-guard settings",
            "hol-guard settings --json",
        ] {
            let (decision, minimum_action) = evaluate(harness, command);
            assert_eq!(decision, "allow", "{harness}: {command}");
            assert_eq!(minimum_action, "allow", "{harness}: {command}");
        }
    }
}

#[test]
fn guard_repairs_controls_and_unbound_launches_stay_reviewed() {
    for harness in ["omp", "zcode"] {
        for command in [
            "hol-guard doctor --repair",
            "hol-guard doctor --fix",
            "hol-guard doctor --incident",
            "hol-guard doctor codex",
            "hol-guard status --repair",
            "hol-guard daemon start",
            "hol-guard daemon stop",
            "hol-guard settings set mode off",
            "hol-guard daemon status; rm -rf /tmp/x",
            "./hol-guard status",
            "/tmp/hol-guard status",
            "npx hol-guard status",
            "plugin-guard status",
        ] {
            let (decision, _) = evaluate(harness, command);
            assert_ne!(decision, "allow", "{harness}: {command}");
        }
        for command in [
            "hol-guard uninstall",
            "hol-guard hooks remove --all",
            "hol-guard policy disable",
            "hol-guard clear --all",
        ] {
            let (decision, _) = evaluate(harness, command);
            assert_eq!(decision, "deny", "{harness}: {command}");
        }
    }
}

#[test]
fn diagnostics_need_a_known_unshadowed_working_directory() {
    let shadowed = workspace("shadowed");
    std::fs::write(shadowed.join("hol-guard"), "#!/bin/sh\n").unwrap();
    for harness in ["omp", "zcode"] {
        let (no_cwd, _) = evaluate_in(harness, "hol-guard status", None);
        assert_ne!(no_cwd, "allow", "{harness}: unknown cwd");
        let (shadow, _) = evaluate_in(harness, "hol-guard status", shadowed.to_str());
        assert_ne!(shadow, "allow", "{harness}: cwd launcher");
    }
    std::fs::remove_dir_all(&shadowed).unwrap();
}
