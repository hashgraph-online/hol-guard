use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;

fn evaluate(harness: &str, command: &str) -> (String, String) {
    let result = evaluate_pre_tool_envelope_with_context(
        harness,
        "PreToolUse",
        &json!({"tool_name":"bash","tool_input":{"command":command}}),
        None,
        None,
        None,
        None,
    );
    (result.decision, result.minimum_action)
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
            "hol-guard policy disable",
            "hol-guard clear --all",
        ] {
            let (decision, _) = evaluate(harness, command);
            assert_eq!(decision, "deny", "{harness}: {command}");
        }
    }
}
