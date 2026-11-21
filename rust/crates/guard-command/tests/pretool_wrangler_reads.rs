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
fn wrangler_metadata_and_identity_reads_are_explicitly_benign() {
    for harness in ["omp", "zcode"] {
        for command in [
            "wrangler --version",
            "wrangler -v",
            "wrangler whoami",
            "wrangler --help",
            "wrangler deploy --help",
            "wrangler kv:namespace list --help",
            "wrangler d1 execute -h",
        ] {
            let (decision, minimum_action) = evaluate(harness, command);
            assert_eq!(decision, "allow", "{harness}: {command}");
            assert_eq!(minimum_action, "allow", "{harness}: {command}");
        }
    }
}

#[test]
fn wrangler_effects_and_unbound_launches_stay_reviewed() {
    for harness in ["omp", "zcode"] {
        for command in [
            "wrangler deploy",
            "wrangler dev",
            "wrangler login",
            "wrangler whoami --account other",
            "wrangler --version --config other.toml",
            "wrangler deploy --dry-run --help",
            "wrangler d1 execute db --command 'DROP TABLE users' --help",
            "./node_modules/.bin/wrangler --version",
            "npx wrangler --version",
        ] {
            let (decision, _) = evaluate(harness, command);
            assert_ne!(decision, "allow", "{harness}: {command}");
        }
    }
}
