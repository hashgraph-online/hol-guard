use guard_command::pretool::evaluate_pre_tool_envelope;
use serde_json::json;

#[test]
fn non_inspection_git_commands_keep_their_existing_review_floor() {
    for command in [
        "cd workspace/repo && git branch --show-current",
        "cd workspace/repo && git rev-parse --show-toplevel",
        "cd workspace/repo && git apply --check workspace/change.patch",
        "cd workspace/repo && git add src/app.py && git commit -m 'fixture' 2>&1",
    ] {
        let result = evaluate_pre_tool_envelope(
            "claude-code",
            "PreToolUse",
            &json!({"tool_name":"Bash", "tool_input":{"command":command}}),
        );
        assert_eq!(result.minimum_action, "review", "{command}");
        assert!(!result.explicitly_benign, "{command}");
        assert_ne!(result.reason_code, "native_git_execution_context_review");
    }
}

#[test]
fn unverified_git_inspections_still_require_fresh_approval() {
    for command in [
        "cd workspace/repo && git status --short",
        "cd workspace/repo && git diff --check",
        "cd workspace/repo && git log -5 --oneline",
        "cd workspace/repo && git show --stat --oneline HEAD",
        "cd workspace/repo && git status --porcelain=v1 | wc -l",
    ] {
        let result = evaluate_pre_tool_envelope(
            "claude-code",
            "PreToolUse",
            &json!({"tool_name":"Bash", "tool_input":{"command":command}}),
        );
        assert_eq!(result.minimum_action, "require-reapproval", "{command}");
        assert_eq!(result.decision, "deny");
        assert_eq!(result.reason_code, "native_git_execution_context_review");
        assert!(!result.explicitly_benign);
    }
}
