//! Removing a root stays a hard block; removing a path inside the project is
//! an ordinary review that an approval can settle.
use guard_command::pretool::evaluate_pre_tool_envelope_with_context;
use serde_json::json;

fn classify(command: &str) -> guard_contracts::PreToolResultV1 {
    evaluate_pre_tool_envelope_with_context(
        "codex",
        "PreToolUse",
        &json!({"tool_name":"Bash","tool_input":{"command":command}}),
        None,
        None,
        Some("/home/tester"),
        Some("/home/tester/project"),
    )
}

#[test]
fn removing_a_root_is_a_hard_block() {
    for command in [
        "rm -rf /",
        "rm -rf ~",
        "rm -rf $HOME",
        "rm -rf /home/tester",
        "rm -rf /usr",
        "cd /home/tester/project && rm -rf /",
        "cd / && rm -rf *",
        "cd ~; rm -rf .",
    ] {
        let result = classify(command);
        assert_eq!(result.decision, "deny", "{command}");
        assert_eq!(result.minimum_action, "block", "{command}");
    }
}

#[test]
fn removing_a_path_inside_the_project_is_not_the_root_floor() {
    for command in [
        "rm -rf /home/tester/project/node_modules",
        "rm -rf /home/tester/project/dist && ls /",
        "rm -rf build && cat /home/tester/project/README.md",
    ] {
        let result = classify(command);
        assert_ne!(
            result.reason_code, "native_destructive_command",
            "{command}"
        );
    }
}
