use super::*;
use serde_json::json;

const VECTORS: &str = include_str!("../testdata/hook_direct_review/package_review_vectors.json");

/// Each recorded review is left to the queue exactly when the package review
/// plan has no command for the evaluator.
#[test]
fn recorded_package_reviews_replay() {
    let document: Value = serde_json::from_str(VECTORS).expect("vectors parse");
    let vectors = document["vectors"].as_array().expect("vector list");
    assert!(vectors.len() > 100, "{}", vectors.len());
    let mut queued = 0;
    for vector in vectors {
        let name = vector["name"].as_str().expect("name");
        let payload = vector["payload"].as_object().expect("payload");
        let result = vector["result"].as_object().expect("result");
        let expected = vector["queued"].as_bool().expect("queued");
        assert_eq!(left_to_queue(payload, result), expected, "{name}");
        queued += usize::from(expected);
    }
    // Both outcomes are covered.
    assert!(queued > 0 && queued < vectors.len(), "{queued}");
}

fn review() -> Value {
    json!({"reason_code": PACKAGE_REVIEW_REASON, "minimum_action": "review"})
}

/// Exec flows and Copilot's `toolArgs` reach the evaluator, so a package the
/// bundle blocks is stopped rather than queued.
#[test]
fn exec_flows_and_copilot_tool_args_stay_with_the_daemon() {
    let result = review();
    for payload in [
        json!({"tool_input": {"command": "npx create-vite@5.1.0"}}),
        json!({"tool_input": {"command": "npm exec --package=create-vite@5.1.0 create-vite"}}),
        json!({"tool_input": {"command": "pnpm dlx create-next-app@14.2.0"}}),
        json!({"tool_input": {"command": "yarn dlx @redwoodjs/create-redwood-app@6.0.0"}}),
        json!({"tool_input": {"command": "bunx @angular/cli@19.0.0"}}),
        json!({"toolName": "bash", "toolArgs": {"command": "npm install minimist@1.2.8"}}),
        json!({"toolName": "bash", "toolArgs": "{\"command\": \"npm install minimist@1.2.8\"}"}),
    ] {
        assert!(
            !left_to_queue(payload.as_object().unwrap(), result.as_object().unwrap()),
            "{payload}"
        );
    }
}

/// A command the evaluator never reads is queued as it stands.
#[test]
fn other_commands_are_left_to_the_queue() {
    let result = review();
    for payload in [
        json!({"tool_input": {"command": "pip install requests"}}),
        json!({"tool_input": {"command": "npm install left-pad && rm -rf build"}}),
        json!({"tool_input": {"command": "\u{1c}"}}),
        json!({"toolArgs": "not json"}),
        json!({"toolArgs": "[\"npm install left-pad\"]"}),
    ] {
        assert!(
            left_to_queue(payload.as_object().unwrap(), result.as_object().unwrap()),
            "{payload}"
        );
    }
}

/// The edge gives `npx` and `bunx` a command review; the daemon plans those
/// launches so a package the bundle blocks is stopped. Any other command under
/// that reason is queued as it stands.
#[test]
fn npx_and_bunx_command_reviews_stay_with_the_daemon() {
    let result = json!({"reason_code": LAUNCH_REVIEW_REASON, "minimum_action": "review"});
    let result = result.as_object().unwrap();
    for (command, queued) in [
        ("npx create-vite@5.1.0", false),
        ("bunx @angular/cli@19.0.0", false),
        ("npm install minimist@1.2.8", true),
        ("pnpm dlx create-next-app@14.2.0", true),
        ("make build", true),
    ] {
        let payload = json!({"tool_input": {"command": command}});
        assert_eq!(
            left_to_queue(payload.as_object().unwrap(), result),
            queued,
            "{command}"
        );
    }
}
