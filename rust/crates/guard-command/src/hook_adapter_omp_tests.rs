//! Oh My Pi tool names map to their own action labels, not the generic
//! `config_change` fallback.

use std::path::Path;

use crate::hook_adapter_envelope::{normalize_harness_envelope, EnvelopeRequest, IntentSummary};
use crate::hook_adapter_paths::PathEnv;
use crate::hook_adapter_value::{parse_python_json, OMap};

fn action_type(harness: &str, tool_name: &str, tool_input: &str) -> String {
    let text = format!(
        r#"{{"hook_event_name":"PreToolUse","tool_name":"{tool_name}","tool_input":{tool_input}}}"#
    );
    let payload: OMap = parse_python_json(&text)
        .expect("payload json")
        .as_map()
        .expect("payload map")
        .clone();
    let request = EnvelopeRequest {
        harness,
        event_name: "PreToolUse",
        payload: &payload,
        workspace: Some("."),
        home_dir: Some("/home/user"),
        devin_project_dir: None,
        env: PathEnv::default(),
    };
    let mut provider =
        |_: &str, _: Option<&Path>, _: Option<&Path>| -> Option<IntentSummary> { None };
    let envelope = normalize_harness_envelope(&request, &mut provider).expect("envelope");
    envelope
        .get_str("action_type")
        .expect("action_type")
        .to_owned()
}

#[test]
fn omp_tools_get_their_own_action_labels() {
    for (tool, input, expected) in [
        (
            "task",
            r#"{"prompt":"summarize the open review threads"}"#,
            "prompt",
        ),
        (
            "eval",
            r#"{"code":"display(1)","language":"js"}"#,
            "shell_command",
        ),
        ("wait", r#"{}"#, "harness_start"),
        ("todo_write", r#"{"todos":[]}"#, "harness_start"),
        ("ls", r#"{"path":"."}"#, "file_read"),
        ("find", r#"{"path":"."}"#, "file_read"),
    ] {
        assert_eq!(action_type("omp", tool, input), expected, "{tool}");
    }
}

#[test]
fn omp_labels_do_not_apply_to_other_harnesses() {
    assert_eq!(
        action_type("pi", "task", r#"{"prompt":"x"}"#),
        "config_change"
    );
}
