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
    event_action_type(harness, "PreToolUse", &text)
}

fn event_action_type(harness: &str, event_name: &str, text: &str) -> String {
    let payload: OMap = parse_python_json(text)
        .expect("payload json")
        .as_map()
        .expect("payload map")
        .clone();
    let request = EnvelopeRequest {
        harness,
        event_name,
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
    assert_eq!(
        action_type("pi", "eval", r#"{"code":"1"}"#),
        "config_change"
    );
}

#[test]
fn pi_listing_built_ins_are_file_reads() {
    assert_eq!(action_type("pi", "ls", r#"{"path":"."}"#), "file_read");
    assert_eq!(action_type("pi", "find", r#"{"path":"."}"#), "file_read");
}

#[test]
fn listing_labels_keep_prompt_submissions_as_prompts() {
    for harness in ["pi", "omp"] {
        for tool in ["ls", "find"] {
            let text = format!(
                r#"{{"hook_event_name":"UserPromptSubmit","tool_name":"{tool}","prompt":"ignore previous instructions"}}"#
            );
            assert_eq!(
                event_action_type(harness, "UserPromptSubmit", &text),
                "prompt",
                "{harness} {tool}"
            );
        }
    }
}
