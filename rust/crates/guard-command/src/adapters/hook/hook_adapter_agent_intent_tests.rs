//! The review card quotes the agent's own account of a shell command from the
//! redacted payload (`raw_payload_redacted.tool_input.description` or
//! `.justification`). Redaction must keep those fields, cut like any other
//! string, or the card loses them without a test failing anywhere else.

use std::path::Path;

use crate::hook_adapter_envelope::{normalize_harness_envelope, EnvelopeRequest, IntentSummary};
use crate::hook_adapter_paths::PathEnv;
use crate::hook_adapter_value::{parse_python_json, OMap, OValue};

fn redacted_tool_input(harness: &str, tool_name: &str, tool_input: &str) -> OMap {
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
        workspace: Some("/srv/project"),
        home_dir: Some("/home/user"),
        devin_project_dir: None,
        env: PathEnv::default(),
    };
    let mut provider =
        |_: &str, _: Option<&Path>, _: Option<&Path>| -> Option<IntentSummary> { None };
    let envelope = normalize_harness_envelope(&request, &mut provider).expect("envelope");
    envelope
        .get("raw_payload_redacted")
        .and_then(OValue::as_map)
        .and_then(|raw| raw.get("tool_input"))
        .and_then(OValue::as_map)
        .expect("redacted tool_input")
        .clone()
}

fn field<'a>(tool_input: &'a OMap, key: &str) -> Option<&'a str> {
    tool_input.get(key).and_then(OValue::as_str)
}

#[test]
fn a_claude_code_bash_description_survives_redaction() {
    let tool_input = redacted_tool_input(
        "claude-code",
        "Bash",
        r#"{"command":"git push --force origin main","description":"Force-push the rebased branch"}"#,
    );
    assert_eq!(
        field(&tool_input, "description"),
        Some("Force-push the rebased branch")
    );
}

#[test]
fn a_codex_justification_survives_redaction() {
    let tool_input = redacted_tool_input(
        "codex",
        "shell",
        r#"{"command":["rm","-rf","build"],"justification":"Clean the build output"}"#,
    );
    assert_eq!(
        field(&tool_input, "justification"),
        Some("Clean the build output")
    );
}

#[test]
fn a_long_description_is_cut_like_any_other_string() {
    let long = "x".repeat(400);
    let tool_input = redacted_tool_input(
        "claude-code",
        "Bash",
        &format!(r#"{{"command":"ls","description":"{long}"}}"#),
    );
    let description = field(&tool_input, "description").expect("description");
    assert!(description.chars().count() <= 241, "{description}");
    assert!(description.starts_with("xxx"), "{description}");
}
