//! A read-only search or listing tool carries a pattern or a directory, not a
//! command, so it used to fall through to the generic `config_change` label.
//! The review card then called a code search a config change, and the scan
//! planner, which plans for `file_write` and `config_change` alike, planned a
//! workspace scan for it. Every harness that ships these tools must label them
//! as the file reads they are.

use std::path::Path;

use guard_command::hook_adapter_envelope::{
    normalize_harness_envelope, EnvelopeRequest, IntentSummary,
};
use guard_command::hook_adapter_paths::PathEnv;
use guard_command::hook_adapter_value::{parse_python_json, OMap, OValue};

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
        workspace: Some("/srv/project"),
        home_dir: Some("/home/user"),
        devin_project_dir: None,
        env: PathEnv::default(),
    };
    let mut provider =
        |_: &str, _: Option<&Path>, _: Option<&Path>| -> Option<IntentSummary> { None };
    let envelope = normalize_harness_envelope(&request, &mut provider).expect("envelope");
    envelope
        .get("action_type")
        .and_then(OValue::as_str)
        .expect("action_type")
        .to_owned()
}

#[test]
fn a_search_tool_without_a_command_reads_files() {
    let mut wrong = Vec::new();
    for harness in ["cursor", "claude-code", "codex", "zcode", "omp", "grok"] {
        for (tool, tool_input) in [
            (
                "Glob",
                r#"{"filePattern":"**/*.rs","path":"/srv/project/src"}"#,
            ),
            (
                "Grep",
                r#"{"glob":"*.rs","output_mode":"files_with_matches","file_path":"/srv/project/src"}"#,
            ),
            ("list_dir", r#"{"relative_workspace_path":"src"}"#),
        ] {
            let action = action_type(harness, tool, tool_input);
            if action != "file_read" {
                wrong.push(format!("{harness} {tool}: {action}"));
            }
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

/// A search tool that reconstructs a command keeps the shell label, so the
/// command detectors still read the search it is about to run.
#[test]
fn a_grep_with_a_pattern_still_reconstructs_a_command() {
    assert_eq!(
        action_type(
            "cursor",
            "Grep",
            r#"{"pattern":"fn main","glob":"*.rs","file_path":"/srv/project/src"}"#
        ),
        "shell_command"
    );
}

/// A search tool that does carry a command keeps the shell label, so the
/// command detectors still read it.
#[test]
fn a_search_tool_with_a_command_stays_a_shell_command() {
    assert_eq!(
        action_type("cursor", "Grep", r#"{"command":"grep -rn parser src"}"#),
        "shell_command"
    );
}

/// Tools the tables do not name keep the generic label.
#[test]
fn an_unnamed_tool_keeps_the_generic_label() {
    assert_eq!(
        action_type(
            "cursor",
            "UpdateSettings",
            r#"{"key":"theme","value":"dark"}"#
        ),
        "config_change"
    );
}
